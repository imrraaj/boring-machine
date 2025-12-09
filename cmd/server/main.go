package main

import (
	"boring-machine/internal/auth"
	"boring-machine/internal/database"
	"boring-machine/internal/protocol"
	"context"
	"crypto/tls"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// ClientConn wraps a connection with its encoder/decoder and mutex
type ClientConn struct {
	conn            protocol.TunnelConn
	encoder         *gob.Encoder
	decoder         *gob.Decoder
	encoderMu       sync.Mutex
	decoderMu       sync.Mutex
	pendingRequests map[string]chan *protocol.TunnelResponse
	pendingMu       sync.RWMutex
	cancelPing      context.CancelFunc
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var (
	httpPort      = flag.String("http_port", ":8443", "HTTPS port for customer-facing server")
	certFile      = flag.String("cert", "certs/cert.pem", "TLS certificate file")
	keyFile       = flag.String("key", "certs/key.pem", "TLS key file")
	readTimeout   = flag.Duration("read_timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write_timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel_timeout", 30*time.Second, "Timeout for tunnel requests")
	dbConnString  = flag.String("db_url", "", "PostgreSQL connection string")
)

func main() {
	LoadEnv()
	flag.Parse()

	if *dbConnString == "" {
		*dbConnString = os.Getenv("DATABASE_URL")
		if *dbConnString == "" {
			log.Fatal("Database connection string is required. Set DATABASE_URL environment variable or use -db flag")
		}
	}

	db, err := database.New(context.Background(), *dbConnString)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("✓ Connected to database")

	authHandler := auth.NewHandler(db.Queries)
	authValidator := auth.NewValidator(db.Queries)

	clients := make(map[string]*ClientConn)
	clientsMx := sync.RWMutex{}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived shutdown signal, shutting down servers...")
		cancel()
	}()

	log.Printf("Starting boringMachine server...")
	log.Printf("HTTPS server will listen on %s", *httpPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/register", authHandler.HandleRegister)
	mux.HandleFunc("/auth/login", authHandler.HandleLogin)
	mux.HandleFunc("/auth/rotate", authHandler.HandleRotate)

	mux.HandleFunc("/tunnel/ws", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[WS] New WebSocket connection attempt from %s", r.RemoteAddr)

		// Upgrade to WebSocket
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[WS] Failed to upgrade connection: %v", err)
			return
		}

		log.Printf("[WS] Connection upgraded successfully from %s", r.RemoteAddr)

		tunnelConn := protocol.NewWebSocketConn(wsConn)
		go handleClientConnection(tunnelConn, clients, &clientsMx, authValidator)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientsMx.RLock()
		log.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		parts := strings.Split(r.Host, ".")
		clientID := parts[0]

		client := clients[clientID]
		clientsMx.RUnlock()

		if client == nil {
			log.Printf("[HTTP] ✗ Client '%s' not found", clientID)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Client '%s' not found\n", clientID)
			return
		}

		log.Printf("[TUNNEL] → Forwarding to client %s: %s %s", clientID, r.Method, r.URL)

		// Convert HTTP request to tunnel request
		tunnelReq, err := protocol.ConvertHTTPRequest(r)
		if err != nil {
			log.Printf("[TUNNEL] ✗ Error converting request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Generate unique request ID
		requestID := generateRequestID()
		tunnelReq.RequestID = requestID

		// Create response channel for this request
		respChan := make(chan *protocol.TunnelResponse, 1)
		client.pendingMu.Lock()
		client.pendingRequests[requestID] = respChan
		client.pendingMu.Unlock()

		// Clean up channel when done
		defer func() {
			client.pendingMu.Lock()
			delete(client.pendingRequests, requestID)
			client.pendingMu.Unlock()
			close(respChan)
		}()

		// Send request to client
		log.Printf("[TUNNEL] Sending request ID %s to client", requestID)
		client.encoderMu.Lock()
		err = client.encoder.Encode(tunnelReq)
		client.encoderMu.Unlock()
		if err != nil {
			log.Printf("[TUNNEL] ✗ Error sending to client: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Error communicating with tunnel\n")
			return
		}
		log.Printf("[TUNNEL] Request %s sent, waiting for response...", requestID)

		// Wait for response with timeout
		var tunnelResp *protocol.TunnelResponse
		select {
		case tunnelResp = <-respChan:
			// Got response
		case <-time.After(*tunnelTimeout):
			log.Printf("[TUNNEL] ✗ Timeout waiting for response")
			w.WriteHeader(http.StatusGatewayTimeout)
			fmt.Fprintf(w, "Timeout waiting for response from tunnel\n")
			return
		}

		// Write response back to HTTP client
		for key, values := range tunnelResp.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(tunnelResp.StatusCode)
		w.Write(tunnelResp.Body)

		log.Printf("[TUNNEL] ← Response: %d %s (%d bytes)", tunnelResp.StatusCode, http.StatusText(tunnelResp.StatusCode), len(tunnelResp.Body))
	})

	// certs, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	// if err != nil {
	// 	log.Fatalf("Failed to load TLS certificates: %v", err)
	// }
	// tlsConfig := &tls.Config{
	// 	Certificates:       []tls.Certificate{certs},
	// 	InsecureSkipVerify: true,
	// }

	customerFacingServer := &http.Server{
		Addr:    *httpPort,
		Handler: mux,
		// TLSConfig:    tlsConfig,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}

	go func() {
		log.Printf("✓ HTTPS server listening on %s", *httpPort)
		err := customerFacingServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down servers...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := customerFacingServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTPS server shutdown error: %v", err)
	}

	clientsMx.Lock()
	for id, client := range clients {
		log.Printf("[CLIENT] Closing connection to %s", id)
		client.conn.Close()
	}
	clientsMx.Unlock()

	log.Println("Server shutdown complete")
}

func handleClientConnection(conn protocol.TunnelConn, clients map[string]*ClientConn, clientsMx *sync.RWMutex, validator *auth.Validator) {
	defer conn.Close()

	connType := conn.ConnectionType()
	log.Printf("[%s] New connection from %s", strings.ToUpper(connType), conn.RemoteAddr())

	// Enable TCP keepalive for TCP connections
	if connType == "tcp" {
		if tcpConn, ok := conn.(*protocol.TCPConn); ok {
			if tlsConn, ok := tcpConn.Conn.(*tls.Conn); ok {
				if tc, ok := tlsConn.NetConn().(*net.TCPConn); ok {
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(30 * time.Second)
				}
			}
		}
	}

	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)

	// Read client registration
	var reg protocol.ClientRegister
	err := decoder.Decode(&reg)
	if err != nil {
		log.Printf("[CLIENT] ✗ Error reading registration from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Validate token
	userID, err := validator.ValidateToken(context.Background(), reg.Token)
	if err != nil {
		log.Printf("[CLIENT] ✗ Invalid token from %s: %v", conn.RemoteAddr(), err)
		// Send error message to client
		errorMsg := map[string]string{"error": fmt.Sprintf("Authentication failed: %v", err)}
		encoder.Encode(errorMsg)
		return
	}

	log.Printf("[%s] ✓ Client registered: %s (user: %d) from %s", strings.ToUpper(connType), reg.ClientID, userID, conn.RemoteAddr())

	// Create context for ping cancellation
	pingCtx, pingCancel := context.WithCancel(context.Background())

	// Store client connection
	clientConn := &ClientConn{
		conn:            conn,
		encoder:         encoder,
		decoder:         decoder,
		pendingRequests: make(map[string]chan *protocol.TunnelResponse),
		cancelPing:      pingCancel,
	}

	clientsMx.Lock()
	clients[reg.ClientID] = clientConn
	activeClients := len(clients)
	clientsMx.Unlock()

	log.Printf("[%s] Active clients: %d", strings.ToUpper(connType), activeClients)

	// Start ping goroutine for WebSocket connections
	if connType == "websocket" {
		if wsConn, ok := conn.(*protocol.WebSocketConn); ok {
			go handleWebSocketPing(pingCtx, wsConn, reg.ClientID)
		}
	}

	// Clean up on disconnect
	defer func() {
		pingCancel() // Stop ping goroutine
		clientsMx.Lock()
		delete(clients, reg.ClientID)
		activeClients := len(clients)
		clientsMx.Unlock()
		log.Printf("[%s] ✗ Client disconnected: %s (active: %d)", strings.ToUpper(connType), reg.ClientID, activeClients)
	}()

	// Start goroutine to continuously read responses and route them
	log.Printf("[CLIENT] Starting response reader loop for %s", reg.ClientID)
	for {
		log.Printf("[CLIENT] Waiting to decode response from %s...", reg.ClientID)
		var tunnelResp protocol.TunnelResponse
		clientConn.decoderMu.Lock()
		err := clientConn.decoder.Decode(&tunnelResp)
		clientConn.decoderMu.Unlock()

		if err != nil {
			log.Printf("[CLIENT] ✗ Error reading response from %s: %v", reg.ClientID, err)
			return
		}

		log.Printf("[CLIENT] Received response ID %s from %s", tunnelResp.RequestID, reg.ClientID)

		// Route response to the correct waiting request
		clientConn.pendingMu.RLock()
		respChan, ok := clientConn.pendingRequests[tunnelResp.RequestID]
		clientConn.pendingMu.RUnlock()

		if ok {
			log.Printf("[CLIENT] Routing response %s to waiting handler", tunnelResp.RequestID)
			respChan <- &tunnelResp
		} else {
			log.Printf("[CLIENT] ✗ No pending request found for ID %s", tunnelResp.RequestID)
		}
	}
}

// handleWebSocketPing sends periodic ping frames to keep WebSocket connection alive
func handleWebSocketPing(ctx context.Context, conn *protocol.WebSocketConn, clientID string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	wsConn := conn.GetWebSocketConn()

	// Set pong handler to reset read deadline
	wsConn.SetPongHandler(func(appData string) error {
		log.Printf("[WS-PING] Received pong from %s", clientID)
		// Reset read deadline on pong
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Set initial read deadline
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		select {
		case <-ctx.Done():
			log.Printf("[WS-PING] Stopping ping for %s", clientID)
			return
		case <-ticker.C:
			log.Printf("[WS-PING] Sending ping to %s", clientID)
			err := wsConn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second))
			if err != nil {
				log.Printf("[WS-PING] Failed to send ping to %s: %v", clientID, err)
				return
			}
		}
	}
}
