package main

import (
	"boring-machine/internal/auth"
	"boring-machine/internal/database"
	"boring-machine/internal/protocol"
	"boring-machine/internal/wsio"
	"context"
	"crypto/rand"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
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
	conn            *websocket.Conn
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
	readTimeout   = flag.Duration("read_timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write_timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel_timeout", 30*time.Second, "Timeout for tunnel requests")
	dbConnString  = flag.String("db_url", "", "PostgreSQL connection string")
	skipAuth      = flag.Bool("skip-auth", false, "Skip authentication (development/benchmark mode only)")
	verbose       = flag.Bool("verbose", false, "Enable verbose/debug logging")
)

func main() {
	LoadEnv()
	flag.Parse()

	var authHandler *auth.Handler
	var authValidator *auth.Validator

	if *skipAuth {
		log.Println("⚠️  Running in skip-auth mode (development/benchmark only)")
	} else {
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

		authHandler = auth.NewHandler(db.Queries)
		authValidator = auth.NewValidator(db.Queries)
	}

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

	if !*skipAuth {
		mux.HandleFunc("/auth/register", authHandler.HandleRegister)
		mux.HandleFunc("/auth/login", authHandler.HandleLogin)
		mux.HandleFunc("/auth/rotate", authHandler.HandleRotate)
	}

	mux.HandleFunc("/tunnel/ws", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[WS] New WebSocket connection attempt from %s", r.RemoteAddr)

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[WS] Failed to upgrade connection: %v", err)
			return
		}

		log.Printf("[WS] Connection upgraded successfully from %s", r.RemoteAddr)
		go handleClientConnection(wsConn, clients, &clientsMx, authValidator)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientsMx.RLock()
		if *verbose {
			log.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
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

		if *verbose {
			log.Printf("[TUNNEL] → Forwarding to client %s: %s %s", clientID, r.Method, r.URL)
		}

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
		if *verbose {
			log.Printf("[TUNNEL] Sending request ID %s to client", requestID)
		}
		client.encoderMu.Lock()
		err = client.encoder.Encode(tunnelReq)
		client.encoderMu.Unlock()
		if err != nil {
			log.Printf("[TUNNEL] ✗ Error sending to client: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Error communicating with tunnel\n")
			return
		}
		if *verbose {
			log.Printf("[TUNNEL] Request %s sent, waiting for response...", requestID)
		}

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

		if *verbose {
			log.Printf("[TUNNEL] ← Response: %d %s (%d bytes)", tunnelResp.StatusCode, http.StatusText(tunnelResp.StatusCode), len(tunnelResp.Body))
		}
	})

	customerFacingServer := &http.Server{
		Addr:         *httpPort,
		Handler:      mux,
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

func handleClientConnection(conn *websocket.Conn, clients map[string]*ClientConn, clientsMx *sync.RWMutex, validator *auth.Validator) {
	defer conn.Close()

	log.Printf("[WS] New connection from %s", conn.RemoteAddr())

	wsrw := wsio.New(conn)
	encoder := gob.NewEncoder(wsrw)
	decoder := gob.NewDecoder(wsrw)

	var reg protocol.ClientRegister
	err := decoder.Decode(&reg)
	if err != nil {
		log.Printf("[WS] ✗ Error reading registration from %s: %v", conn.RemoteAddr(), err)
		return
	}

	var userID int64
	if *skipAuth {
		log.Printf("[WS] Authentication skipped (development mode)")
		userID = 0
	} else {
		userID, err = validator.ValidateToken(context.Background(), reg.Token)
		if err != nil {
			log.Printf("[WS] ✗ Invalid token from %s: %v", conn.RemoteAddr(), err)
			encoder.Encode(protocol.RegistrationResponse{
				Success: false,
				Error:   fmt.Sprintf("Authentication failed: %v", err),
			})
			return
		}
	}

	clientID := generateClientID()

	clientsMx.Lock()
	for {
		if _, exists := clients[clientID]; !exists {
			break
		}
		clientID = generateClientID()
	}

	pingCtx, pingCancel := context.WithCancel(context.Background())

	clientConn := &ClientConn{
		conn:            conn,
		encoder:         encoder,
		decoder:         decoder,
		pendingRequests: make(map[string]chan *protocol.TunnelResponse),
		cancelPing:      pingCancel,
	}

	clients[clientID] = clientConn
	activeClients := len(clients)
	clientsMx.Unlock()

	err = encoder.Encode(protocol.RegistrationResponse{
		Success:  true,
		ClientID: clientID,
		Error:    "",
	})
	if err != nil {
		log.Printf("[WS] ✗ Failed to send registration response: %v", err)
		clientsMx.Lock()
		delete(clients, clientID)
		clientsMx.Unlock()
		return
	}

	log.Printf("[WS] ✓ Client registered: %s (user: %d) from %s", clientID, userID, conn.RemoteAddr())
	log.Printf("[WS] Active clients: %d", activeClients)

	go handleWebSocketPing(pingCtx, conn, clientID)

	defer func() {
		pingCancel()
		clientsMx.Lock()
		delete(clients, clientID)
		activeClients := len(clients)
		clientsMx.Unlock()
		log.Printf("[WS] ✗ Client disconnected: %s (active: %d)", clientID, activeClients)
	}()

	// Start goroutine to continuously read responses and route them
	if *verbose {
		log.Printf("[CLIENT] Starting response reader loop for %s", clientID)
	}
	for {
		if *verbose {
			log.Printf("[CLIENT] Waiting to decode response from %s...", clientID)
		}
		var tunnelResp protocol.TunnelResponse
		clientConn.decoderMu.Lock()
		err := clientConn.decoder.Decode(&tunnelResp)
		clientConn.decoderMu.Unlock()

		if err != nil {
			log.Printf("[CLIENT] ✗ Error reading response from %s: %v", clientID, err)
			return
		}

		if *verbose {
			log.Printf("[CLIENT] Received response ID %s from %s", tunnelResp.RequestID, clientID)
		}

		// Route response to the correct waiting request
		clientConn.pendingMu.RLock()
		respChan, ok := clientConn.pendingRequests[tunnelResp.RequestID]
		clientConn.pendingMu.RUnlock()

		if ok {
			if *verbose {
				log.Printf("[CLIENT] Routing response %s to waiting handler", tunnelResp.RequestID)
			}
			respChan <- &tunnelResp
		} else {
			log.Printf("[CLIENT] ✗ No pending request found for ID %s", tunnelResp.RequestID)
		}
	}
}

// generateClientID generates a random client ID
func generateClientID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// handleWebSocketPing sends periodic ping frames to keep WebSocket connection alive
func handleWebSocketPing(ctx context.Context, conn *websocket.Conn, clientID string) {
	pingTime := 300 * time.Second
	ticker := time.NewTicker(pingTime)
	defer ticker.Stop()

	conn.SetPongHandler(func(appData string) error {
		if *verbose {
			log.Printf("[WS-PING] Received pong from %s", clientID)
		}
		conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))
		return nil
	})

	conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))

	for {
		select {
		case <-ctx.Done():
			if *verbose {
				log.Printf("[WS-PING] Stopping ping for %s", clientID)
			}
			return
		case <-ticker.C:
			if *verbose {
				log.Printf("[WS-PING] Sending ping to %s", clientID)
			}
			err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add((3/2)*pingTime))
			if err != nil {
				log.Printf("[WS-PING] Failed to send ping to %s: %v", clientID, err)
				return
			}
		}
	}
}
