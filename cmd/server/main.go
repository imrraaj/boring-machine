package main

import (
	"boring-machine/internal/auth"
	"boring-machine/internal/database"
	"boring-machine/internal/html"
	"boring-machine/internal/logger"
	"boring-machine/internal/metrics"
	"boring-machine/internal/protocol"
	"boring-machine/internal/wsio"
	"context"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
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
	httpPort      = flag.String("http_port", ":8443", "Port for customer-facing server (HTTP or HTTPS depending on cert-file/key-file flags)")
	readTimeout   = flag.Duration("read_timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write_timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel_timeout", 30*time.Second, "Timeout for tunnel requests")
	dbConnString  = flag.String("db_url", "", "PostgreSQL connection string")
	skipAuth      = flag.Bool("skip-auth", false, "Skip authentication (development/benchmark mode only)")
	verbose       = flag.Bool("verbose", false, "Enable verbose/debug logging")
	certFile      = flag.String("cert-file", "", "Path to TLS certificate file (enables HTTPS/WSS)")
	keyFile       = flag.String("key-file", "", "Path to TLS private key file (enables HTTPS/WSS)")
)

func main() {
	LoadEnv()
	flag.Parse()

	// Create verbose logger
	verboseLog := logger.NewLogger(os.Stdout, *verbose, "")

	// Initialize metrics collection
	serverMetrics := metrics.NewServerMetrics()

	// Check if both cert and key are provided for TLS
	useTLS := *certFile != "" && *keyFile != ""
	serverProtocol := "HTTP"
	if useTLS {
		serverProtocol = "HTTPS"
	}

	var authHandler *auth.Handler
	var authValidator *auth.Validator

	if *skipAuth {
		verboseLog.Println("⚠️  Running in skip-auth mode (development/benchmark only)")
	} else {
		if *dbConnString == "" {
			*dbConnString = os.Getenv("DATABASE_URL")
			if *dbConnString == "" {
				verboseLog.Fatal("Database connection string is required. Set DATABASE_URL environment variable or use -db flag")
			}
		}

		db, err := database.New(context.Background(), *dbConnString)
		if err != nil {
			verboseLog.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()
		verboseLog.Println("✓ Connected to database")

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
		verboseLog.Println("\nReceived shutdown signal, shutting down servers...")
		cancel()
	}()

	verboseLog.Printf("Starting boringMachine server...")
	verboseLog.Printf("%s server will listen on %s", serverProtocol, *httpPort)

	mux := http.NewServeMux()

	if !*skipAuth {
		mux.HandleFunc("/auth/register", authHandler.HandleRegister)
		mux.HandleFunc("/auth/login", authHandler.HandleLogin)
		mux.HandleFunc("/auth/rotate", authHandler.HandleRotate)
	}

	// Admin dashboard endpoints
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		html.RenderDashboard(w)
	})

	mux.HandleFunc("/admin/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Get metrics snapshot
		snapshot := serverMetrics.GetSnapshot()

		// Get system stats
		sysStats := metrics.GetSystemStats()

		// Get active client count
		clientsMx.RLock()
		activeCount := len(clients)
		clientsMx.RUnlock()

		// Build client list for response
		clientsList := make([]map[string]interface{}, 0, len(snapshot.ClientInfo))
		for _, client := range snapshot.ClientInfo {
			clientsList = append(clientsList, map[string]interface{}{
				"client_id":     client.ClientID,
				"user_id":       client.UserID,
				"connected_at":  client.ConnectedAt.Format(time.RFC3339),
				"remote_addr":   client.RemoteAddr,
				"request_count": client.RequestCount,
				"last_request_at": func() string {
					if client.LastRequestAt.IsZero() {
						return ""
					}
					return client.LastRequestAt.Format(time.RFC3339)
				}(),
			})
		}

		// Build response
		response := map[string]interface{}{
			"server": map[string]interface{}{
				"uptime_seconds": time.Since(snapshot.StartTime).Seconds(),
				"start_time":     snapshot.StartTime.Format(time.RFC3339),
			},
			"connections": map[string]interface{}{
				"active":         activeCount,
				"total_accepted": snapshot.TotalConnectionsAccepted,
				"total_closed":   snapshot.TotalConnectionsClosed,
			},
			"requests": map[string]interface{}{
				"forwarded": snapshot.TotalRequestsForwarded,
				"failed":    snapshot.TotalRequestsFailed,
			},
			"clients": clientsList,
			"system":  sysStats,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/tunnel/ws", func(w http.ResponseWriter, r *http.Request) {
		verboseLog.Printf("[WS] New WebSocket connection attempt from %s", r.RemoteAddr)

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			verboseLog.Printf("[WS] Failed to upgrade connection: %v", err)
			return
		}

		verboseLog.Printf("[WS] Connection upgraded successfully from %s", r.RemoteAddr)
		go handleClientConnection(wsConn, clients, &clientsMx, authValidator, verboseLog, serverMetrics)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientsMx.RLock()
		verboseLog.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		parts := strings.Split(r.Host, ".")
		clientID := parts[0]

		client := clients[clientID]
		clientsMx.RUnlock()

		if client == nil {
			verboseLog.Printf("[HTTP] ✗ Client '%s' not found", clientID)
			serverMetrics.RequestFailed()
			html.RenderErrorPage(w, http.StatusNotFound, clientID, "client_not_found", "")
			return
		}

		verboseLog.Printf("[TUNNEL] → Forwarding to client %s: %s %s", clientID, r.Method, r.URL)

		// Convert HTTP request to tunnel request
		tunnelReq, err := protocol.ConvertHTTPRequest(r)
		if err != nil {
			verboseLog.Printf("[TUNNEL] ✗ Error converting request: %v", err)
			serverMetrics.RequestFailed()
			html.RenderErrorPage(w, http.StatusInternalServerError, clientID, "tunnel_error", err.Error())
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
		verboseLog.Printf("[TUNNEL] Sending request ID %s to client", requestID)
		client.encoderMu.Lock()
		err = client.encoder.Encode(tunnelReq)
		client.encoderMu.Unlock()
		if err != nil {
			verboseLog.Printf("[TUNNEL] ✗ Error sending to client: %v", err)
			serverMetrics.RequestFailed()
			html.RenderErrorPage(w, http.StatusBadGateway, clientID, "tunnel_error", err.Error())
			return
		}
		verboseLog.Printf("[TUNNEL] Request %s sent, waiting for response...", requestID)

		// Wait for response with timeout
		var tunnelResp *protocol.TunnelResponse
		select {
		case tunnelResp = <-respChan:
			// Got response
		case <-time.After(*tunnelTimeout):
			verboseLog.Printf("[TUNNEL] ✗ Timeout waiting for response")
			serverMetrics.RequestFailed()
			html.RenderErrorPage(w, http.StatusGatewayTimeout, clientID, "timeout", "")
			return
		}

		// Check if this is an application down error
		if html.IsApplicationDownError(tunnelResp.StatusCode, tunnelResp.Body) {
			verboseLog.Printf("[TUNNEL] ✗ Application not responding")
			serverMetrics.RequestFailed()
			html.RenderErrorPage(w, http.StatusBadGateway, clientID, "application_down", string(tunnelResp.Body))
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

		// Record successful request forwarding
		serverMetrics.RequestForwarded(clientID)

		verboseLog.Printf("[TUNNEL] ← Response: %d %s (%d bytes)", tunnelResp.StatusCode, http.StatusText(tunnelResp.StatusCode), len(tunnelResp.Body))
	})

	customerFacingServer := &http.Server{
		Addr:         *httpPort,
		Handler:      mux,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}

	go func() {
		verboseLog.Printf("✓ %s server listening on %s", serverProtocol, *httpPort)
		var err error
		if useTLS {
			err = customerFacingServer.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			err = customerFacingServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			verboseLog.Fatalf("%s server error: %v", serverProtocol, err)
		}
	}()

	<-ctx.Done()
	verboseLog.Println("Shutting down servers...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := customerFacingServer.Shutdown(shutdownCtx); err != nil {
		verboseLog.Printf("HTTPS server shutdown error: %v", err)
	}

	clientsMx.Lock()
	for id, client := range clients {
		verboseLog.Printf("[CLIENT] Closing connection to %s", id)
		client.conn.Close()
	}
	clientsMx.Unlock()

	verboseLog.Println("Server shutdown complete")
}

func handleClientConnection(conn *websocket.Conn, clients map[string]*ClientConn, clientsMx *sync.RWMutex, validator *auth.Validator, verboseLog *log.Logger, serverMetrics *metrics.ServerMetrics) {
	defer conn.Close()

	verboseLog.Printf("[WS] New connection from %s", conn.RemoteAddr())

	wsrw := wsio.New(conn)
	encoder := gob.NewEncoder(wsrw)
	decoder := gob.NewDecoder(wsrw)

	var reg protocol.ClientRegister
	err := decoder.Decode(&reg)
	if err != nil {
		verboseLog.Printf("[WS] ✗ Error reading registration from %s: %v", conn.RemoteAddr(), err)
		return
	}

	var userID int64
	if *skipAuth {
		verboseLog.Printf("[WS] Authentication skipped (development mode)")
		userID = 0
	} else {
		userID, err = validator.ValidateToken(context.Background(), reg.Token)
		if err != nil {
			verboseLog.Printf("[WS] ✗ Invalid token from %s: %v", conn.RemoteAddr(), err)
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
		verboseLog.Printf("[WS] ✗ Failed to send registration response: %v", err)
		clientsMx.Lock()
		delete(clients, clientID)
		clientsMx.Unlock()
		return
	}

	verboseLog.Printf("[WS] ✓ Client registered: %s (user: %d) from %s", clientID, userID, conn.RemoteAddr())
	verboseLog.Printf("[WS] Active clients: %d", activeClients)

	// Record client connection in metrics
	serverMetrics.ClientConnected(clientID, userID, conn.RemoteAddr().String())

	go handleWebSocketPing(pingCtx, conn, clientID, verboseLog)

	defer func() {
		pingCancel()
		clientsMx.Lock()
		delete(clients, clientID)
		activeClients := len(clients)
		clientsMx.Unlock()

		// Record client disconnection in metrics
		serverMetrics.ClientDisconnected(clientID)

		verboseLog.Printf("[WS] ✗ Client disconnected: %s (active: %d)", clientID, activeClients)
	}()

	// Start goroutine to continuously read responses and route them
	verboseLog.Printf("[CLIENT] Starting response reader loop for %s", clientID)
	for {
		verboseLog.Printf("[CLIENT] Waiting to decode response from %s...", clientID)
		var tunnelResp protocol.TunnelResponse
		clientConn.decoderMu.Lock()
		err := clientConn.decoder.Decode(&tunnelResp)
		clientConn.decoderMu.Unlock()

		if err != nil {
			verboseLog.Printf("[CLIENT] ✗ Error reading response from %s: %v", clientID, err)
			return
		}

		verboseLog.Printf("[CLIENT] Received response ID %s from %s", tunnelResp.RequestID, clientID)

		// Route response to the correct waiting request
		clientConn.pendingMu.RLock()
		respChan, ok := clientConn.pendingRequests[tunnelResp.RequestID]
		clientConn.pendingMu.RUnlock()

		if ok {
			verboseLog.Printf("[CLIENT] Routing response %s to waiting handler", tunnelResp.RequestID)
			respChan <- &tunnelResp
		} else {
			verboseLog.Printf("[CLIENT] ✗ No pending request found for ID %s", tunnelResp.RequestID)
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
func handleWebSocketPing(ctx context.Context, conn *websocket.Conn, clientID string, verboseLog *log.Logger) {
	pingTime := 300 * time.Second
	ticker := time.NewTicker(pingTime)
	defer ticker.Stop()

	conn.SetPongHandler(func(appData string) error {
		verboseLog.Printf("[WS-PING] Received pong from %s", clientID)
		conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))
		return nil
	})

	conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))

	for {
		select {
		case <-ctx.Done():
			verboseLog.Printf("[WS-PING] Stopping ping for %s", clientID)
			return
		case <-ticker.C:
			verboseLog.Printf("[WS-PING] Sending ping to %s", clientID)
			err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add((3/2)*pingTime))
			if err != nil {
				verboseLog.Printf("[WS-PING] Failed to send ping to %s: %v", clientID, err)
				return
			}
		}
	}
}
