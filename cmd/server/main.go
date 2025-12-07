package main

import (
	"boring-machine/internal/protocol"
	"context"
	"crypto/rand"
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
)

var (
	httpPort      = flag.String("http-port", ":8443", "HTTPS port for customer-facing server")
	clientPort    = flag.String("client-port", ":8445", "Port for client connections")
	certFile      = flag.String("cert", "certs/cert.pem", "TLS certificate file")
	keyFile       = flag.String("key", "certs/key.pem", "TLS key file")
	readTimeout   = flag.Duration("read-timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write-timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel-timeout", 30*time.Second, "Timeout for tunnel requests")
)

// ClientConn wraps a connection with its encoder/decoder and mutex
type ClientConn struct {
	conn            net.Conn
	encoder         *gob.Encoder
	decoder         *gob.Decoder
	encoderMu       sync.Mutex
	decoderMu       sync.Mutex
	pendingRequests map[string]chan *protocol.TunnelResponse
	pendingMu       sync.RWMutex
}

func main() {
	flag.Parse()

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

	log.Printf("Starting boring-machine server...")
	log.Printf("HTTPS server will listen on %s", *httpPort)
	log.Printf("Client server will listen on %s", *clientPort)

	mux := http.NewServeMux()

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

	certs, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificates: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certs},
	}

	customerFacingServer := &http.Server{
		Addr:    *httpPort,
		Handler: mux,
		// TLSConfig:    tlsConfig,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}

	// Start HTTPS server in goroutine
	go func() {
		log.Printf("✓ HTTPS server listening on %s", *httpPort)
		err := customerFacingServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	// Start client-facing TCP server
	ln, err := tls.Listen("tcp", *clientPort, tlsConfig)
	if err != nil {
		log.Fatalf("Could not start client server: %s", err)
	}
	defer ln.Close()

	log.Printf("✓ Client server listening on %s", *clientPort)
	log.Println("Server ready! Waiting for client connections...")

	// Accept client connections in goroutine
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					// Server is shutting down
					return
				default:
					log.Printf("[CLIENT] Error accepting connection: %v", err)
					continue
				}
			}

			go handleClientConnection(conn, clients, &clientsMx)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Shutting down servers...")

	// Shutdown HTTPS server with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := customerFacingServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTPS server shutdown error: %v", err)
	}

	// Close client listener
	ln.Close()

	// Close all client connections
	clientsMx.Lock()
	for id, client := range clients {
		log.Printf("[CLIENT] Closing connection to %s", id)
		client.conn.Close()
	}
	clientsMx.Unlock()

	log.Println("Server shutdown complete")
}

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func handleClientConnection(conn net.Conn, clients map[string]*ClientConn, clientsMx *sync.RWMutex) {
	defer conn.Close()

	// Enable TCP keepalive
	if tcpConn, ok := conn.(*tls.Conn); ok {
		if tc, ok := tcpConn.NetConn().(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
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

	log.Printf("[CLIENT] ✓ Client registered: %s from %s", reg.ClientID, conn.RemoteAddr())

	// Store client connection
	clientConn := &ClientConn{
		conn:            conn,
		encoder:         encoder,
		decoder:         decoder,
		pendingRequests: make(map[string]chan *protocol.TunnelResponse),
	}

	clientsMx.Lock()
	clients[reg.ClientID] = clientConn
	activeClients := len(clients)
	clientsMx.Unlock()

	log.Printf("[CLIENT] Active clients: %d", activeClients)

	// Clean up on disconnect
	defer func() {
		clientsMx.Lock()
		delete(clients, reg.ClientID)
		activeClients := len(clients)
		clientsMx.Unlock()
		log.Printf("[CLIENT] ✗ Client disconnected: %s (active: %d)", reg.ClientID, activeClients)
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
