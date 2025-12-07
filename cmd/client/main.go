package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"boring-machine/internal/protocol"
)

var (
	serverAddr = flag.String("server", "localhost:8445", "Server address to connect to")
	localPort  = flag.Int("port", 3000, "Local port to proxy requests to")
	insecure   = flag.Bool("insecure", true, "Skip TLS certificate verification")
)

func main() {
	flag.Parse()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived shutdown signal, closing connection...")
		cancel()
	}()

	// Connect to server with TLS
	log.Printf("Connecting to server at %s...", *serverAddr)
	conn, err := tls.Dial("tcp", *serverAddr, &tls.Config{
		InsecureSkipVerify: *insecure,
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Generate random client ID
	clientID := generateClientID()
	log.Printf("Client ID: %s", clientID)

	// Register with server
	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)

	err = encoder.Encode(protocol.ClientRegister{ClientID: clientID})
	if err != nil {
		log.Fatalf("Failed to register: %v", err)
	}

	log.Printf("✓ Connected and registered with server")
	log.Printf("✓ Forwarding requests to localhost:%d", *localPort)
	log.Printf("✓ Public URL: https://%s.localhost:8443", clientID)

	// Create mutex for encoder (only one goroutine can encode at a time)
	var encoderMu sync.Mutex

	// Main loop: receive requests and proxy to local app
	errChan := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errChan <- nil
				return
			default:
				log.Printf("[DEBUG] Waiting to decode request...")
				var req protocol.TunnelRequest
				err := decoder.Decode(&req)
				log.Printf("[DEBUG] Decode returned, err=%v", err)
				if err != nil {
					if ctx.Err() != nil {
						// Context cancelled, normal shutdown
						errChan <- nil
					} else {
						errChan <- fmt.Errorf("decode error: %w", err)
					}
					return
				}

				log.Printf("→ %s %s (ID: %s)", req.Method, req.URL, req.RequestID)

				// Handle request concurrently
				go func(r protocol.TunnelRequest) {
					// Proxy request to local application
					resp := proxyToLocal(&r, *localPort)

					// Preserve RequestID in response
					resp.RequestID = r.RequestID

					// Send response (must be serialized)
					encoderMu.Lock()
					err := encoder.Encode(resp)
					encoderMu.Unlock()

					if err != nil {
						log.Printf("✗ Error sending response: %v", err)
						return
					}

					log.Printf("← %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
				}(req)
			}
		}
	}()

	// Wait for error or shutdown signal
	err = <-errChan
	if err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}

	log.Println("Client shutdown complete")
}

func proxyToLocal(tunnelReq *protocol.TunnelRequest, localPort int) *protocol.TunnelResponse {
	// Build local URL
	localURL := fmt.Sprintf("http://localhost:%d%s", localPort, tunnelReq.URL)

	// Create HTTP request
	req, err := http.NewRequest(tunnelReq.Method, localURL, bytes.NewReader(tunnelReq.Body))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    make(http.Header),
			Body:       []byte(fmt.Sprintf("Error creating request: %v", err)),
		}
	}

	// Copy headers
	for key, values := range tunnelReq.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Make request to local app
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error proxying to local app: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusBadGateway,
			Headers:    make(http.Header),
			Body:       []byte(fmt.Sprintf("Error connecting to local app on port %d: %v", localPort, err)),
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    make(http.Header),
			Body:       []byte(fmt.Sprintf("Error reading response: %v", err)),
		}
	}

	// Return tunnel response
	return &protocol.TunnelResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}
}

func generateClientID() string {
	b := make([]byte, 8)
	rand.Read(b)
	// return fmt.Sprintf("%x", b)
	return fmt.Sprintf("deltaw")
}
