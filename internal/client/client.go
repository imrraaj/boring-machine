package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"boring-machine/internal/logger"
	"boring-machine/internal/protocol"
	"boring-machine/internal/wsio"

	"github.com/gorilla/websocket"
)

// Client represents a tunnel client instance
type Client struct {
	// Configuration
	config Config

	// State
	credentials Credentials
	clientID    string
	wsConn      *websocket.Conn
	encoder     *gob.Encoder
	decoder     *gob.Decoder
	encoderMu   sync.Mutex

	// Context for lifecycle management
	ctx    context.Context
	cancel context.CancelFunc

	// Logging (verbose-aware)
	logger *log.Logger
}

// NewClient creates a new client instance
func NewClient(config Config, creds Credentials) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		config:      config,
		credentials: creds,
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger.NewLogger(os.Stdout, config.Verbose, ""),
	}
}

// Connect establishes connection to the server and registers the client
func (c *Client) Connect() error {
	if err := c.config.Validate(); err != nil {
		return err
	}

	// Establish WebSocket connection
	if err := c.dialWebSocket(); err != nil {
		log.Printf("✗ Failed to connect: %v", err)
		return err
	}

	// Register with server
	if err := c.registerWithServer(); err != nil {
		log.Printf("✗ Failed to register: %v", err)
		return err
	}

	// Log connection info (always shown)
	log.Printf("✓ Connected to %s", c.config.ServerAddr)
	log.Printf("✓ Client ID: %s", c.clientID)
	log.Printf("✓ Forwarding requests to %s:%d", c.config.ApplicationNetwork, c.config.ApplicationPort)
	log.Printf("✓ Public URL: http://%s.localhost:8443", c.clientID)

	return nil
}

// Run starts the main tunnel loop
func (c *Client) Run() error {
	return c.runTunnel()
}

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() error {
	c.cancel()
	if c.wsConn != nil {
		return c.wsConn.Close()
	}
	return nil
}

// Context returns the client's context
func (c *Client) Context() context.Context {
	return c.ctx
}

// dialWebSocket establishes a WebSocket connection to the server
func (c *Client) dialWebSocket() error {
	wsProtocol := "ws"
	if c.config.Secure {
		wsProtocol = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/tunnel/ws", wsProtocol, c.config.ServerAddr)

	c.logger.Printf("[DEBUG] Attempting to connect via %s...", wsURL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}

	conn, resp, err := dialer.Dial(wsURL, nil)

	// Auto-detect: If ws:// fails and we haven't tried wss:// yet, try wss://
	if err != nil && !c.config.Secure {
		c.logger.Printf("[DEBUG] WebSocket connection failed: %v", err)
		c.logger.Printf("[DEBUG] Attempting secure connection (wss://)...")
		wsURL = fmt.Sprintf("wss://%s/tunnel/ws", c.config.ServerAddr)
		conn, resp, err = dialer.Dial(wsURL, nil)
		if err == nil {
			c.logger.Printf("[DEBUG] Successfully connected via wss:// (auto-detected)")
		}
	}

	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	if resp != nil {
		resp.Body.Close()
	}

	c.wsConn = conn
	return nil
}

// registerWithServer sends registration to server and waits for client ID
func (c *Client) registerWithServer() error {
	c.logger.Printf("[DEBUG] Registering with server...")

	wsrw := wsio.New(c.wsConn)
	c.encoder = gob.NewEncoder(wsrw)
	c.decoder = gob.NewDecoder(wsrw)

	// Send registration
	err := c.encoder.Encode(protocol.ClientRegister{
		Token: c.credentials.Token,
	})
	if err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Receive registration response
	var regResp protocol.RegistrationResponse
	err = c.decoder.Decode(&regResp)
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.Error)
	}

	c.clientID = regResp.ClientID
	c.logger.Printf("[DEBUG] Registered with client ID: %s", c.clientID)
	return nil
}

// runTunnel runs the main tunnel loop, receiving requests and proxying them
func (c *Client) runTunnel() error {
	// Force connection close when context is cancelled
	go func() {
		<-c.ctx.Done()
		// Set read deadline to past time to interrupt any blocking reads
		c.wsConn.SetReadDeadline(time.Now())
		// Close connection to ensure cleanup
		c.wsConn.Close()
	}()

	// Main loop: receive requests and proxy to local app
	errChan := make(chan error, 1)
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				errChan <- nil
				return
			default:
				c.logger.Printf("[DEBUG] Waiting to decode request...")
				var req protocol.TunnelRequest
				err := c.decoder.Decode(&req)
				c.logger.Printf("[DEBUG] Decode returned, err=%v", err)
				if err != nil {
					if c.ctx.Err() != nil {
						// Context cancelled, normal shutdown
						errChan <- nil
					} else {
						// Log actual error (always shown)
						log.Printf("✗ Decode error: %v", err)
						errChan <- fmt.Errorf("decode error: %w", err)
					}
					return
				}

				// Log request - format: [200] GET /api/users
				// In normal mode, we'll log after we get the response
				// In verbose mode, log incoming request
				c.logger.Printf("[DEBUG] → %s %s (ID: %s)", req.Method, req.URL, req.RequestID)

				// Handle request concurrently
				go func(r protocol.TunnelRequest) {
					// Proxy request to local application
					resp := c.proxyToLocal(&r)

					// Preserve RequestID in response
					resp.RequestID = r.RequestID

					// Log the completed request-response pair
					// Format: [200] GET /api/users
					log.Printf("[%d] %s %s", resp.StatusCode, r.Method, r.URL)

					// Send response (must be serialized)
					c.encoderMu.Lock()
					err := c.encoder.Encode(resp)
					c.encoderMu.Unlock()

					if err != nil {
						// Always log encoding errors
						log.Printf("✗ Error sending response: %v", err)
						return
					}

					c.logger.Printf("[DEBUG] Response sent for request %s", r.RequestID)
				}(req)
			}
		}
	}()

	// Wait for error or shutdown signal
	err := <-errChan
	if err != nil {
		return err
	}

	log.Println("Client shutdown complete")
	return nil
}

// proxyToLocal proxies a tunnel request to the local application
func (c *Client) proxyToLocal(tunnelReq *protocol.TunnelRequest) *protocol.TunnelResponse {
	// Build local URL
	localURL := fmt.Sprintf("http://%s:%d%s", c.config.ApplicationNetwork, c.config.ApplicationPort, tunnelReq.URL)

	c.logger.Printf("[DEBUG] Proxying to %s", localURL)

	// Create HTTP request
	req, err := http.NewRequest(tunnelReq.Method, localURL, bytes.NewReader(tunnelReq.Body))
	if err != nil {
		// Always log critical errors
		log.Printf("✗ Error creating request: %v", err)
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
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Always log connection errors
		log.Printf("✗ Error connecting to local app: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusBadGateway,
			Headers:    make(http.Header),
			Body:       []byte(fmt.Sprintf("Error connecting to local app on port %d: %v", c.config.ApplicationPort, err)),
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Always log read errors
		log.Printf("✗ Error reading response: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    make(http.Header),
			Body:       []byte(fmt.Sprintf("Error reading response: %v", err)),
		}
	}

	c.logger.Printf("[DEBUG] Received response: %d %s (%d bytes)", resp.StatusCode, http.StatusText(resp.StatusCode), len(body))

	// Return tunnel response
	return &protocol.TunnelResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}
}
