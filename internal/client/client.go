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

	"github.com/gorilla/websocket"
)

type Client struct {
	config      ClientConfig
	credentials Credentials
	clientID    string
	wsConn      *websocket.Conn
	encoder     *gob.Encoder
	decoder     *gob.Decoder
	encoderMu   sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	logger      *log.Logger
}

func NewClient(config ClientConfig, creds Credentials) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		config:      config,
		credentials: creds,
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger.NewLogger(os.Stdout, config.Verbose, ""),
	}
}

func (c *Client) Connect() error {
	if err := c.config.Validate(); err != nil {
		return err
	}

	if err := c.dialWebSocket(); err != nil {
		log.Fatalf("✗ Failed to connect: %v", err)
		return err
	}

	if err := c.registerWithServer(); err != nil {
		log.Fatalf("✗ Failed to register: %v", err)
		return err
	}

	log.Printf("✓ Connected to %s", c.config.ServerAddr)
	log.Printf("✓ Client ID: %s", c.clientID)
	log.Printf("✓ Forwarding requests to %s:%d", c.config.ApplicationNetwork, c.config.ApplicationPort)
	log.Printf("✓ Public URL: http://%s.%s", c.clientID, c.config.ServerAddr)

	return nil
}

func (c *Client) Run() error {
	return c.runTunnel()
}

func (c *Client) Shutdown() error {
	c.cancel()
	if c.wsConn != nil {
		return c.wsConn.Close()
	}
	return nil
}

func (c *Client) Context() context.Context {
	return c.ctx
}

func (c *Client) dialWebSocket() error {
	wsProtocol := c.config.Protocol()
	wsURL := fmt.Sprintf("%s://%s/tunnel/ws", wsProtocol, c.config.ServerAddr)
	log.Printf("[%s] Attempting to connect via %s...", wsProtocol, wsURL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !c.config.Secure,
		},
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}

	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	if resp != nil {
		resp.Body.Close()
	}

	c.wsConn = conn
	return nil
}

func (c *Client) registerWithServer() error {
	c.logger.Printf("[DEBUG] Registering with server...")

	wsrw := protocol.NewWebSocketReadWriter(c.wsConn)
	c.encoder = gob.NewEncoder(wsrw)
	c.decoder = gob.NewDecoder(wsrw)

	err := c.encoder.Encode(protocol.ClientRegister{
		Token: c.credentials.Token,
	})
	if err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

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

func (c *Client) runTunnel() error {
	go func() {
		<-c.ctx.Done()
		c.wsConn.SetReadDeadline(time.Now())
		c.wsConn.Close()
	}()

	errChan := make(chan error, 1)
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				errChan <- nil
				return
			default:
				var req protocol.TunnelRequest
				err := c.decoder.Decode(&req)
				if err != nil {
					c.logger.Printf("✗ Decode error: %v", err)
					errChan <- fmt.Errorf("decode error: %w", err)
					return
				}

				// Log request - format: [200] GET /api/users
				c.logger.Printf("[DEBUG] → %s %s (ID: %s)", req.Method, req.URL, req.RequestID)
				go func(r protocol.TunnelRequest) {
					resp := c.proxyToLocal(&r)
					resp.RequestID = r.RequestID
					log.Printf("[%d] %s %s", resp.StatusCode, r.Method, r.URL)
					c.encoderMu.Lock()
					err := c.encoder.Encode(resp)
					c.encoderMu.Unlock()

					if err != nil {
						log.Printf("✗ Error sending response: %v", err)
						return
					}
				}(req)
			}
		}
	}()

	err := <-errChan
	if err != nil {
		return err
	}

	log.Println("Client shutdown complete")
	return nil
}

func (c *Client) proxyToLocal(tunnelReq *protocol.TunnelRequest) *protocol.TunnelResponse {
	localURL := fmt.Sprintf("http://%s:%d%s", c.config.ApplicationNetwork, c.config.ApplicationPort, tunnelReq.URL)
	c.logger.Printf("[DEBUG] Proxying to %s", localURL)
	req, err := http.NewRequest(tunnelReq.Method, localURL, bytes.NewReader(tunnelReq.Body))
	if err != nil {
		c.logger.Printf("✗ Error creating request: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    make(http.Header),
			Body:       fmt.Appendf([]byte{}, "Error creating request: %v", err),
		}
	}

	for key, values := range tunnelReq.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		c.logger.Printf("✗ Error connecting to local app: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusBadGateway,
			Headers:    make(http.Header),
			Body:       fmt.Appendf([]byte{}, "Error connecting to local app on port %d: %v", c.config.ApplicationPort, err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Printf("✗ Error reading response: %v", err)
		return &protocol.TunnelResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    make(http.Header),
			Body:       fmt.Appendf([]byte{}, "Error reading response: %v", err),
		}
	}

	c.logger.Printf("[DEBUG] Received response: %d %s (%d bytes)", resp.StatusCode, http.StatusText(resp.StatusCode), len(body))

	return &protocol.TunnelResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       fmt.Appendf([]byte{}, "%s", body),
	}
}
