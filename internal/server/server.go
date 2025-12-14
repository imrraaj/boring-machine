package server

import (
	"boring-machine/internal/database"
	"boring-machine/internal/html"
	"boring-machine/internal/logger"
	"boring-machine/internal/metrics"
	"boring-machine/internal/protocol"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Server struct {
	config     ServerConfig
	clients    map[string]*ClientConn
	clientsMx  sync.RWMutex
	upgrader   websocket.Upgrader
	metrics    *metrics.ServerMetrics
	logger     *log.Logger
	httpServer *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
	db         *database.DB
}

func NewServer(config ServerConfig, db *database.DB) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	srv := &Server{
		config:  config,
		clients: make(map[string]*ClientConn),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			WriteBufferPool: &sync.Pool{},
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		metrics: metrics.NewServerMetrics(),
		logger:  logger.NewLogger(os.Stdout, config.Verbose, "[BRS] "),
		ctx:     ctx,
		cancel:  cancel,
		db:      db,
	}

	mux := srv.setupRoutes()

	srv.httpServer = &http.Server{
		Addr:         srv.config.HTTPPort,
		Handler:      mux,
		ReadTimeout:  srv.config.ReadTimeout,
		WriteTimeout: srv.config.WriteTimeout,
	}

	return srv, nil
}

func (s *Server) Start() error {
	log.Printf("Starting boring-machine server...")

	go func() {
		log.Printf("✓ %s server listening on %s", s.config.Protocol(), s.config.HTTPPort)
		var err error
		if s.config.UseTLS() {
			err = s.httpServer.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("%s server error: %v", s.config.Protocol(), err)
		}
	}()

	return nil
}

func (s *Server) Shutdown() error {
	log.Println("Shutting down servers...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	s.clientsMx.Lock()
	for _, client := range s.clients {
		client.conn.Close()
	}
	s.clientsMx.Unlock()

	log.Println("Server shutdown complete")
	return nil
}

func (s *Server) Context() context.Context {
	return s.ctx
}

func (s *Server) handleTunnelWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Printf("[WS] Failed to upgrade connection: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}
	go s.handleClientConnection(wsConn)
}

func (s *Server) handleHTTPTunnel(w http.ResponseWriter, r *http.Request) {
	s.clientsMx.RLock()
	parts := strings.Split(r.Host, ".")
	if len(parts) < 2 {
		s.clientsMx.RUnlock()
		http.Error(w, "Invalid hostname: missing client identifier", http.StatusBadRequest)
		return
	}
	clientID := parts[0]

	client := s.clients[clientID]
	s.clientsMx.RUnlock()

	if client == nil {
		html.RenderErrorPage(w, http.StatusNotFound, clientID, "client_not_found", "")
		return
	}

	s.logger.Printf("[TUNNEL] → Forwarding to client %s: %s %s", clientID, r.Method, r.URL)

	tunnelReq, err := protocol.ConvertHTTPRequest(r)
	if err != nil {
		s.logger.Printf("[TUNNEL] ✗ Error converting request: %v", err)
		s.metrics.RequestFailed()
		html.RenderErrorPage(w, http.StatusInternalServerError, clientID, "tunnel_error", err.Error())
		return
	}

	requestID := s.generateRequestID()
	tunnelReq.RequestID = requestID

	respChan := make(chan *protocol.TunnelResponse, 1)
	client.pendingMu.Lock()
	client.pendingRequests[requestID] = respChan
	client.pendingMu.Unlock()

	defer func() {
		client.pendingMu.Lock()
		delete(client.pendingRequests, requestID)
		client.pendingMu.Unlock()
		close(respChan)
	}()

	client.encoderMu.Lock()
	err = client.encoder.Encode(tunnelReq)
	client.encoderMu.Unlock()
	if err != nil {
		s.logger.Printf("[TUNNEL] ✗ Error sending to client: %v", err)
		s.metrics.RequestFailed()
		html.RenderErrorPage(w, http.StatusBadGateway, clientID, "tunnel_error", err.Error())
		return
	}

	var tunnelResp *protocol.TunnelResponse
	select {
	case tunnelResp = <-respChan:
	case <-time.After(s.config.TunnelTimeout):
		s.logger.Printf("[TUNNEL] ✗ Timeout waiting for response")
		s.metrics.RequestFailed()
		html.RenderErrorPage(w, http.StatusGatewayTimeout, clientID, "timeout", "")
		return
	}

	if html.IsApplicationDownError(tunnelResp.StatusCode, tunnelResp.Body) {
		s.logger.Printf("[TUNNEL] ✗ Application not responding")
		s.metrics.RequestFailed()
		html.RenderErrorPage(w, http.StatusBadGateway, clientID, "application_down", string(tunnelResp.Body))
		return
	}

	for key, values := range tunnelResp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(tunnelResp.StatusCode)
	w.Write(tunnelResp.Body)
	s.metrics.RequestForwarded(clientID, len(tunnelResp.Body))
}

func (s *Server) generateClientID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (s *Server) generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (s *Server) handleWebSocketPing(ctx context.Context, conn *websocket.Conn, clientID string) {
	pingTime := 300 * time.Second
	ticker := time.NewTicker(pingTime)
	defer ticker.Stop()

	conn.SetPongHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))
		return nil
	})

	conn.SetReadDeadline(time.Now().Add((3 / 2) * pingTime))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add((3/2)*pingTime))
			if err != nil {
				s.logger.Printf("[WS-PING] Failed to send ping to %s: %v", clientID, err)
				return
			}
		}
	}
}
