package server

import (
	"boring-machine/internal/protocol"
	"context"
	"encoding/gob"
	"sync"

	"github.com/gorilla/websocket"
)

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

func (s *Server) handleClientConnection(conn *websocket.Conn) {
	defer conn.Close()

	wsrw := protocol.NewWebSocketReadWriter(conn)
	encoder := gob.NewEncoder(wsrw)
	decoder := gob.NewDecoder(wsrw)

	var reg protocol.ClientRegister
	err := decoder.Decode(&reg)
	if err != nil {
		s.logger.Printf("[WS] ✗ Error reading registration from %s: %v", conn.RemoteAddr(), err)
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseProtocolError, "invalid registration"))
		return
	}

	var userID int64
	if s.config.SkipAuth {
		s.logger.Printf("[WS] Authentication skipped (development mode)")
		userID = 0
	} else {
		userID, err = s.ValidateToken(context.Background(), reg.Token)
		if err != nil {
			s.logger.Printf("[WS] ✗ Invalid token from %s: %v", conn.RemoteAddr(), err)
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authentication failed"))
			return
		}
	}

	clientID := s.generateClientID()

	s.clientsMx.Lock()
	for {
		if _, exists := s.clients[clientID]; !exists {
			break
		}
		clientID = s.generateClientID()
	}

	pingCtx, pingCancel := context.WithCancel(context.Background())

	clientConn := &ClientConn{
		conn:            conn,
		encoder:         encoder,
		decoder:         decoder,
		pendingRequests: make(map[string]chan *protocol.TunnelResponse),
		cancelPing:      pingCancel,
	}

	s.clients[clientID] = clientConn
	s.clientsMx.Unlock()

	err = encoder.Encode(protocol.RegistrationResponse{
		Success:  true,
		ClientID: clientID,
		Error:    "",
	})
	if err != nil {
		s.logger.Printf("[WS] ✗ Failed to send registration response: %v", err)
		s.clientsMx.Lock()
		delete(s.clients, clientID)
		s.clientsMx.Unlock()
		return
	}

	s.logger.Printf("[WS] ✓ Client registered: %s (user: %d) from %s", clientID, userID, conn.RemoteAddr())

	s.metrics.ClientConnected(clientID, userID, conn.RemoteAddr().String())
	go s.handleWebSocketPing(pingCtx, conn, clientID)

	defer func() {
		pingCancel()
		s.clientsMx.Lock()
		delete(s.clients, clientID)
		s.clientsMx.Unlock()

		s.metrics.ClientDisconnected(clientID)

		s.logger.Printf("[WS] ✗ Client disconnected: %s", clientID)
	}()

	// Client ReadWrite loop
	for {
		var tunnelResp protocol.TunnelResponse
		clientConn.decoderMu.Lock()
		err := clientConn.decoder.Decode(&tunnelResp)
		clientConn.decoderMu.Unlock()

		if err != nil {
			return
		}

		clientConn.pendingMu.RLock()
		respChan, ok := clientConn.pendingRequests[tunnelResp.RequestID]
		clientConn.pendingMu.RUnlock()

		if ok {
			s.logger.Printf("[CLIENT] Routing response %s to waiting handler", tunnelResp.RequestID)
			respChan <- &tunnelResp
		} else {
			s.logger.Printf("[CLIENT] ✗ No pending request found for ID %s", tunnelResp.RequestID)
		}
	}
}
