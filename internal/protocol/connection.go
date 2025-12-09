package protocol

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// TunnelConn abstracts the underlying connection type (TCP or WebSocket)
// This allows gob encoding/decoding to work transparently over both transports
type TunnelConn interface {
	// io.ReadWriteCloser for gob encoding
	io.ReadWriteCloser

	// SetDeadline methods for timeout management
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error

	// RemoteAddr returns the remote address
	RemoteAddr() net.Addr

	// ConnectionType returns "tcp" or "websocket"
	ConnectionType() string
}

// TCPConn wraps a net.Conn for TCP connections
type TCPConn struct {
	Conn net.Conn // Exported for TCP keepalive access
}

// NewTCPConn creates a new TCPConn wrapper
func NewTCPConn(conn net.Conn) *TCPConn {
	return &TCPConn{Conn: conn}
}

func (t *TCPConn) Read(p []byte) (n int, err error) {
	return t.Conn.Read(p)
}

func (t *TCPConn) Write(p []byte) (n int, err error) {
	return t.Conn.Write(p)
}

func (t *TCPConn) Close() error {
	return t.Conn.Close()
}

func (t *TCPConn) SetReadDeadline(tm time.Time) error {
	return t.Conn.SetReadDeadline(tm)
}

func (t *TCPConn) SetWriteDeadline(tm time.Time) error {
	return t.Conn.SetWriteDeadline(tm)
}

func (t *TCPConn) RemoteAddr() net.Addr {
	return t.Conn.RemoteAddr()
}

func (t *TCPConn) ConnectionType() string {
	return "tcp"
}

// WebSocketConn wraps a gorilla/websocket.Conn for WebSocket connections
// It implements io.ReadWriteCloser to make gob encoding work transparently
// After the WebSocket upgrade, we use the underlying net.Conn directly for gob encoding
// This avoids the complexity of wrapping gob protocol in WebSocket messages
type WebSocketConn struct {
	conn       net.Conn   // The underlying net.Conn after WebSocket upgrade
	wsConn     *websocket.Conn // Keep reference for ping/pong and close
	remoteAddr net.Addr
}

// NewWebSocketConn creates a new WebSocketConn wrapper
// After WebSocket upgrade, we use the underlying connection for gob encoding
func NewWebSocketConn(wsConn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{
		conn:       wsConn.UnderlyingConn(),
		wsConn:     wsConn,
		remoteAddr: wsConn.RemoteAddr(),
	}
}

// Read implements io.Reader by reading from the underlying connection
func (w *WebSocketConn) Read(p []byte) (n int, err error) {
	return w.conn.Read(p)
}

// Write implements io.Writer by writing to the underlying connection
func (w *WebSocketConn) Write(p []byte) (n int, err error) {
	return w.conn.Write(p)
}

// Close closes the WebSocket connection with a proper close frame
func (w *WebSocketConn) Close() error {
	// Send close frame using WebSocket connection
	w.wsConn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second))
	// Close the underlying connection
	return w.conn.Close()
}

func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

func (w *WebSocketConn) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *WebSocketConn) ConnectionType() string {
	return "websocket"
}

// GetWebSocketConn returns the underlying websocket.Conn for ping/pong handlers
// Returns nil if this is not a WebSocket connection
func (w *WebSocketConn) GetWebSocketConn() *websocket.Conn {
	return w.wsConn
}
