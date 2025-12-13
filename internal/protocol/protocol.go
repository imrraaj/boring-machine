package protocol

import (
	"io"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type WebSocketReadWriter struct {
	conn   *websocket.Conn
	reader io.Reader
	mu     sync.Mutex
}

func NewWebSocketReadWriter(conn *websocket.Conn) *WebSocketReadWriter {
	return &WebSocketReadWriter{
		conn: conn,
	}
}

func (w *WebSocketReadWriter) Read(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.reader != nil {
		n, err = w.reader.Read(p)
		if err != io.EOF {
			return n, err
		}
		w.reader = nil
	}

	_, w.reader, err = w.conn.NextReader()
	if err != nil {
		return 0, err
	}

	return w.reader.Read(p)
}

func (w *WebSocketReadWriter) Write(p []byte) (n int, err error) {
	writer, err := w.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	defer writer.Close()

	return writer.Write(p)
}

type ClientRegister struct {
	Token string
}

// RegistrationResponse is sent by the server after processing client registration
type RegistrationResponse struct {
	Success  bool
	ClientID string
	Error    string
}

// TunnelRequest represents an HTTP request to be sent through the tunnel
type TunnelRequest struct {
	RequestID string // Unique ID to match request with response
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
}

// TunnelResponse represents an HTTP response coming back through the tunnel
type TunnelResponse struct {
	RequestID  string // Matches the request ID
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// ConvertHTTPRequest converts an http.Request to a TunnelRequest
func ConvertHTTPRequest(r *http.Request) (*TunnelRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return &TunnelRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    body,
	}, nil
}
