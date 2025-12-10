package wsio

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

// WebSocketReadWriter wraps a WebSocket connection to provide io.ReadWriter interface
// for gob encoding. It handles WebSocket message framing correctly.
type WebSocketReadWriter struct {
	conn   *websocket.Conn
	reader io.Reader
	mu     sync.Mutex
}

// New creates a new WebSocketReadWriter
func New(conn *websocket.Conn) *WebSocketReadWriter {
	return &WebSocketReadWriter{
		conn: conn,
	}
}

// Read implements io.Reader by reading from WebSocket binary messages
func (w *WebSocketReadWriter) Read(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// If we have an existing reader, continue reading from it
	if w.reader != nil {
		n, err = w.reader.Read(p)
		if err != io.EOF {
			return n, err
		}
		// EOF means message is fully read, get next message
		w.reader = nil
	}

	// Get next WebSocket message reader
	_, w.reader, err = w.conn.NextReader()
	if err != nil {
		return 0, err
	}

	// Read from the new message
	return w.reader.Read(p)
}

// Write implements io.Writer by writing to WebSocket binary messages
func (w *WebSocketReadWriter) Write(p []byte) (n int, err error) {
	// Get a new message writer for each write
	writer, err := w.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	defer writer.Close()

	// Write the data
	return writer.Write(p)
}
