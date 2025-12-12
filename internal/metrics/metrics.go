package metrics

import (
	"sync"
	"time"
)

// ServerMetrics tracks server-wide metrics
type ServerMetrics struct {
	mu sync.RWMutex

	// Server uptime
	StartTime time.Time

	// Connection metrics
	TotalConnectionsAccepted int64
	TotalConnectionsClosed   int64

	// Request metrics
	TotalRequestsForwarded int64
	TotalRequestsFailed    int64

	// Client metadata
	ClientInfo map[string]*ClientMetadata
}

// ClientMetadata stores per-client metrics
type ClientMetadata struct {
	ClientID      string
	UserID        int64
	ConnectedAt   time.Time
	RemoteAddr    string
	RequestCount  int64
	LastRequestAt time.Time
}

// MetricsSnapshot is a thread-safe snapshot of current metrics
type MetricsSnapshot struct {
	StartTime                time.Time
	TotalConnectionsAccepted int64
	TotalConnectionsClosed   int64
	TotalRequestsForwarded   int64
	TotalRequestsFailed      int64
	ClientInfo               map[string]*ClientMetadata
}

// NewServerMetrics creates a new ServerMetrics instance
func NewServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		StartTime:  time.Now(),
		ClientInfo: make(map[string]*ClientMetadata),
	}
}

// ClientConnected records a new client connection
func (m *ServerMetrics) ClientConnected(clientID string, userID int64, remoteAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalConnectionsAccepted++
	m.ClientInfo[clientID] = &ClientMetadata{
		ClientID:    clientID,
		UserID:      userID,
		ConnectedAt: time.Now(),
		RemoteAddr:  remoteAddr,
	}
}

// ClientDisconnected records a client disconnection
func (m *ServerMetrics) ClientDisconnected(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalConnectionsClosed++
	delete(m.ClientInfo, clientID)
}

// RequestForwarded increments the forwarded request counter for a client
func (m *ServerMetrics) RequestForwarded(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequestsForwarded++

	if client, exists := m.ClientInfo[clientID]; exists {
		client.RequestCount++
		client.LastRequestAt = time.Now()
	}
}

// RequestFailed increments the failed request counter
func (m *ServerMetrics) RequestFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequestsFailed++
}

// GetSnapshot returns a thread-safe snapshot of current metrics
func (m *ServerMetrics) GetSnapshot() MetricsSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Deep copy client info
	clientInfoCopy := make(map[string]*ClientMetadata, len(m.ClientInfo))
	for k, v := range m.ClientInfo {
		clientCopy := *v // Copy value
		clientInfoCopy[k] = &clientCopy
	}

	return MetricsSnapshot{
		StartTime:                m.StartTime,
		TotalConnectionsAccepted: m.TotalConnectionsAccepted,
		TotalConnectionsClosed:   m.TotalConnectionsClosed,
		TotalRequestsForwarded:   m.TotalRequestsForwarded,
		TotalRequestsFailed:      m.TotalRequestsFailed,
		ClientInfo:               clientInfoCopy,
	}
}
