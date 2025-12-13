package metrics

import (
	"sync"
	"time"
)

type ServerMetrics struct {
	mu                       sync.RWMutex
	StartTime                time.Time
	TotalConnectionsAccepted int64
	TotalConnectionsClosed   int64
	TotalRequestsForwarded   int64
	TotalRequestsFailed      int64
	ClientInfo               map[string]*ClientMetadata
}

type ClientMetadata struct {
	ClientID      string
	UserID        int64
	ConnectedAt   time.Time
	RemoteAddr    string
	RequestCount  int64
	LastRequestAt time.Time
	ResponseBytes int64
}

func NewServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		StartTime:  time.Now(),
		mu:         sync.RWMutex{},
		ClientInfo: make(map[string]*ClientMetadata),
	}
}

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

func (m *ServerMetrics) ClientDisconnected(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalConnectionsClosed++
	delete(m.ClientInfo, clientID)
}

func (m *ServerMetrics) RequestForwarded(clientID string, responseSize int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequestsForwarded++

	if client, exists := m.ClientInfo[clientID]; exists {
		client.RequestCount++
		client.LastRequestAt = time.Now()
		client.ResponseBytes += int64(responseSize)
	}
}

func (m *ServerMetrics) RequestFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequestsFailed++
}

func (m *ServerMetrics) GetSnapshot() ServerMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Deep copy client info
	clientInfoCopy := make(map[string]*ClientMetadata, len(m.ClientInfo))
	for k, v := range m.ClientInfo {
		clientCopy := *v
		clientInfoCopy[k] = &clientCopy
	}

	return ServerMetrics{
		StartTime:                m.StartTime,
		TotalConnectionsAccepted: m.TotalConnectionsAccepted,
		TotalConnectionsClosed:   m.TotalConnectionsClosed,
		TotalRequestsForwarded:   m.TotalRequestsForwarded,
		TotalRequestsFailed:      m.TotalRequestsFailed,
		ClientInfo:               clientInfoCopy,
	}
}
