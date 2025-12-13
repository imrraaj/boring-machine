package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type TestServer struct {
	users   map[string]*User
	mu      sync.RWMutex
	port    int
	latency time.Duration
	server  *http.Server
}

func NewTestServer(port int, latencyMs int) *TestServer {
	ts := &TestServer{
		users:   make(map[string]*User),
		port:    port,
		latency: time.Duration(latencyMs) * time.Millisecond,
	}

	ts.seedUsers(20)

	return ts
}

func (ts *TestServer) seedUsers(count int) {
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("user-%d", i)
		ts.users[id] = &User{
			ID:        id,
			Name:      fmt.Sprintf("Test User %d", i),
			Email:     fmt.Sprintf("user%d@example.com", i),
			CreatedAt: time.Now().Add(-time.Duration(i) * time.Hour),
		}
	}
}

func (ts *TestServer) simulateLatency() {
	if ts.latency > 0 {
		time.Sleep(ts.latency)
	}
}

func (ts *TestServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/users", ts.handleUsers)
	mux.HandleFunc("/api/slow", ts.handleSlow)

	ts.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ts.port),
		Handler: mux,
	}

	log.Printf("[TEST-SERVER] Starting on port %d", ts.port)
	return ts.server.ListenAndServe()
}

func (ts *TestServer) Stop() error {
	if ts.server != nil {
		return ts.server.Close()
	}
	return nil
}

func (ts *TestServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ts.handleGetUsers(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ts *TestServer) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	ts.simulateLatency()

	ts.mu.RLock()
	users := make([]*User, 0, len(ts.users))
	for _, user := range ts.users {
		users = append(users, user)
	}
	ts.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"users": users,
		"count": len(users),
	})
}

func (ts *TestServer) handleGetUser(w http.ResponseWriter, r *http.Request, id string) {
	ts.simulateLatency()

	ts.mu.RLock()
	user, exists := ts.users[id]
	ts.mu.RUnlock()

	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (ts *TestServer) handleSlow(w http.ResponseWriter, r *http.Request) {
	delay := time.Duration(100+rand.Intn(400)) * time.Millisecond
	time.Sleep(delay)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"delay_ms": delay.Milliseconds(),
		"message":  "This endpoint is intentionally slow",
	})
}

func main() {
	server := NewTestServer(5664, 50)
	server.Start()
}
