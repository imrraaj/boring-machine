package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// User represents a user in our test data
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// TestServer is the local HTTP server for benchmarking
type TestServer struct {
	users   map[string]*User
	mu      sync.RWMutex
	port    int
	latency time.Duration
	server  *http.Server
}

// NewTestServer creates a new test server
func NewTestServer(port int, latencyMs int) *TestServer {
	ts := &TestServer{
		users:   make(map[string]*User),
		port:    port,
		latency: time.Duration(latencyMs) * time.Millisecond,
	}

	// Seed with some initial users
	ts.seedUsers(10)

	return ts
}

// seedUsers creates initial test data
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

// simulateLatency adds artificial delay
func (ts *TestServer) simulateLatency() {
	if ts.latency > 0 {
		time.Sleep(ts.latency)
	}
}

// Start starts the test server
func (ts *TestServer) Start() error {
	mux := http.NewServeMux()

	// Health endpoint (fast)
	mux.HandleFunc("/health", ts.handleHealth)

	// User endpoints
	mux.HandleFunc("/api/users", ts.handleUsers)
	mux.HandleFunc("/api/users/", ts.handleUserByID)
	mux.HandleFunc("/api/upload", ts.handleUpload)
	mux.HandleFunc("/api/slow", ts.handleSlow)

	ts.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ts.port),
		Handler: mux,
	}

	log.Printf("[TEST-SERVER] Starting on port %d", ts.port)
	return ts.server.ListenAndServe()
}

// Stop stops the test server
func (ts *TestServer) Stop() error {
	if ts.server != nil {
		return ts.server.Close()
	}
	return nil
}

// handleHealth is a fast health check endpoint
func (ts *TestServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleUsers handles GET /api/users and POST /api/users
func (ts *TestServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ts.handleGetUsers(w, r)
	case http.MethodPost:
		ts.handleCreateUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetUsers returns list of all users
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

// handleCreateUser creates a new user
func (ts *TestServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	ts.simulateLatency()

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("user-%d", rand.Intn(1000000))
	user := &User{
		ID:        id,
		Name:      req.Name,
		Email:     req.Email,
		CreatedAt: time.Now(),
	}

	ts.mu.Lock()
	ts.users[id] = user
	ts.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// handleUserByID handles GET /api/users/:id, PATCH /api/users/:id, DELETE /api/users/:id
func (ts *TestServer) handleUserByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	id := r.URL.Path[len("/api/users/"):]
	if id == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		ts.handleGetUser(w, r, id)
	case http.MethodPatch:
		ts.handleUpdateUser(w, r, id)
	case http.MethodDelete:
		ts.handleDeleteUser(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetUser returns a single user
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

// handleUpdateUser updates a user
func (ts *TestServer) handleUpdateUser(w http.ResponseWriter, r *http.Request, id string) {
	ts.simulateLatency()

	ts.mu.Lock()
	user, exists := ts.users[id]
	if !exists {
		ts.mu.Unlock()
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name  string `json:"name,omitempty"`
		Email string `json:"email,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ts.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Email != "" {
		user.Email = req.Email
	}

	ts.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// handleDeleteUser deletes a user
func (ts *TestServer) handleDeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	ts.simulateLatency()

	ts.mu.Lock()
	_, exists := ts.users[id]
	if !exists {
		ts.mu.Unlock()
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	delete(ts.users, id)
	ts.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// handleUpload simulates file upload
func (ts *TestServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Add longer latency for upload simulation
	time.Sleep(ts.latency * 5)

	// Read body (simulating file processing)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"bytes":     len(body),
		"timestamp": time.Now(),
	})
}

// handleSlow simulates slow endpoint with random latency
func (ts *TestServer) handleSlow(w http.ResponseWriter, r *http.Request) {
	// Random delay between 100ms and 500ms
	delay := time.Duration(100+rand.Intn(400)) * time.Millisecond
	time.Sleep(delay)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"delay_ms": delay.Milliseconds(),
		"message":  "This endpoint is intentionally slow",
	})
}

func main() {
	server := NewTestServer(6356, 50)
	server.Start()
}
