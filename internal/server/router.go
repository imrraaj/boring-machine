package server

import (
	"boring-machine/internal/database/sqlc"
	"boring-machine/internal/html"
	"boring-machine/internal/metrics"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	TokenLength = 48
	TokenExpiry = 90 * 24 * time.Hour
	BcryptCost  = 12
)

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	if !s.config.SkipAuth {
		mux.HandleFunc("/auth/register", s.HandleRegister)
		mux.HandleFunc("/auth/login", s.HandleLogin)
		mux.HandleFunc("/auth/rotate", s.HandleRotate)
	}

	mux.HandleFunc("/admin/dashboard", html.RenderDashboard)
	mux.HandleFunc("/admin/api/metrics", s.handleMetrics)
	mux.HandleFunc("/tunnel/ws", s.handleTunnelWebSocket)
	mux.HandleFunc("/", s.handleHTTPTunnel)

	return mux
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeError(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), BcryptCost)
	if err != nil {
		writeError(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	user, err := s.db.Queries.CreateUser(r.Context(), sqlc.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		writeError(w, "Database error", http.StatusInternalServerError)
		return
	}

	token, expiresAt, err := s.generateToken(r.Context(), user.ID)
	if err != nil {
		writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.db.Queries.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		writeError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, expiresAt, err := s.generateToken(r.Context(), user.ID)
	if err != nil {
		writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

func (s *Server) HandleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentToken := r.Header.Get("Authorization")
	if currentToken == "" {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "Token required", http.StatusBadRequest)
			return
		}
		currentToken = req.Token
	}

	authToken, err := s.db.Queries.GetTokenByValue(r.Context(), currentToken)
	if err != nil {
		writeError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if time.Now().After(authToken.ExpiresAt) {
		writeError(w, "Token expired", http.StatusUnauthorized)
		return
	}

	s.db.Queries.DeleteToken(r.Context(), authToken.ID)

	newToken, expiresAt, err := s.generateToken(r.Context(), authToken.UserID)
	if err != nil {
		writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	user, err := s.db.Queries.GetUserByID(r.Context(), authToken.UserID)
	if err != nil {
		writeError(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	writeJSON(w, TokenResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

func (s *Server) generateToken(ctx context.Context, userID int64) (string, time.Time, error) {
	tokenBytes := make([]byte, TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}

	tokenStr := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(TokenExpiry)

	_, err := s.db.Queries.CreateToken(ctx, sqlc.CreateTokenParams{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, expiresAt, nil
}

func (s *Server) ValidateToken(ctx context.Context, tokenStr string) (int64, error) {
	token, err := s.db.Queries.GetTokenByValue(ctx, tokenStr)
	if err != nil {
		return 0, fmt.Errorf("invalid token")
	}

	if time.Now().After(token.ExpiresAt) {
		return 0, fmt.Errorf("token expired")
	}

	go s.db.Queries.UpdateLastUsed(context.Background(), token.ID)

	return token.UserID, nil
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snapshot := s.metrics.GetSnapshot()
	sysStats := metrics.GetSystemStats()

	s.clientsMx.RLock()
	activeCount := len(s.clients)
	s.clientsMx.RUnlock()

	clientsList := make([]map[string]any, 0, len(snapshot.ClientInfo))
	for _, client := range snapshot.ClientInfo {
		clientsList = append(clientsList, map[string]any{
			"client_id":     client.ClientID,
			"user_id":       client.UserID,
			"connected_at":  client.ConnectedAt.Format(time.RFC3339),
			"remote_addr":   client.RemoteAddr,
			"request_count": client.RequestCount,
			"last_request_at": func() string {
				if client.LastRequestAt.IsZero() {
					return ""
				}
				return client.LastRequestAt.Format(time.RFC3339)
			}(),
		})
	}

	response := map[string]any{
		"server": map[string]any{
			"uptime_seconds": time.Since(snapshot.StartTime).Seconds(),
			"start_time":     snapshot.StartTime.Format(time.RFC3339),
		},
		"connections": map[string]any{
			"active":         activeCount,
			"total_accepted": snapshot.TotalConnectionsAccepted,
			"total_closed":   snapshot.TotalConnectionsClosed,
		},
		"requests": map[string]any{
			"forwarded": snapshot.TotalRequestsForwarded,
			"failed":    snapshot.TotalRequestsFailed,
		},
		"clients": clientsList,
		"system":  sysStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

/*
* Internal helper functions for JSON response and error handling
* These are internal utilities used by the server handlers.
* They provide consistent JSON response formatting and error handling across all API endpoints.
 */

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
