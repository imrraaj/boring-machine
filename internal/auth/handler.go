package auth

import (
	"boring-machine/internal/database/sqlc"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenLength = 48                  // bytes
	TokenExpiry = 90 * 24 * time.Hour // 90 days
	BcryptCost  = 12
)

type Handler struct {
	queries *sqlc.Queries
}

func NewHandler(queries *sqlc.Queries) *Handler {
	return &Handler{queries: queries}
}

// RegisterRequest represents the registration payload
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents the login payload
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// HandleRegister handles user registration
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		h.writeError(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), BcryptCost)
	if err != nil {
		h.writeError(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	// Create user
	user, err := h.queries.CreateUser(r.Context(), sqlc.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		// Check if it's a unique constraint violation (duplicate username/email)
		if strings.Contains(err.Error(), "unique constraint") || strings.Contains(err.Error(), "duplicate key") {
			h.writeError(w, "User already exists", http.StatusConflict)
			return
		}
		// Log actual error for debugging
		log.Printf("[AUTH] Error creating user: %v", err)
		h.writeError(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate token
	token, expiresAt, err := h.generateToken(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Return token
	h.writeJSON(w, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

// HandleLogin handles user login
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := h.queries.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		h.writeError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		h.writeError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate token
	token, expiresAt, err := h.generateToken(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Return token
	h.writeJSON(w, TokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

// HandleRotate handles token rotation
func (h *Handler) HandleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current token from header or body
	currentToken := r.Header.Get("Authorization")
	if currentToken == "" {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, "Token required", http.StatusBadRequest)
			return
		}
		currentToken = req.Token
	}

	// Validate current token
	authToken, err := h.queries.GetTokenByValue(r.Context(), currentToken)
	if err != nil {
		h.writeError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Check if expired
	if time.Now().After(authToken.ExpiresAt.Time) {
		h.writeError(w, "Token expired", http.StatusUnauthorized)
		return
	}

	// Delete old token
	h.queries.DeleteToken(r.Context(), authToken.ID)

	// Generate new token
	newToken, expiresAt, err := h.generateToken(r.Context(), authToken.UserID)
	if err != nil {
		h.writeError(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Get user for response
	user, err := h.queries.GetUserByID(r.Context(), authToken.UserID)
	if err != nil {
		h.writeError(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	// Return new token
	h.writeJSON(w, TokenResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		Username:  user.Username,
	})
}

// generateToken creates a new random token
func (h *Handler) generateToken(ctx context.Context, userID int64) (string, time.Time, error) {
	// Generate random bytes
	tokenBytes := make([]byte, TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}

	// Convert to hex string
	tokenStr := hex.EncodeToString(tokenBytes)

	// Calculate expiry
	expiresAt := time.Now().Add(TokenExpiry)

	// Store in database
	_, err := h.queries.CreateToken(ctx, sqlc.CreateTokenParams{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: pgtype.Timestamp{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, expiresAt, nil
}

// writeJSON writes a JSON response
func (h *Handler) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// writeError writes an error response
func (h *Handler) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
