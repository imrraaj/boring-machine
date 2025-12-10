package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	ServerURL = "http://localhost:8443" // Baked into executable
)

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

// Login authenticates the user and stores the token
func Login(username, password string) error {
	// Create request
	reqBody, err := json.Marshal(LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	resp, err := http.Post(ServerURL+"/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return fmt.Errorf("login failed: %s", errResp.Error)
		}
		return fmt.Errorf("login failed: %s", string(body))
	}

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Save credentials
	creds := &Credentials{
		Token:     tokenResp.Token,
		Username:  tokenResp.Username,
		ExpiresAt: tokenResp.ExpiresAt,
	}

	if err := SaveCredentials(creds); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	fmt.Printf("Login successful! Token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

// Register creates a new user account and stores the token
func Register(username, email, password string) error {
	// Create request
	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"email":    email,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	resp, err := http.Post(ServerURL+"/auth/register", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return fmt.Errorf("registration failed: %s", errResp.Error)
		}
		return fmt.Errorf("registration failed: %s", string(body))
	}

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Save credentials
	creds := &Credentials{
		Token:     tokenResp.Token,
		Username:  tokenResp.Username,
		ExpiresAt: tokenResp.ExpiresAt,
	}

	if err := SaveCredentials(creds); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	fmt.Printf("Registration successful! Token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

// RotateToken rotates the current token
func RotateToken() error {
	// Load current credentials
	creds, err := LoadCredentials()
	if err != nil {
		return fmt.Errorf("failed to load credentials: %w", err)
	}

	// Create request
	reqBody, err := json.Marshal(map[string]string{"token": creds.Token})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	resp, err := http.Post(ServerURL+"/auth/rotate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return fmt.Errorf("rotation failed: %s", errResp.Error)
		}
		return fmt.Errorf("rotation failed: %s", string(body))
	}

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Save new credentials
	newCreds := &Credentials{
		Token:     tokenResp.Token,
		Username:  tokenResp.Username,
		ExpiresAt: tokenResp.ExpiresAt,
	}

	if err := SaveCredentials(newCreds); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	fmt.Printf("Token rotated successfully! New token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

// ReadPassword prompts for password without echoing
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}
