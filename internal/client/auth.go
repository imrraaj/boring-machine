package client

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

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Username  string    `json:"username"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func RequestToken(url string, body io.Reader) (tokenResponse, error) {
	var tokenResp tokenResponse
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return tokenResp, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return tokenResp, fmt.Errorf("%s", errResp.Error)
		}
		return tokenResp, fmt.Errorf("request failed: %s", string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return tokenResp, fmt.Errorf("failed to parse response: %w", err)
	}

	creds := &Credentials{
		Token:     tokenResp.Token,
		Username:  tokenResp.Username,
		ExpiresAt: tokenResp.ExpiresAt,
	}

	if err := SaveCredentials(creds); err != nil {
		return tokenResp, fmt.Errorf("failed to save credentials: %w", err)
	}

	return tokenResp, nil
}

func Login(url, username, password string) error {
	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	tokenResp, err := RequestToken(fmt.Sprintf("%s/auth/login", url), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	fmt.Printf("Login successful! Token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

func Register(serverURL, username, email, password string) error {
	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"email":    email,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	tokenResp, err := RequestToken(fmt.Sprintf("%s/auth/register", serverURL), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	fmt.Printf("Registration successful! Token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

func RotateToken(serverURL string) error {
	creds, err := LoadCredentials()
	if err != nil {
		return fmt.Errorf("failed to load credentials: %w", err)
	}

	reqBody, err := json.Marshal(map[string]string{"token": creds.Token})
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	tokenResp, err := RequestToken(fmt.Sprintf("%s/auth/rotate", serverURL), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}

	fmt.Printf("Token rotated successfully! New token expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	return nil
}

func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}
