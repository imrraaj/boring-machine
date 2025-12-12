package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	CredentialsDir  = ".boring-client"
	CredentialsFile = "credentials"
)

type Credentials struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetCredentialsPath returns the path to the credentials file
func GetCredentialsPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	credDir := filepath.Join(homeDir, CredentialsDir)
	return filepath.Join(credDir, CredentialsFile), nil
}

// SaveCredentials saves credentials to disk
func SaveCredentials(creds *Credentials) error {
	credPath, err := GetCredentialsPath()
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	credDir := filepath.Dir(credPath)
	if err := os.MkdirAll(credDir, 0700); err != nil {
		return fmt.Errorf("failed to create credentials directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Write to file with restrictive permissions
	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	return nil
}

// LoadCredentials loads credentials from disk
func LoadCredentials() (*Credentials, error) {
	credPath, err := GetCredentialsPath()
	if err != nil {
		return nil, err
	}

	// Read file
	data, err := os.ReadFile(credPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no credentials found. Please run 'client auth login' first")
		}
		return nil, fmt.Errorf("failed to read credentials: %w", err)
	}

	// Unmarshal JSON
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	// Check if expired
	if time.Now().After(creds.ExpiresAt) {
		return nil, fmt.Errorf("token expired. Please run 'client auth login' or 'client auth rotate'")
	}

	return &creds, nil
}
