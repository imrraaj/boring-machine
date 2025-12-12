package client

import (
	"errors"
	"fmt"
)

// Config holds all configuration for the client
type Config struct {
	// Server connection
	ServerAddr string

	// Local application
	ApplicationNetwork string
	ApplicationPort    int

	// Security
	SkipAuth bool
	Secure   bool

	// Logging
	Verbose bool
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.ServerAddr == "" {
		return errors.New("server address is required")
	}

	if c.ApplicationNetwork == "" {
		return errors.New("application network is required")
	}

	if c.ApplicationPort <= 0 || c.ApplicationPort > 65535 {
		return fmt.Errorf("application port must be between 1 and 65535, got %d", c.ApplicationPort)
	}

	return nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() Config {
	return Config{
		ServerAddr:         "localhost:8443",
		ApplicationNetwork: "127.0.0.1",
		ApplicationPort:    3000,
		SkipAuth:          false,
		Secure:            false,
		Verbose:           false,
	}
}
