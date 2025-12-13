package server

import (
	"fmt"
	"time"
)

type ServerConfig struct {
	HTTPPort      string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	TunnelTimeout time.Duration
	DBConnString  string
	SkipAuth      bool
	Verbose       bool
	CertFile      string
	KeyFile       string
}

func (c *ServerConfig) UseTLS() bool {
	return c.CertFile != "" && c.KeyFile != ""
}

func (c *ServerConfig) Protocol() string {
	if c.UseTLS() {
		return "HTTPS"
	}
	return "HTTP"
}

func (c *ServerConfig) Validate() error {
	if c.HTTPPort == "" {
		return fmt.Errorf("HTTP port is required")
	}
	if !c.SkipAuth && c.DBConnString == "" {
		return fmt.Errorf("database connection string is required when auth is enabled")
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return fmt.Errorf("both cert-file and key-file must be provided for TLS")
	}
	return nil
}
