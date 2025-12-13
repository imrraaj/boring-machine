package client

import (
	"errors"
	"fmt"
)

type ClientConfig struct {
	ServerAddr         string
	ApplicationNetwork string
	ApplicationPort    int
	SkipAuth           bool
	Secure             bool
	Verbose            bool
}

func (c *ClientConfig) Validate() error {
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
func (c *ClientConfig) UseTLS() bool {
	return c.Secure
}

func (c *ClientConfig) Protocol() string {
	if c.UseTLS() {
		return "wss"
	}
	return "ws"
}
func DefaultConfig() ClientConfig {
	return ClientConfig{
		ServerAddr:         "localhost:8443",
		ApplicationNetwork: "127.0.0.1",
		ApplicationPort:    3000,
		SkipAuth:           false,
		Secure:             false,
		Verbose:            false,
	}
}
