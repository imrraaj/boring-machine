package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"boring-machine/internal/client"
)

func handleAuthCommand(args []string) {
	authFlags := flag.NewFlagSet("auth", flag.ExitOnError)
	serverURL := authFlags.String("server", "http://localhost:8443", "Authentication server URL")
	authFlags.Parse(args)

	authArgs := authFlags.Args()
	if len(authArgs) < 1 {
		fmt.Println("Usage: client auth [--server URL] <login|register|rotate>")
		os.Exit(1)
	}

	authCmd := authArgs[0]

	switch authCmd {
	case "login":
		handleLogin(*serverURL)
	case "register":
		handleRegister(*serverURL)
	case "rotate":
		handleRotate(*serverURL)
	default:
		fmt.Printf("Unknown auth command: %s\n", authCmd)
		os.Exit(1)
	}
}

func handleLogin(serverURL string) {
	fmt.Print("❯Username: ")
	var username string
	fmt.Scanln(&username)

	password, err := client.ReadPassword("❯Password: ")
	if err != nil {
		fmt.Printf("Failed to read password: %v\n", err)
		return
	}

	if err := client.Login(serverURL, username, password); err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}

}

func handleRegister(serverURL string) {
	fmt.Print("❯Username: ")
	var username string
	fmt.Scanln(&username)

	fmt.Print("❯Email: ")
	var email string
	fmt.Scanln(&email)

	password, err := client.ReadPassword("❯Password: ")
	if err != nil {
		fmt.Printf("Failed to read password: %v\n", err)
		return
	}

	if err := client.Register(serverURL, username, email, password); err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}
}

func handleRotate(serverURL string) {
	if err := client.RotateToken(serverURL); err != nil {
		fmt.Printf("Token rotation failed: %v\n", err)
		return
	}
	fmt.Println("Token rotated successfully!")
}

func handleTunnelCommand(args []string, verbose bool) {
	tunnelFlags := flag.NewFlagSet("tunnel", flag.ExitOnError)
	applicationNetwork := tunnelFlags.String("network", "127.0.0.1", "Local application network address")
	applicationPort := tunnelFlags.Int("port", 3000, "Local application port")
	serverAddr := tunnelFlags.String("server", "localhost:8443", "Server address to connect to")
	skipAuth := tunnelFlags.Bool("skip-auth", false, "Skip authentication (development/benchmark mode only)")
	secure := tunnelFlags.Bool("secure", false, "Use secure WebSocket (wss://) instead of ws://")
	token := tunnelFlags.String("token", "", "Authentication token (overrides credentials file)")
	tunnelFlags.Parse(args)

	config := client.ClientConfig{
		ServerAddr:         *serverAddr,
		ApplicationNetwork: *applicationNetwork,
		ApplicationPort:    *applicationPort,
		SkipAuth:           *skipAuth,
		Secure:             *secure,
		Verbose:            verbose,
	}

	var creds *client.Credentials
	var err error

	if *skipAuth {
		log.Println("⚠️  Running in skip-auth mode (development/benchmark only)")
		creds = &client.Credentials{
			Username: "unknown",
			Token:    "unknown",
		}
	} else {
		if *token != "" {
			log.Println("Using token from --token flag")
			creds = &client.Credentials{
				Username: "unknown",
				Token:    *token,
			}
		} else {
			creds, err = client.LoadCredentials()
			if err != nil {
				fmt.Printf("Failed to load credentials: %v\n", err)
				return
			}
			log.Printf("Loaded credentials for user: %s", creds.Username)
		}
	}

	c := client.NewClient(config, *creds)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived shutdown signal, closing connection...")
		cancel()
		c.Shutdown()
	}()

	if err := c.Connect(); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}

	if err := c.Run(); err != nil {
		fmt.Printf("Tunnel error: %v\n", err)
		return
	}
}
