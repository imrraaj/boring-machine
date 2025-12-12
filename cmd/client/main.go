package main

import (
	"flag"
	"fmt"
	"os"
)

var verbose bool

func main() {
	// Parse global flags
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose/debug logging")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	subcommand := args[0]

	switch subcommand {
	case "auth":
		handleAuthCommand(args[1:])
	case "tunnel":
		handleTunnelCommand(args[1:], verbose)
	default:
		fmt.Printf("Unknown command: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: client [--verbose] <command> [options]")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  --verbose      Enable verbose/debug logging")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  auth           Authenticate with server")
	fmt.Println("  tunnel         Start tunnel to local server")
	fmt.Println()
	fmt.Println("Auth Options:")
	fmt.Println("  --server string")
	fmt.Println("        Authentication server URL (default \"http://localhost:8443\")")
	fmt.Println()
	fmt.Println("Auth Subcommands:")
	fmt.Println("  login          Login and store authentication token")
	fmt.Println("  register       Register new account and store authentication token")
	fmt.Println("  rotate         Rotate authentication token")
	fmt.Println()
	fmt.Println("Tunnel Options:")
	fmt.Println("  --server string")
	fmt.Println("        Server address to connect to (default \"localhost:8443\")")
	fmt.Println("  --network string")
	fmt.Println("        Local application network address (default \"127.0.0.1\")")
	fmt.Println("  --port int")
	fmt.Println("        Local application port (default 3000)")
	fmt.Println("  --secure")
	fmt.Println("        Use secure WebSocket (wss://) instead of ws://")
	fmt.Println("  --skip-auth")
	fmt.Println("        Skip authentication (development/benchmark mode only)")
	fmt.Println("  --token string")
	fmt.Println("        Authentication token (overrides credentials file)")
}
