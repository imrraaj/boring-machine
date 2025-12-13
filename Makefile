.PHONY: all client server clean certs dev-server dev-client help

# Default target
all: client server

# Build client binary
client:
	@echo "Building client..."
	@mkdir -p bin
	@go build -o bin/brc ./cmd/client
	@echo "✓ Client built: bin/brc"

# Build server binary
server:
	@echo "Building server..."
	@mkdir -p bin
	@go build -o bin/brs ./cmd/server
	@echo "✓ Server built: bin/brs"

# Generate self-signed certificates
certs:
	@echo "Generating self-signed certificates..."
	@./scripts/certs.sh
	@echo "✓ Certificates generated in certs/"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@echo "✓ Clean complete"


# Development server (skip auth, verbose logging)
dev-server:
	@echo "Starting development server (skip-auth, verbose)..."
	@go run ./cmd/server --skip-auth --verbose

# Development client (skip auth, verbose logging)
dev-client:
	@echo "Starting development client (skip-auth, verbose)..."
	@go run ./cmd/client --verbose tunnel --skip-auth

# Show help
help:
	@echo "Boring-Machine Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build both client and server (default)"
	@echo "  client       Build client binary only"
	@echo "  server       Build server binary only"
	@echo "  certs        Generate self-signed TLS certificates"
	@echo "  clean        Remove build artifacts"
	@echo "  dev-server   Run server in development mode (skip-auth, verbose)"
	@echo "  dev-client   Run client in development mode (skip-auth, verbose)"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build both binaries"
	@echo "  make client       # Build client only"
	@echo "  make dev-server   # Start dev server"
	@echo "  make clean        # Remove bin/ directory"
