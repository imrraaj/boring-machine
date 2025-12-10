.PHONY: all client server clean install certs test dev-server dev-client help

# Default target
all: client server

# Build client binary
client:
	@echo "Building client..."
	@mkdir -p bin
	@go build -o bin/boring-client ./cmd/client
	@echo "✓ Client built: bin/boring-client"

# Build server binary
server:
	@echo "Building server..."
	@mkdir -p bin
	@go build -o bin/boring-server ./cmd/server
	@echo "✓ Server built: bin/boring-server"

# Install to GOPATH/bin or GOBIN
install: all
	@echo "Installing binaries..."
	@if [ -n "$(GOBIN)" ]; then \
		cp bin/boring-client $(GOBIN)/; \
		cp bin/boring-server $(GOBIN)/; \
		echo "✓ Installed to $(GOBIN)"; \
	elif [ -n "$(GOPATH)" ]; then \
		cp bin/boring-client $(GOPATH)/bin/; \
		cp bin/boring-server $(GOPATH)/bin/; \
		echo "✓ Installed to $(GOPATH)/bin"; \
	else \
		echo "⚠️  Neither GOBIN nor GOPATH is set"; \
		echo "   Install manually or set GOPATH"; \
		exit 1; \
	fi

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

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

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
	@echo "  install      Install binaries to GOPATH/bin or GOBIN"
	@echo "  certs        Generate self-signed TLS certificates"
	@echo "  clean        Remove build artifacts"
	@echo "  test         Run all tests"
	@echo "  dev-server   Run server in development mode (skip-auth, verbose)"
	@echo "  dev-client   Run client in development mode (skip-auth, verbose)"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build both binaries"
	@echo "  make client       # Build client only"
	@echo "  make install      # Build and install to GOPATH/bin"
	@echo "  make dev-server   # Start dev server"
	@echo "  make clean        # Remove bin/ directory"
