# Boring Machine

> A lightweight, secure HTTP tunneling system for exposing local applications to the internet

Boring Machine is a WebSocket-based HTTP tunnel that allows you to securely expose local services running behind firewalls or NAT to the public internet.

## Features

- **HTTP/HTTPS Tunneling** - Forward public requests to local applications
- **User Authentication** - Built-in user registration and token-based auth
- **WebSocket Protocol** - Efficient binary communication via encoding/gob
- **Admin Dashboard** - Real-time metrics and monitoring
- **TLS/WSS Support** - Secure communications with HTTPS/WSS
- **SQLite Database** - Embedded database with zero configuration
- **Custom Error Pages** - Branded error pages with diagnostics
- **System Monitoring** - CPU, memory, and connection metrics
- **Graceful Shutdown** - Proper cleanup with configurable timeouts
- **Development Mode** - Skip authentication for quick testing

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [Server](#server)
  - [Client](#client)
- [Authentication](#authentication)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Admin Dashboard](#admin-dashboard)
- [TLS/HTTPS Setup](#tlshttps-setup)
- [Development](#development)

## Quick Start

### Development Mode (No Authentication)

**Terminal 1 - Start Server:**
```bash
make dev-server
# Server listens on http://localhost:8443
```

**Terminal 2 - Start Client:**
```bash
# Assuming local app running on http://localhost:3000
make dev-client

# Output:
#  Connected to localhost:8443
#  Client ID: a1b2c3d4e5f6g7h8
#  Forwarding requests to 127.0.0.1:3000
#  Public URL: http://a1b2c3d4e5f6g7h8.localhost:8443
```

**Terminal 3 - Test the tunnel:**
```bash
curl http://a1b2c3d4e5f6g7h8.localhost:8443/api/users
# Request tunnels through WebSocket to your local app!
```

## Installation

### Prerequisites

- Go 1.24.5 or higher
- Make (optional, for convenience)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/imrraaj/boring-machine.git
cd boring-machine

# Build both binaries
make

# Or build individually
make client  # Creates bin/brc
make server  # Creates bin/brs
```

### Binaries

After building, you'll find two binaries in `bin/`:
- `brc` - Boring Machine Client
- `brs` - Boring Machine Server

You can move these to your `$PATH` for convenience:
```bash
sudo cp bin/brs /usr/local/bin/
sudo cp bin/brc /usr/local/bin/
```

## Usage

### Server

The server accepts WebSocket connections from clients and routes HTTP requests to them.

#### Basic Usage

```bash
./bin/brs [flags]
```

#### Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `:8443` | HTTP/HTTPS listening port |
| `-db` | `boringmachine.db` | SQLite database file path |
| `-skip-auth` | `false` | Disable authentication (dev/benchmark only) |
| `-verbose` | `false` | Enable verbose/debug logging |
| `-cert-file` | `""` | Path to TLS certificate (enables HTTPS) |
| `-key-file` | `""` | Path to TLS private key (enables HTTPS) |
| `-read_timeout` | `10s` | HTTP read timeout |
| `-write_timeout` | `10s` | HTTP write timeout |
| `-tunnel_timeout` | `30s` | Timeout for tunnel responses |

#### Examples

**Production server with authentication:**
```bash
./bin/brs \
  -port=:8443 \
  -db=/var/lib/boring-machine/data.db
```

**HTTPS server with TLS:**
```bash
./bin/brs \
  -port=:443 \
  -cert-file=/etc/boring-machine/cert.pem \
  -key-file=/etc/boring-machine/key.pem
```

**Development server (skip auth, verbose):**
```bash
./bin/brs -skip-auth -verbose
```

#### Server Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/register` | POST | Register new user |
| `/auth/login` | POST | Login and get token |
| `/auth/rotate` | POST | Rotate authentication token |
| `/tunnel/ws` | WebSocket | Client tunnel connection |
| `/admin/dashboard` | GET | Admin metrics dashboard |
| `/admin/api/metrics` | GET | Metrics JSON API |
| `/*` | Any | HTTP tunnel proxy |

### Client

The client connects to the server and forwards requests to your local application.

#### Basic Usage

```bash
./bin/brc <command> [flags]
```

#### Global Flags

| Flag | Description |
|------|-------------|
| `--verbose` | Enable verbose/debug logging |

#### Commands

##### 1. Authentication Commands

**Register a new account:**
```bash
./bin/brc auth register [--server URL]

# Interactive prompts:
# Enter username: alice
# Enter email: alice@example.com
# Enter password: ********
# Registration successful
# Token saved to ~/.boring-client/credentials
```

**Login to existing account:**
```bash
./bin/brc auth login [--server URL]

# Interactive prompts:
# Enter username: alice
# Enter password: ********
# Login successful
# Token saved to ~/.boring-client/credentials
```

**Rotate authentication token:**
```bash
./bin/brc auth rotate [--server URL]

# Token rotated successfully
# New token saved to ~/.boring-client/credentials
```

**Auth flags:**
- `--server`: Server URL (default: `http://localhost:8443`)

##### 2. Tunnel Command

**Start tunnel to local application:**
```bash
./bin/brc tunnel [flags]
```

**Tunnel Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `localhost:8443` | Server address |
| `--network` | `127.0.0.1` | Local application network |
| `--port` | `3000` | Local application port |
| `--secure` | `false` | Use WSS (secure WebSocket) |
| `--skip-auth` | `false` | Skip authentication |
| `--token` | `""` | Override token from credentials file |

#### Examples

**Tunnel to local app on port 3000:**
```bash
./bin/brc tunnel
# Uses stored credentials from ~/.boring-client/credentials
```

**Tunnel with specific port:**
```bash
./bin/brc tunnel --port 8080
```

**Tunnel with secure WebSocket:**
```bash
./bin/brc tunnel \
  --server example.com:443 \
  --secure \
  --port 3000
```

**Tunnel with manual token:**
```bash
./bin/brc tunnel \
  --server example.com:8443 \
  --token abc123def456...
```

**Development mode (skip auth):**
```bash
./bin/brc tunnel --skip-auth --verbose
```

#### Public URL Format

Once connected, your local application is accessible at:
```
http://{client-id}.{server-hostname}:{port}
```

Example:
```
http://a1b2c3d4e5f6g7h8.localhost:8443
```

The client ID is automatically generated (8-byte hex) and displayed when you connect.

## Authentication

Boring Machine uses token-based authentication with bcrypt password hashing.

### Registration Flow

1. User registers with username, email, and password
2. Password is hashed with bcrypt (cost 12)
3. User receives a 96-character hex token
4. Token is valid for 90 days
5. Token is stored in `~/.boring-client/credentials`

### Token Storage

Credentials are stored in JSON format at `~/.boring-client/credentials`:

```json
{
  "token": "abc123def456...",
  "username": "alice",
  "expires_at": "2026-03-15T10:30:00Z"
}
```

File permissions are automatically set to `0600` (readable only by owner).

### Token Validation

When the client connects:
1. Token is sent in the WebSocket registration message
2. Server validates token exists and hasn't expired
3. Server associates the tunnel with the user ID
4. `last_used_at` timestamp is updated

### Token Rotation

Rotate your token to invalidate the old one and get a fresh 90-day token:

```bash
./bin/brc auth rotate --server https://example.com
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database path (server)
DATABASE_PATH=/var/lib/boring-machine/data.db
```

The `.env` file is automatically loaded by both server and client.

### Database

Boring Machine uses SQLite for user and token storage.

**Schema:**
- `users` table: username, email, password_hash
- `auth_tokens` table: token, user_id, expires_at, last_used_at

**Features:**
- Automatic schema initialization on first run
- Foreign key constraints enabled
- Indexes on frequently queried columns
- Connection pooling optimized for SQLite (max 1 connection)

**Location:**
- Default: `boringmachine.db` (current directory)
- Override with `-db` flag or `DATABASE_PATH` env var

## Architecture

### System Overview

```
+------------------+
|  External User   |
+--------+---------+
         | HTTP
         v
+------------------+
|     Server       |  * Assigns client-id.hostname.com
|   (Public IP)    |
+--------+---------+
         | WebSocket (binary protocol)
         v
+------------------+
|     Client       |  * Runs on local machine
|  (Behind NAT)    |
+--------+---------+
         | HTTP
         v
+------------------+
|   Local App      |  * localhost:3000
|  (localhost)     |
+------------------+
```

### Communication Protocol

1. **Client Registration:**
   - Client connects via WebSocket to `/tunnel/ws`
   - Sends `ClientRegister` with auth token
   - Server validates and assigns unique client ID
   - Server responds with `RegistrationResponse`

2. **HTTP Request Flow:**
   - External user makes HTTP request to `{client-id}.server.com`
   - Server looks up client by ID from hostname
   - Server creates `TunnelRequest` with request details
   - Request is gob-encoded and sent via WebSocket
   - Client decodes request and forwards to local app
   - Client receives HTTP response from local app
   - Client creates `TunnelResponse` with response details
   - Response is gob-encoded and sent back via WebSocket
   - Server decodes and writes HTTP response to external user

3. **Keepalive:**
   - Server sends WebSocket ping every 300 seconds
   - Client must respond with pong to maintain connection
   - Missed pongs result in connection closure

### Protocol Types

```go
// Client -> Server (registration)
type ClientRegister struct {
    Token string
}

// Server -> Client (registration response)
type RegistrationResponse struct {
    Success  bool
    ClientID string
    Error    string
}

// Server -> Client (HTTP request)
type TunnelRequest struct {
    RequestID string      // Unique ID for matching
    Method    string      // HTTP method
    URL       string      // Request URL
    Headers   http.Header // HTTP headers
    Body      []byte      // Request body
}

// Client -> Server (HTTP response)
type TunnelResponse struct {
    RequestID  string      // Matches request ID
    StatusCode int         // HTTP status
    Headers    http.Header // Response headers
    Body       []byte      // Response body
}
```

## Admin Dashboard

Access real-time metrics and monitoring at:
```
http://your-server:8443/admin/dashboard
```

### Dashboard Features

- **Server Status:** Uptime, protocol (HTTP/HTTPS), start time
- **Connection Metrics:** Active tunnels, total connections
- **Request Metrics:** Forwarded requests, failed requests, success rate
- **System Resources:** CPU usage, memory usage, goroutines
- **Client Details:** Client ID, user ID, IP address, request count, last activity
- **Auto-refresh:** Updates every 5 seconds

### Metrics API

Get raw metrics in JSON format:
```bash
curl http://your-server:8443/admin/api/metrics
```

Response includes:
```json
{
  "server": {
    "uptime_seconds": 3600,
    "start_time": "2025-12-13T10:00:00Z"
  },
  "connections": {
    "active": 5,
    "total_accepted": 150,
    "total_closed": 145
  },
  "requests": {
    "forwarded": 12500,
    "failed": 23
  },
  "clients": [...],
  "system": {
    "cpu_percent": 15.2,
    "memory_used_mb": 45.3,
    "memory_total_mb": 8192,
    "memory_percent": 0.55,
    "goroutines": 42,
    "cpu_cores": 8
  }
}
```

## TLS/HTTPS Setup

### Generate Self-Signed Certificates

For development/testing:
```bash
make certs
# Certificates created in certs/
```

### Use Existing Certificates

For production with Let's Encrypt or commercial certs:
```bash
./bin/brs \
  -port=:443 \
  -cert-file=/etc/letsencrypt/live/example.com/fullchain.pem \
  -key-file=/etc/letsencrypt/live/example.com/privkey.pem
```

### Client with TLS

When server uses HTTPS, client must use secure WebSocket:
```bash
./bin/brc tunnel --server example.com:443 --secure
```

**Note:** Both `-cert-file` and `-key-file` must be provided. The server will reject configuration with only one.

## Development

### Build Targets

```bash
make              # Build both client and server
make client       # Build client only
make server       # Build server only
make clean        # Remove build artifacts
make certs        # Generate TLS certificates
make dev-server   # Run server (skip-auth, verbose)
make dev-client   # Run client (skip-auth, verbose)
```

### Dependencies

Key dependencies managed in `go.mod`:

- `github.com/gorilla/websocket` - WebSocket library
- `golang.org/x/crypto` - Bcrypt password hashing
- `golang.org/x/term` - Terminal password input
- `modernc.org/sqlite` - Pure Go SQLite driver

### Running Tests

Start a local test server (runs on port 5664):
```bash
go run cmd/benchmark/test_server.go
```

Then benchmark the tunnel:
```bash
# Terminal 1: Start boring-machine server
./bin/brs -skip-auth

# Terminal 2: Start client tunneling to test server
./bin/brc tunnel --skip-auth --port 5664

# Terminal 3: Benchmark
wrk -t12 -c400 -d30s http://{client-id}.localhost:8443/api/users
```

## Performance

Typical performance metrics (tested with `wrk`):

- **Throughput:** ~7,500 requests/second
- **Latency:** ~50-60ms average (includes tunnel overhead)
- **Concurrent Connections:** Tested with 400+ concurrent connections
- **Memory Usage:** ~40-50MB per server instance

Performance characteristics:
- WebSocket binary protocol using `encoding/gob`
- Connection pooling for local HTTP requests
- Concurrent request handling with goroutines
- Efficient request/response matching via maps

## Security Considerations

1. **Authentication:** Always use authentication in production (`-skip-auth` is for development only)
2. **TLS/HTTPS:** Use HTTPS in production to encrypt WebSocket traffic
3. **Token Storage:** Credentials file is created with 0600 permissions
4. **Password Hashing:** Bcrypt with cost factor 12
5. **Token Expiry:** 90-day expiration with rotation support
6. **Database:** Foreign key constraints prevent orphaned tokens

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---
