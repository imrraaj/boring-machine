package main

import (
	"boring-machine/internal/database"
	"boring-machine/internal/server"
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	httpPort      = flag.String("http_port", ":8443", "Port for customer-facing server")
	readTimeout   = flag.Duration("read_timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write_timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel_timeout", 30*time.Second, "Timeout for tunnel requests")
	dbPath        = flag.String("db", "", "SQLite database file path (default: boring-machine.db)")
	skipAuth      = flag.Bool("skip-auth", false, "Skip authentication (development/benchmark mode only)")
	verbose       = flag.Bool("verbose", false, "Enable verbose/debug logging")
	certFile      = flag.String("cert-file", "", "Path to TLS certificate file (enables HTTPS/WSS)")
	keyFile       = flag.String("key-file", "", "Path to TLS private key file (enables HTTPS/WSS)")
)

func main() {
	LoadEnv()
	flag.Parse()

	if *dbPath == "" && !*skipAuth {
		*dbPath = os.Getenv("DATABASE_PATH")
		if *dbPath == "" {
			*dbPath = "boring-machine.db"
		}
	}

	config := server.ServerConfig{
		HTTPPort:      *httpPort,
		ReadTimeout:   *readTimeout,
		WriteTimeout:  *writeTimeout,
		TunnelTimeout: *tunnelTimeout,
		DBPath:        *dbPath,
		SkipAuth:      *skipAuth,
		Verbose:       *verbose,
		CertFile:      *certFile,
		KeyFile:       *keyFile,
	}

	var db *database.DB
	var err error

	if !*skipAuth {
		db, err = database.New(context.Background(), config.DBPath)
		if err != nil {
			panic(err)
		}
		defer db.Close()
	}

	srv, err := server.NewServer(config, db)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	if err := srv.Start(); err != nil {
		panic(err)
	}

	<-ctx.Done()
	srv.Shutdown()
}
