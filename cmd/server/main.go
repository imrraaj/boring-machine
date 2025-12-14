package main

import (
	"boring-machine/internal/database"
	"boring-machine/internal/server"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	httpPort      = flag.String("port", ":8443", "Port for customer-facing server")
	readTimeout   = flag.Duration("read_timeout", 10*time.Second, "HTTP read timeout")
	writeTimeout  = flag.Duration("write_timeout", 10*time.Second, "HTTP write timeout")
	tunnelTimeout = flag.Duration("tunnel_timeout", 30*time.Second, "Timeout for tunnel requests")
	dbPath        = flag.String("db", "boringmachine.db", "SQLite database file path")
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
			*dbPath = "boringmachine.db"
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
			log.Fatalf("Failed to initialize database: %v", err)
		}
		defer db.Close()
		log.Println("✅ Database initialized successfully")
		log.Printf("Database path: %s", config.DBPath)
	} else {
		log.Println("⚠️  Running in skip-auth mode (development/benchmark only)")
		log.Println("⚠️  Authentication is disabled - all connections will be allowed")
	}

	srv, err := server.NewServer(config, db)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
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
		log.Fatalf("Failed to start server: %v", err)
	}

	<-ctx.Done()
	srv.Shutdown()
}
