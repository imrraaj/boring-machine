package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	conn net.Conn
	mu   sync.RWMutex
}

type ServerState struct {
	clients map[string]*Client
	mu      sync.RWMutex
}

type Server struct {
	state        *ServerState
	addr         string
	cert         string
	key          string
	mux          *http.ServeMux
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func NewServer(addr string, cert string, key string, mux *http.ServeMux, readTimeout time.Duration, writeTimeout time.Duration) *Server {
	return &Server{
		state: &ServerState{
			clients: make(map[string]*Client),
			mu:      sync.RWMutex{},
		},
		addr:         addr,
		cert:         cert,
		key:          key,
		mux:          mux,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
	}
}

func (s *Server) Start() error {
	cert, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server := &http.Server{
		Addr:         s.addr,
		Handler:      s.mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
	}
	return server.ListenAndServeTLS("", "")
}
