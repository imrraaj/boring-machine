package protocol

import (
	"io"
	"net/http"
)

// ClientRegister is sent by the client when it first connects to register itself
type ClientRegister struct {
	Token string
}

// RegistrationResponse is sent by the server after processing client registration
type RegistrationResponse struct {
	Success  bool
	ClientID string
	Error    string
}

// TunnelRequest represents an HTTP request to be sent through the tunnel
type TunnelRequest struct {
	RequestID string // Unique ID to match request with response
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
}

// TunnelResponse represents an HTTP response coming back through the tunnel
type TunnelResponse struct {
	RequestID  string // Matches the request ID
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// ConvertHTTPRequest converts an http.Request to a TunnelRequest
func ConvertHTTPRequest(r *http.Request) (*TunnelRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	return &TunnelRequest{
		Method:  r.Method,
		URL:     r.URL.String(),
		Headers: r.Header,
		Body:    body,
	}, nil
}
