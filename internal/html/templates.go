package html

import (
	_ "embed"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

//go:embed error.html
var errorTemplate string

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.New("error").Parse(errorTemplate)
	if err != nil {
		panic("Failed to parse error template: " + err.Error())
	}
}

// ErrorPageData contains all data needed to render an error page
type ErrorPageData struct {
	StatusCode        int
	ErrorTitle        string
	ErrorMessage      string
	ClientID          string
	ServerStatus      bool
	TunnelStatus      bool
	ClientStatus      bool
	ApplicationStatus bool
	Port              int
	Details           string
	HelpText          template.HTML
}

// RenderErrorPage renders an HTML error page based on the error type
func RenderErrorPage(w http.ResponseWriter, statusCode int, clientID string, errorType string, details string) {
	data := ErrorPageData{
		StatusCode:   statusCode,
		ClientID:     clientID,
		Details:      details,
		ServerStatus: true, // Server is always working if we're rendering this page
	}

	switch errorType {
	case "client_not_found":
		data.ErrorTitle = "Client Not Connected"
		data.ErrorMessage = "The tunnel client you're trying to reach is not connected to the server."
		data.TunnelStatus = true
		data.ClientStatus = false
		data.ApplicationStatus = false
		data.HelpText = template.HTML(`
			<ul>
				<li>Make sure your tunnel client is running</li>
				<li>Check that the client ID in the URL is correct</li>
				<li>Verify your network connection</li>
			</ul>
		`)

	case "application_down":
		data.ErrorTitle = "Application Not Responding"
		data.ErrorMessage = "The tunnel client is connected, but your local application is not responding."
		data.TunnelStatus = true
		data.ClientStatus = true
		data.ApplicationStatus = false

		// Try to extract port from details
		if port := extractPort(details); port > 0 {
			data.Port = port
		}

		data.HelpText = template.HTML(`
			<ul>
				<li>Make sure your local application is running</li>
				<li>Verify the application is listening on the correct port</li>
				<li>Check application logs for errors</li>
			</ul>
		`)

	case "tunnel_error":
		data.ErrorTitle = "Tunnel Communication Error"
		data.ErrorMessage = "There was an error communicating with the tunnel client."
		data.TunnelStatus = false
		data.ClientStatus = false
		data.ApplicationStatus = false
		data.HelpText = template.HTML(`
			<ul>
				<li>The client may have disconnected</li>
				<li>Try restarting your tunnel client</li>
				<li>Check your network stability</li>
			</ul>
		`)

	case "timeout":
		data.ErrorTitle = "Tunnel Timeout"
		data.ErrorMessage = "The tunnel client took too long to respond."
		data.TunnelStatus = true
		data.ClientStatus = true
		data.ApplicationStatus = false
		data.HelpText = template.HTML(`
			<ul>
				<li>Your application may be overloaded or hung</li>
				<li>Check if your application is processing requests slowly</li>
				<li>Try restarting your local application</li>
			</ul>
		`)

	default:
		data.ErrorTitle = "Tunnel Error"
		data.ErrorMessage = "An unexpected error occurred while processing your request."
		data.TunnelStatus = false
		data.ClientStatus = false
		data.ApplicationStatus = false
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	if err := tmpl.Execute(w, data); err != nil {
		// Fallback to plain text if template fails
		http.Error(w, "Error rendering error page: "+err.Error(), http.StatusInternalServerError)
	}
}

// extractPort attempts to extract a port number from error details
func extractPort(details string) int {
	re := regexp.MustCompile(`port (\d+)`)
	matches := re.FindStringSubmatch(details)
	if len(matches) > 1 {
		port, err := strconv.Atoi(matches[1])
		if err == nil {
			return port
		}
	}
	return 0
}

// IsApplicationDownError checks if the response indicates the local app is down
func IsApplicationDownError(statusCode int, body []byte) bool {
	if statusCode != http.StatusBadGateway {
		return false
	}
	bodyStr := string(body)
	return strings.Contains(bodyStr, "Error connecting to local app on port")
}
