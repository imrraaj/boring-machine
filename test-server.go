package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		response := fmt.Sprintf(`Hello from test server!
Time: %s
Method: %s
Path: %s
Headers:
`, time.Now().Format(time.RFC3339), r.Method, r.URL.Path)

		for key, values := range r.Header {
			for _, value := range values {
				response += fmt.Sprintf("  %s: %s\n", key, value)
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))

		log.Printf("Sent response (%d bytes)", len(response))
	})

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<h1>Hello from the tunnel!</h1><p>This is a test response.</p>"))
	})

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Hello from tunnel","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	server := &http.Server{
		Addr:    ":3000",
		Handler: mux,
	}

	log.Println("Test HTTP server starting on http://localhost:3000")
	log.Println("Endpoints:")
	log.Println("  /       - Plain text with request info")
	log.Println("  /hello  - HTML response")
	log.Println("  /json   - JSON response")
	log.Fatal(server.ListenAndServe())
}
