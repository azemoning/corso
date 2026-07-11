package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type LoggedRequest struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Body      json.RawMessage   `json:"body,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

var (
	mu       sync.Mutex
	requests []LoggedRequest
)

func echoHandler(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if r.Body != nil {
		defer r.Body.Close()
		buf := make([]byte, r.ContentLength+512)
		n, _ := r.Body.Read(buf)
		if n > 0 {
			body = json.RawMessage(buf[:n])
		}
	}

	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	entry := LoggedRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		Body:      body,
		Headers:   headers,
		Timestamp: time.Now().UTC(),
	}

	mu.Lock()
	requests = append(requests, entry)
	mu.Unlock()

	log.Printf("Received %s %s (body=%d bytes)", r.Method, r.URL.Path, len(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","received":%d}`, len(requests))
}

func requestsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

func clearHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requests = nil
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"cleared"}`)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"healthy"}`)
}

func main() {
	http.HandleFunc("/", echoHandler)
	http.HandleFunc("/requests", requestsHandler)
	http.HandleFunc("/clear", clearHandler)
	http.HandleFunc("/healthz", healthHandler)

	log.Println("Echo server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
