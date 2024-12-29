// public_server.go
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/promhttp"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

// Configuration struct
type Config struct {
	LocalServers  []string `yaml:"local_servers"`
	WhitelistCIDR []string `yaml:"whitelist_cidr"`
	RateLimit     int      `yaml:"rate_limit"`
}

var (
	publicAddr    = flag.String("publicAddr", ":8080", "Public server address")
	publicTLSAddr = flag.String("publicTLSAddr", ":8443", "Public TLS server address")
	certFile      = flag.String("certFile", "server.crt", "Path to TLS certificate file")
	keyFile       = flag.String("keyFile", "server.key", "Path to TLS key file")
	configFile    = flag.String("config", "config.yaml", "Path to the configuration file")
	metricsAddr   = flag.String("metricsAddr", ":9090", "Address for Prometheus metrics")

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for simplicity; configure properly in production
		},
	}

	localConnections      = make(map[*websocket.Conn]string) // Conn -> Local Server Address
	localConnectionsMutex sync.Mutex
	config                Config
	limiter               *rate.Limiter
	requestCounter        = promauto.NewCounter(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests served.",
	})
	activeConnectionsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "websocket_connections_active",
		Help: "Number of active WebSocket connections.",
	})
)

func loadConfig() error {
	f, err := os.ReadFile(*configFile)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(f, &config)
	if err != nil {
		return err
	}
	return nil
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}

	// Here, you might implement a handshake to identify the local server
	// For simplicity, we'll just assign one based on availability
	localAddr := selectLocalServer()
	if localAddr == "" {
		conn.WriteMessage(websocket.TextMessage, []byte("No local servers available"))
		conn.Close()
		return
	}

	localConnectionsMutex.Lock()
	localConnections[conn] = localAddr
	localConnectionsMutex.Unlock()
	activeConnectionsGauge.Inc()

	log.Printf("Local server connected via WebSocket: %s", localAddr)

	defer func() {
		localConnectionsMutex.Lock()
		delete(localConnections, conn)
		localConnectionsMutex.Unlock()
		conn.Close()
		activeConnectionsGauge.Dec()
		log.Println("Local server disconnected")
	}()

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("WebSocket read error: %v from %s", err, localAddr)
			}
			break
		}
		log.Printf("Received from local server %s: [%d] %s", localAddr, messageType, p)
		// Handle messages from local server if needed
	}
}

func selectLocalServer() string {
	localConnectionsMutex.Lock()
	defer localConnectionsMutex.Unlock()

	if len(config.LocalServers) == 0 {
		return ""
	}

	// Simple Round-Robin load balancing
	var availableServers []string
	serverCounts := make(map[string]int)
	for _, addr := range config.LocalServers {
		serverCounts[addr] = 0
	}
	for _, addr := range localConnections {
		serverCounts[addr]++
	}

	minConnections := -1
	var selectedServer string
	for _, addr := range config.LocalServers {
		if minConnections == -1 || serverCounts[addr] < minConnections {
			minConnections = serverCounts[addr]
			selectedServer = addr
		}
	}
	return selectedServer
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	requestCounter.Inc()

	// IP Whitelisting
	if len(config.WhitelistCIDR) > 0 {
		clientIPPort := r.RemoteAddr
		clientIP, _, err := netip.SplitPort(clientIPPort)
		if err != nil {
			log.Printf("Error parsing client IP: %v", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		allowed := false
		for _, cidrStr := range config.WhitelistCIDR {
			_, cidr, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				log.Printf("Error parsing whitelist CIDR: %v", err)
				continue // Skip invalid CIDR
			}
			if cidr.Contains(clientIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("Blocked request from IP: %s", clientIP)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	// Rate Limiting
	if config.RateLimit > 0 && !limiter.Allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	localConnectionsMutex.Lock()
	var targetServer string
	// Simple load balancing - find a local server with active connections
	for _, addr := range localConnections {
		targetServer = addr
		break // Use the first available one for simplicity, improve later if needed
	}
	localConnectionsMutex.Unlock()

	if targetServer == "" {
		http.Error(w, "No backend servers available", http.StatusServiceUnavailable)
		return
	}

	targetURL, err := url.Parse(targetServer)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Error parsing local address: %v", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = targetURL.Host

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("HTTP proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(rw, "Backend fetch failed: %v", err)
	}

	proxy.ServeHTTP(w, r)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func main() {
	flag.Parse()

	if err := loadConfig(); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	limiter = rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit)

	// Handle WebSocket connection from the local server
	http.HandleFunc("/ws", handleWebSocket)

	// Handle all other requests as reverse proxy requests
	http.HandleFunc("/", proxyHandler)

	// Metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Start metrics server
	go func() {
		log.Printf("Starting metrics server on %s", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()

	// Start HTTP server
	go func() {
		log.Printf("Starting HTTP server on %s", *publicAddr)
		if err := http.ListenAndServe(*publicAddr, nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server if certificate and key are provided
	if *certFile != "" && *keyFile != "" {
		go func() {
			log.Printf("Starting HTTPS server on %s", *publicTLSAddr)
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 or higher
			}
			server := &http.Server{
				Addr:      *publicTLSAddr,
				Handler:   nil,
				TLSConfig: tlsConfig,
			}
			if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Println("TLS certificate and key not provided, HTTPS will not be enabled.")
	}

	// Keep the public server running
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("Shutting down...")

	// Add graceful shutdown for HTTP/HTTPS servers here if needed
	// Example:
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	// if err := server.Shutdown(ctx); err != nil {
	// 	log.Fatalf("HTTPS server shutdown failed: %v", err)
	// }

	log.Println("Server gracefully stopped")
}
