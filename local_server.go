// local_server.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	publicServerAddr = flag.String("publicServerAddr", "ws://your_public_server_ip:8080/ws", "Public server WebSocket address")
	localServiceAddr = flag.String("localServiceAddr", "localhost:3000", "Address of your local service")
	reconnectDelay   = flag.Duration("reconnectDelay", 5*time.Second, "Delay before attempting to reconnect")
)

func main() {
	flag.Parse()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	var conn *websocket.Conn

	connect := func() error {
		u, err := url.Parse(*publicServerAddr)
		if err != nil {
			return fmt.Errorf("failed to parse public server address: %v", err)
		}
		log.Printf("Connecting to %s", u.String())

		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			return fmt.Errorf("dial error: %v", err)
		}
		log.Println("Connected to public server")
		conn = c
		return nil
	}

	// Attempt initial connection
	if err := connect(); err != nil {
		log.Fatalf("Initial connection failed: %v", err)
	}
	defer func() {
		if conn != nil {
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("Error during websocket closing:", err)
			}
			conn.Close()
		}
	}()

	// Handle disconnections and reconnection attempts
	go func() {
		defer close(interrupt)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				log.Printf("WebSocket disconnected: %v", err)
				// Attempt reconnection
				for {
					log.Printf("Attempting to reconnect in %s...", *reconnectDelay)
					select {
					case <-time.After(*reconnectDelay):
						if err := connect(); err == nil {
							log.Println("Reconnected to public server")
							return // Exit reconnection loop
						}
						log.Printf("Reconnect failed: %v", err)
					case <-interrupt:
						return // Exit reconnection goroutine on interrupt
					}
				}
			}
		}
	}()

	// Keep the connection alive (optional, can send heartbeats if needed)
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if conn != nil {
					err := conn.WriteMessage(websocket.TextMessage, []byte("heartbeat"))
					if err != nil {
						log.Println("Error sending heartbeat:", err)
						return
					}
				}
			case <-interrupt:
				return
			}
		}
	}()

	log.Println("Tunnel established. Local server connected.")

	// Your local server logic remains the same
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from your local server behind NAT!")
	})

	// Start your local HTTP server
	go func() {
		log.Printf("Starting local HTTP server on %s", *localServiceAddr)
		if err := http.ListenAndServe(*localServiceAddr, nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Local HTTP server error: %v", err)
		}
	}()

	<-interrupt
	log.Println("Interrupted")
}
