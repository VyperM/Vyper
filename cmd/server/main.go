package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync" // Import sync package for WaitGroup

	"github.com/UltraTLS/UltraTLS/config"   // Import config package
	"github.com/UltraTLS/UltraTLS/protocol" // Import protocol package
	"github.com/UltraTLS/UltraTLS/server"   // Import server package
	v2net "github.com/v2fly/v2ray-core/v5/common/net" // Import v2net
)

// NewErrFrame creates a new ERR_FRAME.
// This function is defined here because it's not exported from the protocol package,
// and we are only allowed to modify cmd/server/main.go.
func NewErrFrame(content []byte) *protocol.VyperSessionFrame {
	return &protocol.VyperSessionFrame{
		FrameType: 0x05, // ERR_FRAME
		Sequence:  0,    // Sequence can be 0 for ERR_FRAME
		Content:   content,
	}
}

func main() {
	// Load server configuration
	serverConf, err := config.LoadServerConfig()
	if err != nil {
		log.Fatalf("Failed to load server configuration: %v", err)
	}

	// Define the Mux.Cool layer handler function for the server
	// This function is responsible for handling REQ_FRAME received from the Mux.Cool sub-stream
	// and connecting to the target website.
	serverHandler := func(stream protocol.Stream) {
		// Get the target address from the Mux.Cool sub-stream.
		// The protocol.Stream interface (from protocol/stream.go) now includes a Destination() method.
		targetDest := stream.Destination()

		if targetDest.IsValid() {
			log.Printf("Server: Accepted Mux sub-stream for target: %s", targetDest.String())

			// Establish connection to the target website
			// targetDest.NetAddr() returns a "host:port" formatted string, suitable for net.Dial.
			targetConn, err := net.Dial("tcp", targetDest.NetAddr())
			if err != nil {
				log.Printf("Server: Failed to connect to target %s: %v", targetDest.String(), err)
				// Send ERR_FRAME to notify the client about the connection failure
				errFrame := NewErrFrame([]byte(fmt.Sprintf("Failed to connect to target: %v", err)))
				// protocol.WriteFrame is assumed to write the Vyper frame directly to the underlying connection
				// which protocol.Stream (v2Stream) encapsulates.
				if _, writeErr := protocol.WriteFrame(stream, errFrame); writeErr != nil {
					log.Printf("Server: Failed to send ERR_FRAME to client: %v", writeErr)
				}
				stream.Close() // Close the Mux sub-stream
				return
			}
			defer targetConn.Close() // Ensure the connection to the target website is eventually closed
			log.Printf("Server: Successfully connected to target %s", targetDest.String())

			// Bidirectional data forwarding
			var wg sync.WaitGroup
			wg.Add(2) // Two goroutines: one for client-to-target, one for target-to-client

			// Goroutine 1: Read data from Mux sub-stream and write to target connection (client to target)
			go func() {
				defer wg.Done()
				_, err := io.Copy(targetConn, stream) // Read from Mux sub-stream, write to target connection
				if err != nil && err != io.EOF {
					log.Printf("Server: Data forwarding error from Mux stream to target %s: %v", targetDest.String(), err)
				}
				// Graceful shutdown: Notify the target connection that no more data will be written
				if closer, ok := targetConn.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				}
			}()

			// Goroutine 2: Read data from target connection and write to Mux sub-stream (target to client)
			go func() {
				defer wg.Done()
				_, err := io.Copy(stream, targetConn) // Read from target connection, write to Mux sub-stream
				if err != nil && err != io.EOF {
					log.Printf("Server: Data forwarding error from target %s to Mux stream: %v", targetDest.String(), err)
				}
				// Graceful shutdown: Notify the Mux sub-stream that no more data will be written
				if closer, ok := stream.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				}
			}()

			wg.Wait() // Wait for both forwarding goroutines to complete
			log.Printf("Server: Mux sub-stream for %s closed.", targetDest.String())

		} else {
			log.Printf("Server: Invalid target destination received from Mux sub-stream.")
			// If the target address is invalid, send an error frame and close the sub-stream
			errFrame := NewErrFrame([]byte("Invalid target destination"))
			if _, writeErr := protocol.WriteFrame(stream, errFrame); writeErr != nil {
				log.Printf("Server: Failed to send ERR_FRAME for invalid target: %v", writeErr)
			}
			stream.Close() // Close the Mux sub-stream
		}
	}

	serverCfg := &server.ServerConfig{
		ListenAddr:  serverConf.ListenAddr,
		Handler:     serverHandler, // Use the handler defined above
		VyperConfig: serverConf,
	}

	log.Printf("Starting Vyper server...")
	if err := server.StartServer(serverCfg); err != nil {
		log.Fatalf("Vyper server failed to start: %v", err)
	}
}

