package server

import (
	"bufio" // Used for reading HTTP requests
	"bytes" // Used for building HTTP responses
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http" // Used for full HTTP request and response handling
	"net/url" // Used for URL parsing
	"time"

	"github.com/UltraTLS/UltraTLS/protocol" // Assuming the protocol package is here
	"github.com/UltraTLS/UltraTLS/config"
	"github.com/v2fly/v2ray-core/v5/common/net" // Assuming this package is available
)

// ServerConfig configuration for starting the server
type ServerConfig struct {
	ListenAddr  string
	Handler     func(stream protocol.Stream) // Mux.Cool layer handler function
	VyperConfig *config.ServerConfig // Contains Vyper protocol specific configuration
}

// StartServer starts the Vyper server
func StartServer(cfg *ServerConfig) error {
	// Load TLS configuration
	tlsCert, err := tls.LoadX509KeyPair(cfg.VyperConfig.TLSCertPath, cfg.VyperConfig.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("Failed to load TLS certificate or key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, // Recommended minimum TLS 1.2
	}

	if cfg.VyperConfig.TLSClientAuth {
		clientCACertPool, err := protocol.LoadCACertPool(cfg.VyperConfig.TLSClientCaCertPath)
		if err != nil {
			return fmt.Errorf("Failed to load client CA certificate pool: %w", err)
		}
		tlsConfig.ClientCAs = clientCACertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	listener, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("Server TLS listening failed: %w", err)
	}
	defer listener.Close()

	log.Printf("Vyper server is listening on %s", cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Server accept connection error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go func(rawConn net.Conn) {
			defer rawConn.Close()

			log.Printf("Received new connection from %s", rawConn.RemoteAddr())

			// --- Vyper Protocol Authentication Phase ---
			initFrame, err := protocol.ReadVyperInitializationFrame(rawConn)
			if err != nil {
				log.Printf("Failed to read Vyper Initialization Frame (%s): %v", rawConn.RemoteAddr(), err)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// Validate AuthBlob
			if string(initFrame.AuthBlob) != cfg.VyperConfig.AuthToken {
				log.Printf("AuthBlob validation failed (%s): AuthBlob mismatch", rawConn.RemoteAddr())
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// Calculate and validate SessionToken
			currentTimeSeconds := time.Now().Unix()
			sessionTokenData := make([]byte, 8)
			binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
			sessionTokenData = append(sessionTokenData, []byte(cfg.VyperConfig.AuthToken)...)

			hasher := sha256.New()
			hasher.Write(sessionTokenData)
			sessionTokenHash := hasher.Sum(nil)
			expectedSessionToken := sessionTokenHash[:4]

			// Parse pseudo-HTTP request from ClientInfo, and extract SessionToken
			// Assume ClientInfo contains a complete HTTP request line, and the path is "/SessionToken/<Base64EncodedSessionToken>"
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(initFrame.ClientInfo))))
			if err != nil {
				log.Printf("Failed to parse pseudo-HTTP request in Vyper Initialization Frame (%s): %v", rawConn.RemoteAddr(), err)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			if req.Method != "GET" {
				log.Printf("Pseudo-HTTP request method is not GET (%s): %s", rawConn.RemoteAddr(), req.Method)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// Parse request path, extract SessionToken
			if !bytes.HasPrefix([]byte(req.URL.Path), []byte("/SessionToken/")) {
				log.Printf("Pseudo-HTTP request path format is incorrect (%s): %s", rawConn.RemoteAddr(), req.URL.Path)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			base64EncodedToken := req.URL.Path[len("/SessionToken/"):]
			decodedToken, decodeErr := protocol.Base64Decode(base64EncodedToken)
			if decodeErr != nil {
				log.Printf("SessionToken Base64 decoding failed (%s): %v", rawConn.RemoteAddr(), decodeErr)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}
			clientSessionToken := string(decodedToken)

			if clientSessionToken != string(expectedSessionToken) {
				log.Printf("SessionToken validation failed (%s): Client %x, Expected %x", rawConn.RemoteAddr(), clientSessionToken, expectedSessionToken)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			log.Printf("Vyper client %s authenticated successfully", rawConn.RemoteAddr())

			// --- IMPORTANT: Removed immediate PAD_FRAME response as per Vyper Protocol Spec Section 4.2 ---
			// The server MUST NOT send any immediate response frame after the Initialization Frame.
			// Padding frames will be handled by the vyperConn and Mux.Cool layers during data transfer.

			// After successful authentication, establish mux session
			// The server-side padding rule is determined by the client's InitialPaddingRule
			// and the server's configured PaddingPatterns.
			// The newVyperConn function (assumed to be in protocol package) handles this.
			vyperConn := protocol.NewVyperConn(rawConn, byte(initFrame.InitialPaddingRule), cfg.VyperConfig.PaddingPatterns)
			
			session := protocol.NewSession(vyperConn) // Use the vyperConn for the Mux session
			defer session.Close()

			// Continuously accept sub-streams
			for {
				stream, _, err := session.AcceptStream()
				if err != nil {
					log.Printf("Server accept Mux sub-stream error (%s): %v", rawConn.RemoteAddr(), err)
					break
				}
				log.Printf("Server accepted new Mux sub-stream (%s)", rawConn.RemoteAddr())
				go cfg.Handler(stream) // Delegate handling of the Mux sub-stream to the provided handler
			}
		}(conn)
	}
}

// handleFallback handles HTTP Fallback after authentication failure.
// It forwards the client's request to fallbackAddr and writes the response back to the client.
func handleFallback(conn net.Conn, fallbackAddr string) {
	log.Printf("Triggering Fallback to %s", fallbackAddr)

	// Use bufio.Reader to read from the connection so http.ReadRequest can parse correctly
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read Fallback HTTP request (%s): %v", conn.RemoteAddr(), err)
		// Try to send an error response, then close the connection
		sendHTTPError(conn, http.StatusBadRequest, "Invalid HTTP Request")
		return
	}

	// Parse fallbackAddress
	fallbackURL, err := url.Parse(fallbackAddr)
	if err != nil {
		log.Printf("Failed to parse Fallback URL (%s): %v", conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusInternalServerError, "Server Fallback Misconfiguration")
		return
	}

	// Adjust the request for forwarding to fallbackAddr
	req.RequestURI = "" // This field must be cleared, otherwise http.Client.Do will error
	req.URL.Host = fallbackURL.Host
	req.URL.Scheme = fallbackURL.Scheme
	req.URL.Opaque = fallbackURL.Opaque // Preserve opaque path

	// Use http.Client to send the request
	client := &http.Client{
		// Configure client to follow redirects, handle TLS, etc.
		// Timeout can be set
		Timeout: 10 * time.Second, // Timeout for fallback request
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to forward Fallback request to %s (%s): %v", fallbackAddr, conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusBadGateway, "Fallback Target Unreachable")
		return
	}
	defer resp.Body.Close()

	// Write the response back to the original connection
	err = resp.Write(conn)
	if err != nil {
		log.Printf("Failed to write Fallback response to client (%s): %v", conn.RemoteAddr(), err)
		// Connection may break here, no need to send more errors
	}

	log.Printf("Fallback request processed, closing connection %s", conn.RemoteAddr())
}

// sendHTTPError sends a simple HTTP error response to the connection
func sendHTTPError(w io.Writer, statusCode int, message string) {
	resp := &http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(message + "\n")),
	}
	resp.Header.Set("Connection", "close")
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(message)+1))

	err := resp.Write(w)
	if err != nil {
		log.Printf("Failed to send HTTP error response: %v", err)
	}
}

