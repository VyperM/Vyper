package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
	// crypto/x509 and os are not needed here as they are imported and used in frame.go within the same package
	// and this file will depend on common functions and types defined in frame.go and mux.go.
)

// =============================================================================
// Vyper Protocol Connection Encapsulation (vyperConn) and its padding logic.
// These structures and functions are defined in this file and duplicated in inbound.go,
// to ensure each file can compile independently and contain complete Vyper protocol logic
// without creating new generic files.
// =============================================================================

// vyperConn encapsulates the underlying net.Conn and handles Vyper protocol frame reading/writing and padding logic.
// It implements the net.Conn interface, allowing higher-level applications to use it directly without
// needing to know the details of the Vyper protocol.
type vyperConn struct {
	net.Conn // Embeds the underlying connection, implementing most net.Conn interface methods

	reader *bufio.Reader // Buffered reader for efficient reading from the underlying connection

	// Write-related
	writeBuffer  *bytes.Buffer // Used to build outbound Vyper frames
	writeMutex   sync.Mutex    // Protects write operations, ensuring concurrency safety
	paddingState *paddingState // Padding state, used to manage obfuscation padding for outbound traffic

	// Read-related
	readBuffer *bytes.Buffer // Used to store encapsulated Vyper DATA_FRAME content, provided for higher-level reading
	readMutex  sync.Mutex    // Protects read operations, ensuring concurrency safety
}

// paddingState struct manages the padding state for the current connection.
// It contains all parameters required for dynamic burst negotiation and random interleaving.
type paddingState struct {
	allPatterns        [][][]int // Fix: Changed to [][][]int, as each pattern is a sequence of (min, max) tuples
	currentPatternIndex int       // Index of the currently selected padding pattern
	currentStepInPattern int       // Index of the next PAD_FRAME step in the current pattern
	lastPaddingTime    time.Time // Time of the last padding frame sent, can be used for future time-based padding intervals
}

// newPaddingState initializes the padding state.
// initialRule: The initial padding rule negotiated in the Vyper Initialization Frame.
// allPatterns: All "Padding Burst Patterns" configured by the client or server.
func newPaddingState(initialRule byte, allPatterns [][][]int) *paddingState { // Fix: allPatterns type
	ps := &paddingState{
		allPatterns:     allPatterns,
		lastPaddingTime: time.Now(),
	}

	// Select or determine the current padding pattern based on InitialPaddingRule.
	if initialRule >= 0x01 && int(initialRule-1) < len(allPatterns) {
		// 0x01 to 0xFE: Client specifies a concrete pattern index.
		ps.currentPatternIndex = int(initialRule - 1)
	} else if initialRule == 0xFF && len(allPatterns) > 0 {
		// 0xFF: Client requests the server to dictate. In this implementation, we default to the first pattern.
		ps.currentPatternIndex = 0
	} else {
		// 0x00 (no active padding) or invalid index: Indicates no active padding.
		ps.currentPatternIndex = -1
	}
	return ps
}

// generatePaddingFrame generates a PAD_FRAME based on the current padding state.
// Returns nil if a padding frame should not be generated at this time.
// Detailed padding logic:
// 1. **Check if active padding is enabled:** If `currentPatternIndex` is -1 or `allPatterns` is empty,
//    it means no active padding, return `nil` directly.
// 2. **Select current padding pattern:** Select the currently used "Padding Burst Pattern" from `allPatterns`
//    based on `currentPatternIndex`.
// 3. **Handle empty pattern:** If the selected pattern is empty, also return `nil`.
// 4. **Loop pattern steps:** `currentStepInPattern` tracks progress within the current pattern.
//    If the end of the pattern is reached, it resets to 0, implementing continuous padding.
// 5. **Determine padding length range:** Get the `(minimum_length, maximum_length)` range from the current pattern step.
// 6. **Generate random padding length:** Generate a random integer within the `[minLen, maxLen]` range
//    as the content length of the `PAD_FRAME`.
// 7. **Generate random padding data:** Create a byte slice of the specified length and fill it with random data
//    to increase unpredictability.
// 8. **Update state:** Increment `currentStepInPattern` and update `lastPaddingTime`.
// 9. **Create PAD_FRAME:** Call `NewPadFrame` to create and return a `PAD_FRAME` of type `VyperSessionFrame`.
func (ps *paddingState) generatePaddingFrame() *VyperSessionFrame {
	if ps.currentPatternIndex == -1 || len(ps.allPatterns) == 0 {
		return nil // No active padding mode or no patterns configured
	}

	selectedPattern := ps.allPatterns[ps.currentPatternIndex] // selectedPattern is now [][]int
	if len(selectedPattern) == 0 {
		return nil // Selected pattern is empty
	}

	// Loop through the steps in the pattern, implementing continuous padding behavior "lacking a stop counter"
	if ps.currentStepInPattern >= len(selectedPattern) {
		ps.currentStepInPattern = 0
	}

	minLen := selectedPattern[ps.currentStepInPattern][0] // Fix: selectedPattern[step] is now []int, can index [0]
	maxLen := selectedPattern[ps.currentStepInPattern][1] // Fix: selectedPattern[step] is now []int, can index [1]

	// Ensure minLen is not greater than maxLen to prevent rand.Intn errors, improving robustness
	if minLen > maxLen {
		minLen = maxLen // Correct unreasonable configuration, making it at least equal to maxLen
	}

	// Generate random length padding data, implementing length unpredictability
	paddingLen := rand.Intn(maxLen-minLen+1) + minLen
	padData := make([]byte, paddingLen)
	rand.Read(padData) // Fill with random data for further obfuscation

	ps.currentStepInPattern++
	ps.lastPaddingTime = time.Now() // Record last padding time
	return NewPadFrame(padData)
}

// NewVyperConn creates a new vyperConn instance.
// rawConn is the underlying established TCP/TLS connection.
// initialRule is the initial padding rule of the Vyper protocol.
// allPatterns are all available padding patterns.
func NewVyperConn(rawConn net.Conn, initialRule byte, allPatterns [][][]int) *vyperConn { // Fix: Exported function name, allPatterns type
	vc := &vyperConn{
		Conn:         rawConn,
		reader:       bufio.NewReader(rawConn),
		writeBuffer:  new(bytes.Buffer), // Fix: vyperConn struct now includes this field
		readBuffer:   new(bytes.Buffer),
		paddingState: newPaddingState(initialRule, allPatterns),
	}
	return vc
}

// Read reads data from the Vyper connection. It parses Vyper frames, skips padding frames, and returns the content of DATA_FRAME.
// This method blocks until data is available or an error occurs.
// Detailed read logic:
// 1. **Prioritize reading from internal buffer:** First, check if `readBuffer` has already encapsulated `DATA_FRAME` content.
//    If yes, read directly from it and return, avoiding unnecessary underlying reads.
// 2. **Loop reading Vyper frames:** If `readBuffer` is empty, enter a loop to read a complete Vyper session frame from the underlying `net.Conn`.
// 3. **Error handling:** If reading the underlying frame fails, check if it's `io.EOF` (indicating connection closure), otherwise return a detailed error.
// 4. **Frame type handling:**
//    - `DATA_FRAME (0x02)`: Actual application data frame received. Its `Content` is written to `readBuffer`, then read from `readBuffer` into the incoming `b`. This is the core data transfer of the Vyper protocol.
//    - `PAD_FRAME (0x06)`: Obfuscation padding frame received. Its `Content` is completely discarded, then continue looping to read the next frame. This implements the obfuscation feature of the Vyper protocol, where the receiver does not process padding data.
//    - `CLOSE_FRAME (0x04)`: Close signal frame received. Indicates the peer has closed its write half. Return `io.EOF` to signal the higher-level application that the stream has ended.
//    - `ERR_FRAME (0x05)`: Error frame received. Indicates an unrecoverable error at the protocol layer. Return an `error` containing the error message.
//    - `REQ_FRAME (0x01)` / `FLOW_FRAME (0x03)` and other unknown frames: According to the Vyper protocol stack design, `REQ_FRAME` and `FLOW_FRAME` are typically handled by the Mux.Cool layer. If these frames are received at the `vyperConn` layer (i.e., the Vyper protocol layer), it indicates a possible anomaly or misuse of the protocol stack, so an error is returned.
func (vc *vyperConn) Read(b []byte) (n int, err error) {
	vc.readMutex.Lock()
	defer vc.readMutex.Unlock()

	// If internal read buffer has data, prioritize reading from it
	if vc.readBuffer.Len() > 0 {
		return vc.readBuffer.Read(b)
	}

	// Otherwise, read Vyper frames from the underlying connection and process
	for {
		frame, err := ReadVyperSessionFrame(vc.reader) // Call generic function
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF // Underlying connection closed
			}
			return 0, fmt.Errorf("Failed to read Vyper session frame: %w", err)
		}

		switch frame.FrameType {
		case 0x02: // DATA_FRAME
			// Received data frame, write its content to the internal buffer
			vc.readBuffer.Write(frame.Content)
			// Then read from the buffer into the incoming b
			return vc.readBuffer.Read(b)
		case 0x06: // PAD_FRAME
			// Received padding frame, discard content directly, continue reading the next frame
			continue
		case 0x04: // CLOSE_FRAME
			// Received close frame, indicating the peer has closed its write half
			return 0, io.EOF // Return EOF to signal end of stream
		case 0x05: // ERR_FRAME
			// Received error frame
			return 0, fmt.Errorf("Vyper protocol error frame: %s", string(frame.Content))
		case 0x01: // REQ_FRAME (This frame should be handled by Mux.Cool, should not appear in VyperConn's Read)
			return 0, fmt.Errorf("Vyper protocol anomaly: REQ_FRAME received in data stream (should be handled by Mux.Cool)")
		case 0x03: // FLOW_FRAME (This frame should be handled by Mux.Cool, should not appear in VyperConn's Read)
			return 0, fmt.Errorf("Vyper protocol anomaly: FLOW_FRAME received in data stream (should be handled by Mux.Cool)")
		default:
			return 0, fmt.Errorf("Vyper protocol anomaly: Unknown frame type %x", frame.FrameType)
		}
	}
}

// Write writes data to the Vyper connection. It encapsulates the data into a DATA_FRAME, and injects PAD_FRAME
// according to the padding strategy.
// This method blocks until data is written or an error occurs.
// Detailed write logic:
// 1. **Write DATA_FRAME:** Encapsulate the incoming raw data `b` into a `DATA_FRAME`. This frame has `FrameType` 0x02,
//    `Sequence` simplified to 0 (should maintain an incrementing sequence number in actual application), and `Content` as raw data.
//    Then write this `DATA_FRAME` to the underlying connection.
// 2. **Inject PAD_FRAME (random interleaving):**
//    - Immediately after writing a `DATA_FRAME`, call `vc.paddingState.generatePaddingFrame()` to attempt to generate a `PAD_FRAME`.
//    - If `generatePaddingFrame()` returns a valid `PAD_FRAME` (indicating that the current padding mode requires sending padding),
//      then write this `PAD_FRAME` to the underlying connection.
//    - This behavior of randomly interspersing padding frames after actual data frames implements the "random interleaving"
//      feature described in Section 6.2 of the Vyper protocol specification.
//    - Since `generatePaddingFrame`'s internal logic loops through padding patterns and lacks a "stop" counter, this also
//      implements Section 6.3's "lack of stop counter" feature, ensuring padding remains active throughout the connection's lifetime.
//    - Failure to write a padding frame is usually treated as a non-fatal error, only logged, and does not interrupt the main data flow
//      to maintain protocol resilience.
// 3. **Return write length:** Finally, return the length of the successfully written raw data `b`.
func (vc *vyperConn) Write(b []byte) (n int, err error) {
	vc.writeMutex.Lock()
	defer vc.writeMutex.Unlock()

	// 1. Write DATA_FRAME
	dataFrame := &VyperSessionFrame{ // Use generic structure
		FrameType: 0x02, // DATA_FRAME
		Sequence:  0,    // Simplified: actual application should maintain an incrementing sequence number
		Content:   b,
	}
	if _, err := WriteFrame(vc.Conn, dataFrame); err != nil { // Call generic function
		return 0, fmt.Errorf("Failed to write DATA_FRAME: %w", err)
	}

	// 2. Inject PAD_FRAME (random interleaving)
	// According to the protocol, PAD_FRAME can be randomly interleaved. Here, we choose to attempt to inject one after each DATA_FRAME write.
	// This implements "random interleaving" and "lack of stop counter" features.
	if padFrame := vc.paddingState.generatePaddingFrame(); padFrame != nil {
		if _, err := WriteFrame(vc.Conn, padFrame); err != nil { // Call generic function
			// Padding frame write failures are usually not fatal errors, log and continue
			log.Printf("VyperConn: Failed to write PAD_FRAME: %v", err)
		}
	}

	return len(b), nil
}

// Close closes the Vyper connection. It sends a CLOSE_FRAME, then closes the underlying connection.
func (vc *vyperConn) Close() error {
	vc.writeMutex.Lock()
	defer vc.writeMutex.Unlock()

	closeFrame := &VyperSessionFrame{FrameType: 0x04, Sequence: 0, Content: []byte{}} // Use generic structure
	if _, err := WriteFrame(vc.Conn, closeFrame); err != nil { // Call generic function
		log.Printf("VyperConn: Failed to send CLOSE_FRAME: %v", err)
		// Even if sending fails, try to close the underlying connection
	}
	return vc.Conn.Close()
}

// LocalAddr returns the local network address of the underlying connection.
func (vc *vyperConn) LocalAddr() net.Addr {
	return vc.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address of the underlying connection.
func (vc *vyperConn) RemoteAddr() net.Addr {
	return vc.Conn.RemoteAddr()
}

// SetDeadline sets the read and write deadline for the underlying connection.
func (vc *vyperConn) SetDeadline(t time.Time) error {
	return vc.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline for the underlying connection.
func (vc *vyperConn) SetReadDeadline(t time.Time) error {
	return vc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the underlying connection.
func (vc *vyperConn) SetWriteDeadline(t time.Time) error {
	return vc.Conn.SetWriteDeadline(t)
}


// =============================================================================
// Outbound Interface and TCPOutbound Implementation
// =============================================================================

// Outbound abstract exit, all outbound traffic connects through this interface.
type Outbound interface {
	Connect(network, address string) (net.Conn, error)
	Close() error
}

// TCPOutbound implements the Outbound interface for establishing TCP connections.
// It can be configured for plain TCP connections or TLS connections.
type TCPOutbound struct {
	timeout            time.Duration // Connection timeout
	tlsConfig          *tls.Config   // Optional TLS configuration, if nil, plain TCP connection
	authToken          string        // Vyper protocol AuthToken, used for authentication
	initialPaddingRule byte          // Client initial padding rule
	clientInfo         string        // Client information string, used for disguising HTTP User-Agent
	paddingPatterns    [][][]int     // Fix: Changed to [][][]int
	mu                 sync.Mutex    // Mutex, used to protect the closed field
	closed             bool          // Flag indicating if Outbound is closed
}

// NewTCPOutbound creates a new TCPOutbound instance for plain TCP connections.
// The timeout parameter specifies the connection establishment timeout.
func NewTCPOutbound(timeout time.Duration) *TCPOutbound {
	return &TCPOutbound{timeout: timeout}
}

// NewTLSOutbound creates a new TCPOutbound instance for TLS connections and handles Vyper protocol handshake.
// The timeout parameter specifies the connection establishment timeout.
// The tlsConfig parameter contains client TLS configuration, such as server name, CA certificate, etc.
// authToken is the Vyper protocol authentication token.
// initialPaddingRule is the initial padding rule the client wishes to use.
// clientInfo is the client information string, used for disguising HTTP User-Agent.
// paddingPatterns is the list of padding patterns defined by the client.
func NewTLSOutbound(timeout time.Duration, tlsConfig *tls.Config, authToken string, initialPaddingRule byte, clientInfo string, paddingPatterns [][][]int) *TCPOutbound { // Fix: paddingPatterns type
	return &TCPOutbound{
		timeout:            timeout,
		tlsConfig:          tlsConfig,
		authToken:          authToken,
		initialPaddingRule: initialPaddingRule,
		clientInfo:         clientInfo,
		paddingPatterns:    paddingPatterns,
	}
}

// Connect attempts to establish a connection and performs the Vyper protocol client handshake and authentication.
// The network parameter is typically "tcp", and the address parameter is the target address and port (e.g., "example.com:443").
// Returns an error if the Outbound instance is closed.
// Upon successful authentication, returns a net.Conn (vyperConn instance) that has completed the Vyper handshake.
// On failure, closes the connection and returns an error.
func (o *TCPOutbound) Connect(network, address string) (net.Conn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, errors.New("outbound closed")
	}

	var rawConn net.Conn
	var err error

	if o.tlsConfig != nil {
		dialer := &net.Dialer{Timeout: o.timeout}
		rawConn, err = tls.DialWithDialer(dialer, network, address, o.tlsConfig)
	} else {
		rawConn, err = net.DialTimeout(network, address, o.timeout)
	}

	if err != nil {
		return nil, fmt.Errorf("Connection failed: %w", err)
	}
	log.Printf("Outbound: Connected to %s", address)

	// --- Vyper Protocol Authentication Phase ---
	// 1. Construct AuthBlob
	authBlob := []byte(o.authToken)

	// 2. Construct pseudo-HTTP request for SessionToken
	currentTimeSeconds := time.Now().Unix()
	sessionTokenData := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
	sessionTokenData = append(sessionTokenData, []byte(o.authToken)...)

	hasher := sha256.New()
	hasher.Write(sessionTokenData)
	sessionTokenHash := hasher.Sum(nil)
	calculatedSessionToken := sessionTokenHash[:4]

	base64EncodedSessionToken := base64.StdEncoding.EncodeToString(calculatedSessionToken)

	httpReqPath := fmt.Sprintf("/SessionToken/%s", base64EncodedSessionToken)
	httpReqBody := new(bytes.Buffer)
	httpReq, _ := http.NewRequest("GET", httpReqPath, nil)
	if o.tlsConfig != nil && o.tlsConfig.ServerName != "" {
		httpReq.Host = o.tlsConfig.ServerName
	} else {
		host, _, _ := net.SplitHostPort(address)
		httpReq.Host = host
	}
	httpReq.Header.Set("User-Agent", o.clientInfo)
	httpReq.Header.Set("Connection", "keep-alive")
	_ = httpReq.Write(httpReqBody)

	clientInfo := httpReqBody.String()

	// 3. Construct Vyper Initialization Frame
	initFrame := &VyperInitializationFrame{ // Use generic structure
		AuthBlob:           authBlob,
		InitialPaddingRule: o.initialPaddingRule,
		Reserved:           []byte{0x00, 0x00, 0x00},
		ClientInfo:         clientInfo,
	}

	// 4. Write Vyper Initialization Frame
	if _, err := WriteVyperInitializationFrame(rawConn, initFrame); err != nil { // Call generic function
		rawConn.Close()
		return nil, fmt.Errorf("Failed to write Vyper Initialization Frame: %w", err)
	}
	log.Printf("Outbound: Vyper Initialization Frame sent")

	// 5. Read server's authentication response (PAD_FRAME)
	responseFrame, err := ReadVyperSessionFrame(rawConn) // Call generic function
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("Failed to read server authentication response frame: %w", err)
	}

	if responseFrame.FrameType != 0x06 {
		rawConn.Close()
		return nil, fmt.Errorf("Server authentication response frame type is incorrect: Expected 0x06 (PAD_FRAME), Actual %x", responseFrame.FrameType)
	}
	if len(responseFrame.Content) < 900 || len(responseFrame.Content) > 1400 {
		rawConn.Close()
		return nil, fmt.Errorf("Server authentication response padding frame length does not meet requirements: Actual %d, Expected 900-1400", len(responseFrame.Content))
	}
	log.Printf("Outbound: Vyper server authenticated successfully, received padding frame, length %d", len(responseFrame.Content))

	// Handshake successful, return a net.Conn encapsulated with Vyper protocol logic
	return NewVyperConn(rawConn, o.initialPaddingRule, o.paddingPatterns), nil // Call generic function
}

// Close closes the outbound, preventing new connections.
func (o *TCPOutbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	return nil
}
