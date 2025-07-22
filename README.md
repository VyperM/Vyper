# The Vyper Protocol

The Vyper Protocol is a streamlined, TCP-based proxy protocol designed for secure and obfuscated data tunneling over TLS. It aims to provide a minimalist yet effective solution for bypassing network restrictions by mimicking standard TLS traffic. Vyper focuses on a novel, dynamic padding scheme and delegates built-in multiplexing or heartbeating functionalities to higher-layer protocols or underlying network mechanisms.

This repository contains a Go implementation of the Vyper Protocol, including both client and server components.

## 1\. Introduction

The proliferation of network censorship and active probing mechanisms necessitates the development of flexible and robust tunneling protocols. Existing solutions often trade off simplicity for features, or become predictable in their traffic patterns, making them susceptible to detection and blocking. The Vyper Protocol aims to strike a balance, providing strong obfuscation capabilities without unnecessary complexity.

### 1.1. Protocol Goals

The primary goals of the Vyper Protocol are:

  * **Stealth:** Mimic standard TLS traffic to evade deep packet inspection (DPI) and active probing.
  * **Obfuscation:** Incorporate a dynamic and unpredictable padding scheme to further disguise traffic patterns.
  * **Efficiency:** Maintain a lean protocol overhead by focusing on core proxy functionality.
  * **Simplicity:** Minimize complexity by delegating functionalities like multiplexing (e.g., via Mux.Cool) and heartbeating to higher or lower layers.
  * **TCP-Centric:** Designed specifically for TCP proxying.

## 2\. Terminology

  * **Client:** The initiating endpoint of a Vyper connection, typically running on a user's device.
  * **Server:** The responding endpoint of a Vyper connection, typically running on a remote server.
  * **TLS:** Transport Layer Security, as defined in [RFC8446].
  * **OS Connection:** A single TCP connection over TLS running the Vyper Protocol, dedicated to proxying a single application stream.
  * **Auth Blob:** A client-generated, fixed-size random byte sequence used for connection authentication.
  * **Padding Burst Pattern:** A sequence of length ranges for `PAD_FRAME`s used for traffic obfuscation.

## 3\. Protocol Stack

The Vyper Protocol operates directly above the TLS layer. A typical protocol stack involving Vyper would be:

```
    Application Proxy (e.g., SOCKS5)
            |
      Vyper Protocol
            |
        TLS (RFC 8446)
            |
        TCP (RFC 9293)
            |
        IP (RFC 791)
```

Implementations MAY integrate higher-level multiplexing protocols (e.g., Mux.Cool) above the Vyper Protocol layer to enable multiple application streams over a single OS Connection. This implementation leverages Mux.Cool for multiplexing.

## 4\. Connection Establishment

### 4.1. TLS Handshake

The Vyper Client MUST first establish a standard TLS connection with the Vyper Server. All subsequent Vyper protocol data MUST be encapsulated within this secure TLS tunnel.

### 4.2. Vyper Initialization Frame

Immediately following a successful TLS handshake, the Vyper Client MUST send a single Vyper Initialization Frame to the Server. This frame combines authentication material with initial padding instructions.

The Vyper Initialization Frame has the following structure:

```
    0                               1                               2                               3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   AuthBlob Length             | AuthBlob (variable length)    ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------------------------+
   ...                                                               ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | InitialPaddingRule    |           Reserved (3 bytes)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ClientInfo Length           | ClientInfo (variable length) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------------------------+
   ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

  * **AuthBlob Length (2 bytes, Big-Endian uint16):** The length, in bytes, of the `AuthBlob` field.
  * **AuthBlob (variable length):** A client-generated, fixed-size random byte sequence. The Server MUST verify this `AuthBlob` against a pre-shared secret. If invalid, the Server SHOULD immediately close the connection or MAY implement an L7 fallback.
  * **InitialPaddingRule (1 byte, uint8):** Dictates the initial padding behavior for the Client's outbound frames.
      * `0x00`: No active padding initiated by the Client.
      * `0x01` to `0xFE`: An index to a specific "Padding Burst Pattern" known to both Client and Server.
      * `0xFF`: Client requests the Server to dictate the effective padding pattern.
  * **Reserved (3 bytes):** MUST be `0x000000` by the Client and ignored by the Server.
  * **ClientInfo Length (2 bytes, Big-Endian uint16):** The length, in bytes, of the `ClientInfo` field.
  * **ClientInfo (variable length):** An OPTIONAL UTF-8 encoded string providing details about the client software.

Upon receiving a valid Vyper Initialization Frame, the Server stores the `InitialPaddingRule` and `ClientInfo`. The Server then implicitly transitions to waiting for the first Vyper Session Frame (`REQ_FRAME`) from the Client. The Server MUST NOT send any immediate response frame to avoid creating predictable handshake patterns.

## 5\. Vyper Session Frames

After the Vyper Initialization Frame exchange, all subsequent communication within the Vyper connection MUST be carried in Vyper Session Frames.

### 5.1. Frame Structure

All Vyper Session Frames share a common header structure:

```
    0                               1                               2                               3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | FrameType     |                   Sequence (4 bytes)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Content Length              |       Content (variable)      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------------------------+
   ...
```

  * **FrameType (1 byte, uint8):** Identifies the type of the Vyper Session Frame.
  * **Sequence (4 bytes, Big-Endian uint32):** A monotonically increasing sequence number, unique for each Vyper Session Frame type that carries logical flow.
  * **Content Length (2 bytes, Big-Endian uint16):** The length, in bytes, of the `Content` field. Maximum `Content Length` is 65535 bytes.
  * **Content (variable length):** The payload of the frame, whose format and meaning depend on the `FrameType`.

### 5.2. Frame Types

#### 5.2.1. `REQ_FRAME` (0x01)

Initiates a TCP proxy request to a target address.

  * **Sender:** Client.
  * **Content:** Target address for proxying, formatted according to SOCKS5 ATYP.
  * **Server Action:** Attempts to connect to the target. If successful, implicitly transitions to data relay. If failed, sends an `ERR_FRAME` and closes the connection.

#### 5.2.2. `DATA_FRAME` (0x02)

Carries the actual proxied application data.

  * **Sender:** Client or Server.
  * **Content:** Raw bytes of the proxied data.
  * **Behavior:** Senders MAY fragment large data streams. Receivers MUST reassemble.

#### 5.2.3. `FLOW_FRAME` (0x03)

Provides a lightweight acknowledgment mechanism for `DATA_FRAME`s and assists in detecting connection stalls.

  * **Sender:** Client or Server.
  * **Content:** A 4-byte Big-Endian uint32 representing the `Sequence` number of the last `DATA_FRAME` successfully received from the *other* side.

#### 5.2.4. `CLOSE_FRAME` (0x04)

Signals the graceful closure of the data stream from one side.

  * **Sender:** Client or Server.
  * **Content:** Empty (`Content Length` MUST be 0).
  * **Behavior:** Sender transmits when its underlying connection closes. Receiver MUST close its write half.

#### 5.2.5. `ERR_FRAME` (0x05)

Sent by the Server to indicate an error that prevents successful proxy session continuation.

  * **Sender:** Server.
  * **Content:** A UTF-8 encoded string describing the error.
  * **Client Action:** Logs the error and immediately terminates the Vyper connection.

#### 5.2.6. `PAD_FRAME` (0x06)

Used exclusively for traffic obfuscation by adding arbitrary data.

  * **Sender:** Client or Server.
  * **Content:** Arbitrary random or predefined bytes.
  * **Behavior:** Receivers MUST read and silently discard the `Content`.

## 6\. Obfuscation Padding Scheme

Vyper employs a dynamic, per-connection padding scheme designed to disguise traffic volume and timing patterns, avoiding static or predictable padding behaviors.

### 6.1. Dynamic Burst Negotiation

The padding behavior is primarily controlled by the `InitialPaddingRule` in the Vyper Initialization Frame.

  * **Padding Burst Patterns:** Both Client and Server are configured out-of-band with a set of "Padding Burst Patterns." Each pattern is a sequence of `(minimum_length, maximum_length)` ranges for `PAD_FRAME`s.
  * **Client-Initiated Pattern:** If `InitialPaddingRule` is `0x01` to `0xFE`, the Client explicitly requests a specific pattern.
  * **Server-Dictated Pattern:** If `InitialPaddingRule` is `0xFF`, the Client requests the Server to dictate the padding behavior.
  * **No Active Padding (0x00):** The Client will not actively send `PAD_FRAME`s unless required by the underlying TLS layer.
  * **Adaptive Behavior:** Clients MAY try different `InitialPaddingRule` values for subsequent connections if previous ones fail.

### 6.2. Random Interleaving

`PAD_FRAME`s can be interspersed randomly with other Vyper Session Frames (e.g., immediately after `DATA_FRAME`s or `REQ_FRAME`s), as long as it does not disrupt the logical flow and ordering of other frames.

### 6.3. Lack of "Stop" Counter

Vyper's padding scheme does not employ a fixed "packet counter" or a "stop" mechanism. Padding, if enabled, remains active throughout the lifetime of the Vyper connection, adapting its frequency and size based on the chosen pattern.

## 7\. Connection Management

  * **Single Stream per Connection:** Each Vyper connection (over one TLS tunnel) is dedicated to proxying a single TCP application stream. Higher-layer protocols like Mux.Cool are intended to provide multiplexing.
  * **No Built-in Heartbeating:** Vyper intentionally omits a dedicated heartbeating mechanism. Underlying TCP Keepalives or higher-layer protocols (e.g., within Mux.Cool) are responsible for detecting and managing idle connections.
  * **Error Termination:** The Server can use the `ERR_FRAME` to signal unrecoverable errors and initiate connection termination. The Client MUST honor such termination requests.

## 8\. Security Considerations

  * **TLS Security:** Heavily relies on the underlying TLS implementation. Implementations MUST use up-to-date TLS versions and strong cryptographic suites.
  * **AuthBlob Secrecy:** Provides basic access control. The pre-shared secret MUST be kept confidential. Brute-forcing can be mitigated by server-side rate limiting.
  * **Padding Effectiveness:** Its effectiveness depends on chosen patterns blending with legitimate TLS traffic. Patterns SHOULD be randomized and varied.
  * **L7 Fallback:** If implemented, care must be taken to ensure the fallback itself does not reveal the presence of a proxy server.
  * **Resource Exhaustion:** Servers MUST implement measures to prevent resource exhaustion attacks.

## 9\. Project Structure

This Go project is structured as follows:

  * **`cmd/client/main.go`**: The main entry point for the Vyper client application. It sets up the local SOCKS5 proxy and initiates the Vyper connection to the server.
  * **`cmd/server/main.go`**: The main entry point for the Vyper server application. It listens for Vyper client connections and handles forwarding to target destinations.
  * **`client/`**: Contains the `client.go` file, which implements the core Vyper client-side logic, including the SOCKS5 local inbound proxy and the connection handling to the Vyper server. The `inbound.go` within this directory specifically handles the SOCKS5 protocol parsing.
  * **`server/`**: Contains the `server.go` file, which implements the core Vyper server-side logic, handling incoming Vyper connections and delegating stream processing to a handler.
  * **`protocol/`**: Defines the fundamental Vyper protocol structures, frame types, and helper functions (e.g., `VyperInitializationFrame`, `VyperSessionFrame`, `ReadVyperInitializationFrame`, `WriteFrame`, `NewVyperConn`, `NewSession`, `Stream` interface, `v2Stream` implementation). It also contains the `TCPOutbound` for the Vyper client's connection to the server.
  * **`config/`**: Contains `config.go`, defining the configuration structures for both client (`Config`) and server (`ServerConfig`), and functions to load these configurations from YAML files.

## 10\. Usage and Configuration

### 10.1. Configuration Files

Both the client and server require configuration files.

  * **Client Configuration (`config.yaml`)**:

    ```yaml
    server_ip: your_server_ip_or_domain
    server_port: 443
    auth_token: your_secret_auth_token # Base64 encoded
    buffer_size: 8192
    timeout: 10
    initialPaddingRule: 1 # Example: use the first padding pattern
    clientInfo: "VyperClient/1.0.0"
    paddingPatterns: # Client-side padding patterns
      - [50, 100]
      - [120, 200]
    tlsEnabled: true
    tlsServerName: your_server_domain # Must match server's certificate CN/SAN
    tlsInsecureSkipVerify: false # Set to true ONLY for testing with self-signed certs
    tlsCACertPath: "" # Path to CA cert if using custom CA
    tlsClientCertPath: "" # Path to client cert for mutual TLS
    tlsClientKeyPath: "" # Path to client key for mutual TLS
    proxyListenAddress: "127.0.0.1"
    proxyListenPort: 1080
    proxyProtocol: "socks5"
    ```

  * **Server Configuration (`server_config.yaml`)**:

    ```yaml
    listenAddr: "0.0.0.0:443"
    authToken: your_secret_auth_token # Base64 encoded, must match client
    tlsEnabled: true
    tlsCertPath: /path/to/server.crt
    tlsKeyPath: /path/to/server.key
    tlsClientAuth: false # Set to true if you require client certificates
    tlsClientCaCertPath: "" # Path to CA cert for client auth
    paddingPatterns: # Server-side padding patterns
      - [900, 1400] # Example: for initial PAD_FRAME response (though removed per spec)
      - [100, 200] # Other patterns for random interleaving
    fallbackAddress: "http://127.0.0.1:80" # Optional: HTTP fallback for failed auth
    ```

    **Note**: As per Vyper Protocol Specification Section 4.2, the server MUST NOT send an immediate response frame after the Initialization Frame. The `paddingPatterns` for the server are primarily used for generating `PAD_FRAME`s during the active data transfer phase, not as an initial handshake response.

### 10.2. Running the Applications

1.  **Build**:
    ```bash
    # Build client
    go build -o bin/client ./cmd/client/main.go
    # Build server
    go build -o bin/server ./cmd/server/main.go
    ```
2.  **Run Server**:
    Place `server_config.yaml`, `server.crt`, `server.key` in the same directory as the `bin/server` executable, or in a `config/` subdirectory.
    ```bash
    ./bin/server
    ```
3.  **Run Client**:
    Place `config.yaml` in the same directory as the `bin/client` executable, or in a `config/` subdirectory.
    ```bash
    ./bin/client
    ```
4.  **Configure Local Application**: Configure your browser or other applications to use a SOCKS5 proxy at `127.0.0.1:1080` (or whatever `proxyListenAddress:proxyListenPort` you configured).

## 11\. Automated Builds with GitHub Actions

This project includes a GitHub Workflow (`.github/workflows/release.yml`) that automates the build process for multiple platforms whenever a new Git tag (e.g., `v1.0.0`) is pushed.

The workflow will:

  * Compile `cmd/client/main.go` and `cmd/server/main.go` for Linux (AMD64, ARM64), Windows (AMD64), and macOS (AMD64, ARM64).
  * Attach the compiled binaries as assets to a new GitHub Release.

To trigger a build, simply push a new tag:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

## References

  * [RFC1928](https://www.rfc-editor.org/info/rfc1928) IETF. "SOCKS Protocol Version 5", RFC 1928, March 1996.
  * [RFC2119](https://www.rfc-editor.org/info/rfc2119) Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
  * [RFC8174](https://www.rfc-editor.org/info/rfc8174) Leiba, B., "Ambiguity of OMITTED-TEXT-STYLE-KEYWORD", BCP 14, RFC 8174, May 2017.
  * [RFC8446](https://www.rfc-editor.org/info/rfc8446) Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018.
  * [RFC9293](https://www.rfc-editor.org/info/rfc9293) Eddy, K., Ed., "Transmission Control Protocol (TCP)", STD 7, RFC 9293, August 2022.
  * [Mux.Cool SPEC](https://www.v2fly.org/developer/protocols/muxcool.html) KSLR, "Mux.Cool Protocol"

-----

**License:** This project is licensed under the Revised BSD License.
