package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"io"
	"time"
	// crypto/x509 和 os 不需要在此处导入，因为 LoadCACertPool 已被移除到通用部分
	// 并且其内部逻辑已由外部文件提供。
)

// =============================================================================
// Inbound 接口和 TCPInbound 实现
// 此文件依赖于 protocol 包中其他文件（例如 frame.go, mux.go）定义的通用结构和辅助函数。
// =============================================================================

// Inbound 抽象入口，所有入站流量都通过这个接口进行监听和接受。
type Inbound interface {
	Listen() error
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// TCPInbound 实现了 Inbound 接口，用于监听和接受 TCP 连接。
// 它可以配置为进行普通的 TCP 监听，也可以进行 TLS 监听。
type TCPInbound struct {
	addr            string          // 监听地址
	listener        net.Listener    // 底层监听器
	tlsConfig       *tls.Config     // 可选的 TLS 配置，如果为 nil 则进行普通 TCP 监听
	authToken       string          // Vyper 协议的 AuthToken，用于认证
	fallbackAddress string          // 认证失败时的 L7 回退地址
	paddingPatterns [][]int         // 服务器定义的填充模式列表
	mu              sync.Mutex      // 互斥锁，用于保护 closed 字段和 listener
	closed          bool            // 标记 Inbound 是否已关闭
}

// NewTCPInbound 创建一个新的 TCPInbound 实例，用于普通 TCP 监听。
// addr 参数指定了监听的网络地址（例如 "0.0.0.0:8080"）。
func NewTCPInbound(addr string) *TCPInbound {
	return &TCPInbound{addr: addr}
}

// NewTLSInbound 创建一个新的 TCPInbound 实例，用于 TLS 监听并处理 Vyper 协议握手。
// addr 参数指定了监听的网络地址。
// tlsConfig 参数包含了服务器的 TLS 证书、私钥等配置。
// authToken 是 Vyper 协议的认证令牌。
// fallbackAddress 是认证失败时的 HTTP 回退地址。
// paddingPatterns 是服务器定义的填充模式列表。
func NewTLSInbound(addr string, tlsConfig *tls.Config, authToken, fallbackAddress string, paddingPatterns [][]int) *TCPInbound {
	return &TCPInbound{
		addr:            addr,
		tlsConfig:       tlsConfig,
		authToken:       authToken,
		fallbackAddress: fallbackAddress,
		paddingPatterns: paddingPatterns,
	}
}

// Listen 开始监听 TCP 连接。
// 如果 Inbound 实例已经关闭，则返回错误。
// 如果配置了 tlsConfig，则进行 TLS 监听；否则进行普通 TCP 监听。
func (i *TCPInbound) Listen() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return errors.New("inbound closed")
	}

	var ln net.Listener
	var err error

	if i.tlsConfig != nil {
		ln, err = tls.Listen("tcp", i.addr, i.tlsConfig)
	} else {
		ln, err = net.Listen("tcp", i.addr)
	}

	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	i.listener = ln
	return nil
}

// Accept 接受一个传入的连接，并执行 Vyper 协议的服务器端握手和认证。
// 如果监听器尚未初始化，则返回错误。
// 成功认证后，返回一个已完成 Vyper 握手的 net.Conn (vyperConn 实例)。
// 失败时，会根据配置尝试回退或直接关闭连接。
func (i *TCPInbound) Accept() (net.Conn, error) {
	if i.listener == nil {
		return nil, errors.New("inbound not listening")
	}

	rawConn, err := i.listener.Accept()
	if err != nil {
		return nil, err
	}

	log.Printf("Inbound: 接收到来自 %s 的新连接", rawConn.RemoteAddr())

	// --- Vyper 协议认证阶段 ---
	// 1. 读取客户端发送的 Vyper Initialization Frame
	initFrame, err := ReadVyperInitializationFrame(rawConn) // 使用通用函数
	if err != nil {
		log.Printf("Inbound: 读取 Vyper 初始化帧失败 (%s): %v", rawConn.RemoteAddr(), err)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: %w", err)
	}

	// 2. 验证 AuthBlob
	if string(initFrame.AuthBlob) != i.authToken {
		log.Printf("Inbound: AuthBlob 验证失败 (%s): AuthBlob不匹配", rawConn.RemoteAddr())
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: AuthBlob 不匹配")
	}

	// 3. 计算并验证 SessionToken
	currentTimeSeconds := time.Now().Unix()
	sessionTokenData := make([]byte, 8)
	binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
	sessionTokenData = append(sessionTokenData, []byte(i.authToken)...)

	hasher := sha256.New()
	hasher.Write(sessionTokenData)
	sessionTokenHash := hasher.Sum(nil)
	expectedSessionToken := sessionTokenHash[:4]

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(initFrame.ClientInfo))))
	if err != nil {
		log.Printf("Inbound: 解析 Vyper Initialization Frame 中的伪 HTTP 请求失败 (%s): %v", rawConn.RemoteAddr(), err)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: 无法解析伪 HTTP 请求: %w", err)
	}

	if req.Method != "GET" {
		log.Printf("Inbound: 伪 HTTP 请求方法不是 GET (%s): %s", rawConn.RemoteAddr(), req.Method)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: 伪 HTTP 请求方法不正确")
	}

	if !bytes.HasPrefix([]byte(req.URL.Path), []byte("/SessionToken/")) {
		log.Printf("Inbound: 伪 HTTP 请求路径格式不正确 (%s): %s", rawConn.RemoteAddr(), req.URL.Path)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: 伪 HTTP 请求路径格式不正确")
	}

	base64EncodedToken := req.URL.Path[len("/SessionToken/"):]
	decodedToken, decodeErr := Base64Decode(base64EncodedToken) // 使用通用函数
	if decodeErr != nil {
		log.Printf("Inbound: SessionToken Base64解码失败 (%s): %v", rawConn.RemoteAddr(), decodeErr)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, fmt.Errorf("Vyper 握手失败: SessionToken 解码失败: %w", decodeErr)
	}
	clientSessionToken := string(decodedToken)

	if clientSessionToken != string(expectedSessionToken) {
		log.Printf("Inbound: SessionToken 验证失败 (%s): 客户端 %x, 预期 %x", rawConn.RemoteAddr(), clientSessionToken, expectedSessionToken)
		if i.fallbackAddress != "" {
			i.handleFallback(rawConn, i.fallbackAddress)
		} else {
			rawConn.Close()
		}
		return nil, errors.New("Vyper 握手失败: SessionToken 不匹配")
	}

	log.Printf("Inbound: Vyper 客户端 %s 认证成功", rawConn.RemoteAddr())

	// 4. 认证成功：发送填充帧作为确认 (900-1400字节)
	paddingLen := rand.Intn(501) + 900 // 900 到 1400 之间
	padData := make([]byte, paddingLen)
	rand.Read(padData)

	padFrame := NewPadFrame(padData) // 使用通用函数
	if _, err := WriteFrame(rawConn, padFrame); err != nil { // 使用通用函数
		log.Printf("Inbound: 发送认证成功填充帧失败 (%s): %v", rawConn.RemoteAddr(), err)
		rawConn.Close()
		return nil, fmt.Errorf("Vyper 握手失败: 无法发送认证确认帧: %w", err)
	}
	log.Printf("Inbound: 已发送认证成功填充帧，长度 %d", paddingLen)

	// 握手成功，返回一个封装了 Vyper 协议逻辑的 net.Conn
	// 服务器端主动填充，使用客户端请求的 InitialPaddingRule 对应的模式
	// 如果客户端请求 0xFF，服务器默认使用第一个模式
	var serverPaddingRule byte = 0x01 // 默认使用第一个模式
	if initFrame.InitialPaddingRule == 0xFF && len(i.paddingPatterns) > 0 {
		serverPaddingRule = 0x01 // 客户端请求服务器决定，服务器默认使用第一个
	} else if initFrame.InitialPaddingRule >= 0x01 && int(initFrame.InitialPaddingRule-1) < len(i.paddingPatterns) {
		serverPaddingRule = initFrame.InitialPaddingRule // 使用客户端指定的模式
	} else {
		// 如果客户端规则无效，或者 0x00 (无主动填充)，服务器也不主动填充
		serverPaddingRule = 0x00
	}

	return newVyperConn(rawConn, serverPaddingRule, i.paddingPatterns), nil // 使用通用函数
}

// Close 关闭入站器，停止接受新的连接。
func (i *TCPInbound) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	if i.listener != nil {
		return i.listener.Close()
	}
	return nil
}

// Addr 返回监听器的网络地址。
func (i *TCPInbound) Addr() net.Addr {
	if i.listener != nil {
		return i.listener.Addr()
	}
	return nil
}

// handleFallback 处理认证失败后的 HTTP Fallback
func (i *TCPInbound) handleFallback(conn net.Conn, fallbackAddr string) {
	log.Printf("Inbound: 触发 Fallback 到 %s", fallbackAddr)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Inbound: 读取 Fallback HTTP 请求失败 (%s): %v", conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusBadRequest, "Invalid HTTP Request")
		return
	}

	fallbackURL, err := url.Parse(fallbackAddr)
	if err != nil {
		log.Printf("Inbound: 解析 Fallback URL 失败 (%s): %v", conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusInternalServerError, "Server Fallback Misconfiguration")
		return
	}

	req.RequestURI = ""
	req.URL.Host = fallbackURL.Host
	req.URL.Scheme = fallbackURL.Scheme
	req.URL.Opaque = fallbackURL.Opaque

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Inbound: 转发 Fallback 请求到 %s 失败 (%s): %v", fallbackAddr, conn.RemoteAddr(), err)
		i.sendHTTPError(conn, http.StatusBadGateway, "Fallback Target Unreachable")
		return
	}
	defer resp.Body.Close()

	err = resp.Write(conn)
	if err != nil {
		log.Printf("Inbound: 写入 Fallback 响应到客户端失败 (%s): %v", conn.RemoteAddr(), err)
	}

	log.Printf("Inbound: 已处理 Fallback 请求，关闭连接 %s", conn.RemoteAddr())
}

// sendHTTPError 向连接发送一个简单的 HTTP 错误响应
func (i *TCPInbound) sendHTTPError(w io.Writer, statusCode int, message string) {
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
		log.Printf("Inbound: 发送 HTTP 错误响应失败: %v", err)
	}
}
