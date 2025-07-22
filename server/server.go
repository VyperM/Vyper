package server

import (
	"bufio" // 用于读取HTTP请求
	"bytes" // 用于构建HTTP响应
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http" // 用于完整的HTTP请求和响应处理
	"net/url" // 用于解析URL
	"time"

	"github.com/UltraTLS/UltraTLS/protocol" // 假设 protocol 包在这里
	"github.com/UltraTLS/UltraTLS/config" 
	"github.com/v2fly/v2ray-core/v5/common/net" // 假设这个包可用
)

// ServerConfig 用于启动服务器的配置
type ServerConfig struct {
	ListenAddr    string
	Handler       func(stream protocol.Stream) // Mux.Cool 层的处理函数
	VyperConfig   *config.ServerConfig // 包含 Vyper 协议特有配置
}

// StartServer 启动 Vyper 服务器
func StartServer(cfg *ServerConfig) error {
	// 加载 TLS 配置
	tlsCert, err := tls.LoadX509KeyPair(cfg.VyperConfig.TLSCertPath, cfg.VyperConfig.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("无法加载 TLS 证书或密钥: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12, // 建议至少 TLS 1.2
	}

	if cfg.VyperConfig.TLSClientAuth {
		clientCACertPool, err := protocol.LoadCACertPool(cfg.VyperConfig.TLSClientCaCertPath)
		if err != nil {
			return fmt.Errorf("无法加载客户端 CA 证书池: %w", err)
		}
		tlsConfig.ClientCAs = clientCACertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	listener, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("服务器 TLS 监听失败: %w", err)
	}
	defer listener.Close()

	log.Printf("Vyper 服务器正在监听 %s", cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("服务器接受连接错误: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go func(rawConn net.Conn) {
			defer rawConn.Close()

			log.Printf("接收到来自 %s 的新连接", rawConn.RemoteAddr())

			// --- Vyper 协议认证阶段 ---
			initFrame, err := protocol.ReadVyperInitializationFrame(rawConn)
			if err != nil {
				log.Printf("读取 Vyper 初始化帧失败 (%s): %v", rawConn.RemoteAddr(), err)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// 验证 AuthBlob
			if string(initFrame.AuthBlob) != cfg.VyperConfig.AuthToken {
				log.Printf("AuthBlob 验证失败 (%s): AuthBlob不匹配", rawConn.RemoteAddr())
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// 计算并验证 SessionToken
			currentTimeSeconds := time.Now().Unix()
			sessionTokenData := make([]byte, 8)
			binary.BigEndian.PutUint64(sessionTokenData[:], uint64(currentTimeSeconds))
			sessionTokenData = append(sessionTokenData, []byte(cfg.VyperConfig.AuthToken)...)

			hasher := sha256.New()
			hasher.Write(sessionTokenData)
			sessionTokenHash := hasher.Sum(nil)
			expectedSessionToken := sessionTokenHash[:4]

			// 从 ClientInfo 中解析伪 HTTP 请求，并提取 SessionToken
			// 假定 ClientInfo 包含一个完整的 HTTP 请求行，且路径是 "/SessionToken/<Base64编码的SessionToken>"
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(initFrame.ClientInfo))))
			if err != nil {
				log.Printf("解析 Vyper Initialization Frame 中的伪 HTTP 请求失败 (%s): %v", rawConn.RemoteAddr(), err)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			if req.Method != "GET" {
				log.Printf("伪 HTTP 请求方法不是 GET (%s): %s", rawConn.RemoteAddr(), req.Method)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			// 解析请求路径，提取 SessionToken
			if !bytes.HasPrefix([]byte(req.URL.Path), []byte("/SessionToken/")) {
				log.Printf("伪 HTTP 请求路径格式不正确 (%s): %s", rawConn.RemoteAddr(), req.URL.Path)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			base64EncodedToken := req.URL.Path[len("/SessionToken/"):]
			decodedToken, decodeErr := protocol.Base64Decode(base64EncodedToken)
			if decodeErr != nil {
				log.Printf("SessionToken Base64解码失败 (%s): %v", rawConn.RemoteAddr(), decodeErr)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}
			clientSessionToken := string(decodedToken)

			if clientSessionToken != string(expectedSessionToken) {
				log.Printf("SessionToken 验证失败 (%s): 客户端 %x, 预期 %x", rawConn.RemoteAddr(), clientSessionToken, expectedSessionToken)
				if cfg.VyperConfig.FallbackAddress != "" {
					handleFallback(rawConn, cfg.VyperConfig.FallbackAddress)
				}
				return
			}

			log.Printf("Vyper 客户端 %s 认证成功", rawConn.RemoteAddr())

			// 认证成功：发送填充帧作为确认 (900-1400字节)
			paddingLen := rand.Intn(501) + 900 // 900 到 1400 之间
			padData := make([]byte, paddingLen)
			rand.Read(padData)

			padFrame := protocol.NewPadFrame(padData)
			if _, err := protocol.WriteFrame(rawConn, padFrame); err != nil {
				log.Printf("发送认证成功填充帧失败 (%s): %v", rawConn.RemoteAddr(), err)
				return
			}

			// 认证成功且填充帧发送后，建立 mux session
			session := protocol.NewSession(rawConn)
			defer session.Close()

			// 持续接受子流
			for {
				stream, _, err := session.AcceptStream()
				if err != nil {
					log.Printf("服务器接受 Mux 子流错误 (%s): %v", rawConn.RemoteAddr(), err)
					break
				}
				log.Printf("服务器接受到新的 Mux 子流 (%s)", rawConn.RemoteAddr())
				go cfg.Handler(stream)
			}
		}(conn)
	}
}

// handleFallback 处理认证失败后的 HTTP Fallback
// 它将客户端的请求转发到 fallbackAddr，并将响应写回客户端。
func handleFallback(conn net.Conn, fallbackAddr string) {
	log.Printf("触发 Fallback 到 %s", fallbackAddr)

	// 使用 bufio.Reader 从连接中读取，以便 http.ReadRequest 可以正确解析
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("读取 Fallback HTTP 请求失败 (%s): %v", conn.RemoteAddr(), err)
		// 尝试发送一个错误响应，然后关闭连接
		sendHTTPError(conn, http.StatusBadRequest, "Invalid HTTP Request")
		return
	}

	// 解析 fallbackAddress
	fallbackURL, err := url.Parse(fallbackAddr)
	if err != nil {
		log.Printf("解析 Fallback URL 失败 (%s): %v", conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusInternalServerError, "Server Fallback Misconfiguration")
		return
	}

	// 调整请求以转发到 fallbackAddr
	req.RequestURI = "" // 必须清空此字段，否则 http.Client.Do 会出错
	req.URL.Host = fallbackURL.Host
	req.URL.Scheme = fallbackURL.Scheme
	req.URL.Opaque = fallbackURL.Opaque // 保留不透明路径

	// 使用 http.Client 发送请求
	client := &http.Client{
		// 配置客户端以跟随重定向，处理 TLS 等
		// 可以设置 Timeout
		Timeout: 10 * time.Second, // Fallback 请求的超时
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("转发 Fallback 请求到 %s 失败 (%s): %v", fallbackAddr, conn.RemoteAddr(), err)
		sendHTTPError(conn, http.StatusBadGateway, "Fallback Target Unreachable")
		return
	}
	defer resp.Body.Close()

	// 将响应写回原始连接
	err = resp.Write(conn)
	if err != nil {
		log.Printf("写入 Fallback 响应到客户端失败 (%s): %v", conn.RemoteAddr(), err)
		// 连接可能会在这里中断，无需发送更多错误
	}

	log.Printf("已处理 Fallback 请求，关闭连接 %s", conn.RemoteAddr())
}

// sendHTTPError 向连接发送一个简单的 HTTP 错误响应
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
		log.Printf("发送 HTTP 错误响应失败: %v", err)
	}
}
