package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"     // 引入 sync 包用于 WaitGroup
	"time"

	"github.com/VyperM/Vyper/config"
	"github.com/VyperM/Vyper/protocol" // 假设 protocol 包在这里
	v2net "github.com/v2fly/v2ray-core/v5/common/net" // 引入 v2net
)

// ClientConfig 配置结构（可扩展）
type ClientConfig struct {
	LocalListen string // 本地监听地址 (SOCKS5 代理)
	Handler     func(stream protocol.Stream) // 可选的自定义数据处理函数
}

// StartClient 启动 Vyper 客户端。
// 它会启动一个本地 SOCKS5 代理，接收来自本地应用程序的连接，
// 然后通过 Vyper 协议将流量转发到远程 Vyper 服务器。
func StartClient(cfg *ClientConfig) error {
	// === 1. 读取配置 ===
	conf, err := config.LoadClientConfig()
	if err != nil {
		log.Fatalf("无法加载配置: %v", err)
	}
	log.Printf("客户端配置加载成功: ServerIP=%s, ServerPort=%d", conf.ServerIP, conf.ServerPort)

	// === 2. 使用新的 SOCKS5 Inbound 作为本地代理入口 ===
	// 创建并启动 SOCKS5 监听器，接收来自本地应用的代理请求
	localInbound := NewSocks5Inbound(cfg.LocalListen) // 使用新的 SOCKS5 Inbound
	if err := localInbound.Listen(); err != nil {
		return fmt.Errorf("客户端本地 SOCKS5 监听失败: %w", err)
	}
	defer localInbound.Close() // 确保在函数退出时关闭监听器
	log.Printf("客户端 SOCKS5 代理正在监听 %s", cfg.LocalListen)

	// 循环接受新的本地连接
	for {
		// localInbound.Accept() 方法现在会返回客户端连接和解析出的目标地址
		clientConn, targetDest, err := localInbound.Accept()
		if err != nil {
			log.Printf("客户端本地 SOCKS5 接受连接错误: %v", err)
			time.Sleep(time.Second) // 避免在错误循环中耗尽 CPU 资源
			continue
		}
		log.Printf("SOCKS5: 接收到本地连接，来自 %s，目标 %s", clientConn.RemoteAddr(), targetDest.String())

		// 为每个接受的连接启动一个 goroutine 进行处理，实现并发
		go handleConnection(clientConn, conf, cfg.Handler, targetDest)
	}
}

// handleConnection 处理单个客户端连接的完整生命周期。
// 它负责建立到 Vyper 服务器的连接，进行 Vyper 协议握手，建立 Mux.Cool 子流，并双向转发数据。
func handleConnection(clientConn net.Conn, conf *config.Config, handler func(protocol.Stream), targetDest v2net.Destination) {
	defer clientConn.Close() // 确保本地客户端连接最终被关闭
	log.Printf("处理本地连接，来自 %s，目标 %s", clientConn.RemoteAddr(), targetDest.String())

	// === 3. 建立到 Vyper 服务器的主 TLS 连接并完成 Vyper 协议握手 ===
	serverAddr := fmt.Sprintf("%s:%d", conf.ServerIP, conf.ServerPort)

	// 构建 TLS 配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: conf.TLSInsecureSkipVerify, // 是否跳过服务器证书验证 (不推荐在生产环境使用)
		ServerName:         conf.TLSServerName,        // 用于 SNI (Server Name Indication)
		MinVersion:         tls.VersionTLS12,          // 建议至少 TLS 1.2
	}

	// 加载 CA 证书，用于验证服务器证书 (如果配置了)
	if conf.TLSCACertPath != "" {
		caCertPool, err := protocol.LoadCACertPool(conf.TLSCACertPath) // 假设 LoadCACertPool 存在于 protocol 包
		if err != nil {
			log.Printf("无法加载 CA 证书池: %v", err)
			return
		}
		tlsConfig.RootCAs = caCertPool
	}

	// 加载客户端证书和密钥，用于双向 TLS 认证 (如果配置了)
	if conf.TLSClientCertPath != "" && conf.TLSClientKeyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(conf.TLSClientCertPath, conf.TLSClientKeyPath)
		if err != nil {
			log.Printf("无法加载客户端证书或密钥: %v", err)
			return
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// 使用 protocol 包中的 Vyper 客户端 Outbound 来连接到 Vyper 服务器
	vyperOutbound := protocol.NewTLSOutbound(
		10*time.Second,              // 连接超时时间
		tlsConfig,                   // TLS 配置
		conf.AuthToken,              // Vyper 协议认证令牌
		byte(conf.InitialPaddingRule), // 客户端初始填充规则
		conf.ClientInfo,             // 客户端信息字符串 (用于伪装 HTTP User-Agent)
		conf.PaddingPatterns,        // 客户端定义的填充模式列表
	)
	// 注意: vyperOutbound.Close() 主要是为了阻止新的连接，
	// Connect 返回的 serverConn 才是实际需要 defer 关闭的连接
	defer vyperOutbound.Close()

	// 连接到 Vyper 服务器并完成 Vyper 协议握手
	serverConn, err := vyperOutbound.Connect("tcp", serverAddr)
	if err != nil {
		log.Printf("客户端连接到 Vyper 服务器 %s 失败: %v", serverAddr, err)
		return
	}
	defer serverConn.Close() // 确保 Vyper 连接在处理完成后关闭
	log.Printf("已连接到 Vyper 服务器 %s 并完成 Vyper 握手", serverAddr)

	// === 4. 建立 Mux.Cool Session ===
	// Mux.Cool 会话建立在 Vyper 连接之上，用于多路复用多个应用流
	session := protocol.NewSession(serverConn) // 传递认证成功后的 serverConn (vyperConn 实例)
	defer session.Close() // 确保 Mux.Cool 会话关闭
	log.Printf("Mux.Cool 会话已建立")

	// === 5. 开一个 Mux.Cool 子流，目标是客户端请求的实际目的地 ===
	// 将从 SOCKS5 握手中解析出的目标地址传递给 Mux.Cool，由 Mux.Cool 负责转发请求
	stream, err := session.OpenStream(targetDest)
	if err != nil {
		log.Printf("客户端打开 Mux 子流失败: %v", err)
		return
	}
	defer stream.Close() // 确保 Mux.Cool 子流关闭
	log.Printf("Mux.Cool 子流已打开，目标 %s", targetDest.String())

	// === 6. 双向转发数据 ===
	// 将本地客户端连接的数据与 Mux.Cool 子流进行双向转发
	if handler != nil {
		// 如果提供了自定义 handler，则将 Mux.Cool 子流交给 handler 处理
		handler(stream)
	} else {
		// 否则，进行标准的双向数据转发
		var wg sync.WaitGroup
		wg.Add(2) // 两个 goroutine，一个用于上传，一个用于下载

		// goroutine 1: 从本地客户端读取数据并写入 Mux 子流 (上传)
		go func() {
			defer wg.Done()
			_, err := io.Copy(stream, clientConn) // 从本地客户端读，写到 Mux 子流
			if err != nil && err != io.EOF {
				log.Printf("客户端到 Mux 子流的数据转发错误: %v", err)
			}
			// 优雅关闭：通知 Mux 子流不再有数据写入
			// 假设 protocol.Stream 实现了 CloseWrite() 方法
			if closer, ok := stream.(interface{ CloseWrite() error }); ok {
				closer.CloseWrite()
			} else {
				log.Printf("警告: protocol.Stream 未实现 CloseWrite()，可能导致半关闭问题。")
			}
		}()

		// goroutine 2: 从 Mux 子流读取数据并写入本地客户端 (下载)
		go func() {
			defer wg.Done()
			_, err := io.Copy(clientConn, stream) // 从 Mux 子流读，写到本地客户端
			if err != nil && err != io.EOF {
				log.Printf("Mux 子流到客户端的数据转发错误: %v", err)
			}
			// 优雅关闭：通知本地客户端不再有数据写入
			// 假设 net.Conn 实现了 CloseWrite() 方法 (并非所有 net.Conn 都支持)
			if closer, ok := clientConn.(interface{ CloseWrite() error }); ok {
				closer.CloseWrite()
			} else {
				log.Printf("警告: 本地客户端连接未实现 CloseWrite()，可能导致半关闭问题。")
			}
		}()

		wg.Wait() // 等待两个转发 goroutine 都完成
	}
	log.Printf("连接处理完成，关闭连接 %s", clientConn.RemoteAddr())
}

