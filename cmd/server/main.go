package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync" // 引入 sync 包用于 WaitGroup

	"github.com/UltraTLS/UltraTLS/config"   // 导入配置包
	"github.com/UltraTLS/UltraTLS/protocol" // 导入协议包
	"github.com/UltraTLS/UltraTLS/server"   // 导入服务器包
	v2net "github.com/v2fly/v2ray-core/v5/common/net" // 导入 v2net
)

func main() {
	// 加载服务器配置
	serverConf, err := config.LoadServerConfig()
	if err != nil {
		log.Fatalf("Failed to load server configuration: %v", err)
	}

	// 定义服务器的 Mux.Cool 层处理函数
	// 这个函数负责处理从 Mux.Cool 子流中接收到的 REQ_FRAME，并连接到目标网站
	serverHandler := func(stream protocol.Stream) {
		// 从 Mux.Cool 子流中获取目标地址
		// 根据 Vyper 协议规范 5.2.1 REQ_FRAME (0x01)，REQ_FRAME 的内容包含目标地址。
		// 假设 Mux.Cool 层已经处理了 REQ_FRAME，并通过 stream.Destination() 方法暴露了目标地址。
		// 这是 Mux.Cool 设计的常见模式，它在 Vyper 协议之上提供多路复用，并管理到最终目标的连接。
		targetDest := stream.Destination() // 假设 protocol.Stream 接口有此方法

		if targetDest.IsValid() {
			log.Printf("Server: Accepted Mux sub-stream for target: %s", targetDest.String())

			// 建立到目标网站的连接
			// targetDest.NetAddr() 假设返回 "host:port" 格式的字符串，适合 net.Dial
			targetConn, err := net.Dial("tcp", targetDest.NetAddr())
			if err != nil {
				log.Printf("Server: Failed to connect to target %s: %v", targetDest.String(), err)
				// 发送 ERR_FRAME 通知客户端连接目标失败
				errFrame := protocol.NewErrFrame([]byte(fmt.Sprintf("Failed to connect to target: %v", err)))
				// 假设 protocol.WriteFrame 可以直接写入 protocol.Stream
				if _, writeErr := protocol.WriteFrame(stream, errFrame); writeErr != nil {
					log.Printf("Server: Failed to send ERR_FRAME to client: %v", writeErr)
				}
				stream.Close() // 关闭 Mux 子流
				return
			}
			defer targetConn.Close() // 确保到目标网站的连接最终被关闭
			log.Printf("Server: Successfully connected to target %s", targetDest.String())

			// 双向转发数据
			var wg sync.WaitGroup
			wg.Add(2) // 两个 goroutine，一个用于从客户端到目标，一个用于从目标到客户端

			// goroutine 1: 从 Mux 子流读取数据并写入目标连接 (从客户端到目标)
			go func() {
				defer wg.Done()
				_, err := io.Copy(targetConn, stream) // 从 Mux 子流读，写到目标连接
				if err != nil && err != io.EOF {
					log.Printf("Server: Data forwarding error from Mux stream to target %s: %v", targetDest.String(), err)
				}
				// 优雅关闭：通知目标连接不再有数据写入
				if closer, ok := targetConn.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				}
			}()

			// goroutine 2: 从目标连接读取数据并写入 Mux 子流 (从目标到客户端)
			go func() {
				defer wg.Done()
				_, err := io.Copy(stream, targetConn) // 从目标连接读，写到 Mux 子流
				if err != nil && err != io.EOF {
					log.Printf("Server: Data forwarding error from target %s to Mux stream: %v", targetDest.String(), err)
				}
				// 优雅关闭：通知 Mux 子流不再有数据写入
				if closer, ok := stream.(interface{ CloseWrite() error }); ok {
					closer.CloseWrite()
				}
			}()

			wg.Wait() // 等待两个转发 goroutine 都完成
			log.Printf("Server: Mux sub-stream for %s closed.", targetDest.String())

		} else {
			log.Printf("Server: Invalid target destination received from Mux sub-stream.")
			// 如果目标地址无效，发送错误帧并关闭子流
			errFrame := protocol.NewErrFrame([]byte("Invalid target destination"))
			if _, writeErr := protocol.WriteFrame(stream, errFrame); writeErr != nil {
				log.Printf("Server: Failed to send ERR_FRAME for invalid target: %v", writeErr)
			}
			stream.Close() // 关闭 Mux 子流
		}
	}

	serverCfg := &server.ServerConfig{
		ListenAddr:  serverConf.ListenAddr,
		Handler:     serverHandler, // 使用上面定义的 handler
		VyperConfig: serverConf,
	}

	log.Printf("Starting Vyper server...")
	if err := server.StartServer(serverCfg); err != nil {
		log.Fatalf("Vyper server failed to start: %v", err)
	}
}

