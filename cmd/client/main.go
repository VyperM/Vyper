package main

import (
	"log"
	"fmt"
	"path/filepath"

	"github.com/VyperM/Vyper/client" // 导入客户端包
	"github.com/VyperM/Vyper/config" // 导入配置包
)

func main() {
	// 加载客户端配置
	conf, err := config.LoadClientConfig()
	if err != nil {
		log.Fatalf("Failed to load client configuration: %v", err)
	}

	// 使用配置中的本地监听地址
	localListenAddr := filepath.Join(conf.ProxyListenAddress, fmt.Sprintf("%d", conf.ProxyListenPort))

	// 创建客户端配置实例
	clientCfg := &client.ClientConfig{
		LocalListen: localListenAddr,
		// Handler 字段可以根据需要设置，这里保持为 nil，使用默认转发逻辑
		Handler: nil,
	}

	log.Printf("Starting Vyper client...")
	if err := client.StartClient(clientCfg); err != nil {
		log.Fatalf("Vyper client failed to start: %v", err)
	}
}

