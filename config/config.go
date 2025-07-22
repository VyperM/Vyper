package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 是客户端的配置结构
type Config struct {
	// --- 基础连接与核心 Vyper 参数 ---
	ServerIP            string `yaml:"server_ip"`             // 必填：Vyper 服务器的 IP 地址或域名
	ServerPort          int    `yaml:"server_port"`           // 必填：Vyper 服务器的端口
	AuthToken           string `yaml:"auth_token"`            // 必填：用于认证的预共享 Auth Token (Base64 编码)
	BufferSize          int    `yaml:"buffer_size"`           // 可选：数据传输缓冲区大小 (字节)
	Timeout             int    `yaml:"timeout"`               // 可选：连接超时时间 (秒)

	// --- Vyper 协议特有参数 (客户端部分) ---
	InitialPaddingRule  int    `yaml:"initialPaddingRule"`    // 必填：初始填充规则索引 (0-255)
	ClientInfo          string `yaml:"clientInfo"`            // 可选：客户端软件信息字符串
	// 新增：客户端定义的填充模式列表。
	// 客户端通过 initialPaddingRule 索引来选择。
	// 可以包含多种模式，每种模式是一个数组，数组中包含 [min_length, max_length] 对。
	PaddingPatterns     [][][]int `yaml:"paddingPatterns"` // 修复：为客户端添加 PaddingPatterns 字段

	// --- TLS (传输层安全) 配置 (客户端部分) ---
	TLSEnabled          bool   `yaml:"tlsEnabled"`            // 必填：是否启用 TLS (Vyper 协议必须为 true)
	TLSServerName       string `yaml:"tlsServerName"`         // 必填：TLS SNI (Server Name Indication)
	TLSInsecureSkipVerify bool `yaml:"tlsInsecureSkipVerify"` // 必填：是否跳过服务器证书验证 (生产环境应为 false)
	TLSCACertPath       string `yaml:"tlsCACertPath"`         // 可选：自定义 CA 证书路径 (PEM 格式)
	TLSClientCertPath   string `yaml:"tlsClientCertPath"`     // 可选：客户端 TLS 证书路径 (PEM 格式，如果服务器需要)
	TLSClientKeyPath    string `yaml:"tlsClientKeyPath"`      // 可选：客户端 TLS 私钥路径 (PEM 格式)

	// --- 本地代理监听配置 (客户端部分) ---
	ProxyListenAddress  string `yaml:"proxyListenAddress"`    // 必填：本地代理监听地址
	ProxyListenPort     int    `yaml:"proxyListenPort"`       // 必填：本地代理监听端口
	ProxyProtocol       string `yaml:"proxyProtocol"`         // 可选：本地代理协议类型 (例如 "socks5", "http")
}

// ServerConfig 包含了 Vyper 服务器的所有配置参数。
type ServerConfig struct {
	// --- 基础监听与核心 Vyper 参数 ---
	ListenAddr          string `yaml:"listenAddr"`            // 必填：服务器监听地址 (例如 "0.0.0.0:443")
	AuthToken           string `yaml:"authToken"`             // 必填：用于认证的预共享 Auth Token (Base64 编码)

	// --- TLS (传输层安全) 配置 ---
	TLSEnabled          bool   `yaml:"tlsEnabled"`            // 必填：是否启用 TLS (Vyper 协议必须为 true)
	TLSCertPath         string `yaml:"tlsCertPath"`           // 必填：服务器证书链文件路径 (PEM 格式)
	TLSKeyPath          string `yaml:"tlsKeyPath"`            // 必填：服务器私钥文件路径 (PEM 格式)
	TLSClientAuth       bool   `yaml:"tlsClientAuth"`         // 可选：是否启用客户端证书认证
	TLSClientCaCertPath string `yaml:"tlsClientCaCertPath"`   // 可选：用于验证客户端证书的 CA 证书路径

	// --- 填充模式定义 (服务器特有) ---
	// 必填：服务器定义的填充模式列表。
	// 客户端通过 initialPaddingRule 索引来选择。
	// 可以包含多种模式，每种模式是一个数组，数组中包含 [min_length, max_length] 对。
	// 注意：这里的类型是 [][]int，因为 ServerConfig 只需要定义模式本身，
	// 而不是像 protocol 包那样处理多层嵌套的模式集合。
	PaddingPatterns     [][][]int `yaml:"paddingPatterns"` // 修复：确保服务器端也使用 [][][]int

	// --- 回退地址 (可选，用于伪装) ---
	FallbackAddress     string `yaml:"fallbackAddress"`       // 可选：Auth Token 验证失败或协议错误时的 L7 服务回退地址
}

// LoadClientConfig 读取并解析客户端配置。
// 不处理可选参数的默认值。
func LoadClientConfig() (*Config, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("无法获取可执行文件路径: %w", err)
	}
	execDir := filepath.Dir(execPath)

	configPaths := []string{
		filepath.Join(execDir, "config.yaml"),
		filepath.Join(execDir, "config", "config.yaml"),
	}

	var data []byte
	var foundPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil {
			data, err = os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("无法读取配置文件 %s: %w", p, err)
			}
			foundPath = p
			break
		}
	}

	if data == nil {
		return nil, fmt.Errorf("在预期位置未找到 config.yaml: %v", configPaths)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("无法解析配置文件 %s: %w", foundPath, err)
	}

	// --- 客户端基本验证 (不处理可选参数的默认值) ---
	if cfg.ServerIP == "" || cfg.ServerPort == 0 {
		return nil, fmt.Errorf("缺少 Vyper 服务器连接基本信息 (server_ip, server_port)")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token 缺失，认证必需")
	}
	if !cfg.TLSEnabled {
		return nil, fmt.Errorf("Vyper 协议必须启用 TLS (tlsEnabled 需为 true)")
	}
	if cfg.TLSServerName == "" && !cfg.TLSInsecureSkipVerify {
		return nil, fmt.Errorf("TLS 已启用但 tlsServerName 缺失，且 tlsInsecureSkipVerify 为 false")
	}
	if cfg.ProxyListenAddress == "" || cfg.ProxyListenPort == 0 {
		return nil, fmt.Errorf("缺少本地代理监听信息 (proxyListenAddress, proxyListenPort)")
	}
	// 验证 PaddingPatterns 是否为空，如果 InitialPaddingRule 不是 0x00
	if cfg.InitialPaddingRule != 0x00 && len(cfg.PaddingPatterns) == 0 {
		return nil, fmt.Errorf("当 initialPaddingRule 不为 0x00 时，paddingPatterns 不能为空")
	}

	return &cfg, nil
}

// LoadServerConfig 读取并解析服务器配置。
// 不处理可选参数的默认值。
func LoadServerConfig() (*ServerConfig, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("无法获取可执行文件路径: %w", err)
	}
	execDir := filepath.Dir(execPath)

	configPaths := []string{
		filepath.Join(execDir, "server_config.yaml"),
		filepath.Join(execDir, "config", "server_config.yaml"),
	}

	var data []byte
	var foundPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil {
			data, err = os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("无法读取服务器配置文件 %s: %w", p, err)
			}
			foundPath = p
			break
		}
	}

	if data == nil {
		return nil, fmt.Errorf("在预期位置未找到 server_config.yaml: %v", configPaths)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("无法解析服务器配置文件 %s: %w", foundPath, err)
	}

	// --- 服务器基本验证 (不处理可选参数的默认值) ---
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listenAddr 缺失，服务器监听地址必需")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("authToken 缺失，认证必需")
	}
	if !cfg.TLSEnabled {
		return nil, fmt.Errorf("TLS 必须启用 (tlsEnabled 需为 true)")
	}
	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		return nil, fmt.Errorf("TLS 启用时，tlsCertPath 和 tlsKeyPath 必需")
	}
	if cfg.TLSClientAuth && cfg.TLSClientCaCertPath == "" {
		return nil, fmt.Errorf("TLS 客户端认证启用时，tlsClientCaCertPath 必需")
	}
	if len(cfg.PaddingPatterns) == 0 {
		return nil, fmt.Errorf("paddingPatterns 列表不能为空")
	}

	return &cfg, nil
}
