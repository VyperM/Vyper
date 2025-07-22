package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	// 假设 v2net 路径正确，用于表示目标地址
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
)

// Inbound 接口定义了本地代理入站器的通用行为。
// 它负责监听本地连接，并从这些连接中解析出目标地址。
type Inbound interface {
	Listen() error
	// Accept 方法现在返回客户端连接和解析出的目标地址
	Accept() (net.Conn, v2net.Destination, error)
	Close() error
	Addr() net.Addr
}

// Socks5Inbound 实现了 Inbound 接口，用于处理 SOCKS5 代理协议。
// 它监听本地 TCP 端口，并执行 SOCKS5 握手以获取客户端请求的目标地址。
type Socks5Inbound struct {
	addr     string       // 监听地址 (例如 "127.0.0.1:1080")
	listener net.Listener // 底层 TCP 监听器
}

// NewSocks5Inbound 创建并返回一个新的 Socks5Inbound 实例。
func NewSocks5Inbound(addr string) *Socks5Inbound {
	return &Socks5Inbound{addr: addr}
}

// Listen 开始监听 SOCKS5 连接。
func (s *Socks5Inbound) Listen() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 监听失败: %w", err)
	}
	s.listener = ln
	log.Printf("SOCKS5 客户端代理正在监听 %s", s.addr)
	return nil
}

// Accept 接受一个新的 SOCKS5 连接，执行 SOCKS5 握手，并解析目标地址。
// 返回客户端连接和解析出的目标地址。
func (s *Socks5Inbound) Accept() (net.Conn, v2net.Destination, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return nil, v2net.Destination{}, fmt.Errorf("SOCKS5 接受连接错误: %w", err)
	}
	log.Printf("SOCKS5: 接收到本地连接，来自 %s", conn.RemoteAddr())

	// 执行 SOCKS5 握手并解析目标地址
	targetDest, err := s.handleSocks5Handshake(conn)
	if err != nil {
		conn.Close() // 握手失败，关闭连接
		return nil, v2net.Destination{}, fmt.Errorf("SOCKS5 握手失败: %w", err)
	}
	return conn, targetDest, nil
}

// handleSocks5Handshake 执行 SOCKS5 协议的协商和请求解析。
// 它处理认证方法选择和 CONNECT 请求，并返回解析出的目标地址。
func (s *Socks5Inbound) handleSocks5Handshake(conn net.Conn) (v2net.Destination, error) {
	// 设置读超时，防止恶意或卡住的客户端
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // 恢复无超时

	// SOCKS5 协商阶段 1: 读取 GREETING (VER, NMETHODS, METHODS)
	buf := make([]byte, 258) // SOCKS5 规范中 METHODS 的最大长度为 255
	_, err := io.ReadFull(conn, buf[:2]) // 读取 VER (0x05) 和 NMETHODS
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取 VER/NMETHODS 失败: %w", err)
	}
	ver := buf[0]
	nMethods := buf[1]

	if ver != 0x05 {
		// 不支持的 SOCKS 版本，发送错误响应
		_, _ = conn.Write([]byte{0x05, 0xFF}) // SOCKS5, NO ACCEPTABLE METHODS
		return v2net.Destination{}, errors.New("SOCKS5: 不支持的 SOCKS 版本")
	}
	if nMethods == 0 {
		_, _ = conn.Write([]byte{0x05, 0xFF}) // SOCKS5, NO ACCEPTABLE METHODS
		return v2net.Destination{}, errors.New("SOCKS5: NMETHODS 为 0")
	}

	_, err = io.ReadFull(conn, buf[:nMethods]) // 读取 METHODS
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取 METHODS 失败: %w", err)
	}

	// 简化：我们只支持 NO AUTHENTICATION REQUIRED (0x00)
	foundNoAuth := false
	for _, method := range buf[:nMethods] {
		if method == 0x00 {
			foundNoAuth = true
			break
		}
	}

	if !foundNoAuth {
		// 没有可接受的认证方法，发送 NO ACCEPTABLE METHODS (0xFF)
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return v2net.Destination{}, errors.New("SOCKS5: 不支持的认证方法 (仅支持无认证)")
	}

	// SOCKS5 协商阶段 2: 发送 METHOD SELECTION RESPONSE (VER, METHOD)
	_, err = conn.Write([]byte{0x05, 0x00}) // SOCKS5, 无认证
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 发送 METHOD 响应失败: %w", err)
	}

	// SOCKS5 请求阶段 1: 读取 REQUEST (VER, CMD, RSV, ATYP)
	_, err = io.ReadFull(conn, buf[:4]) // 读取 VER, CMD, RSV, ATYP
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取请求头失败: %w", err)
	}
	ver = buf[0]
	cmd := buf[1] // CMD: CONNECT (0x01), BIND (0x02), UDP ASSOCIATE (0x03)
	// rsv := buf[2] // Reserved, 0x00
	atyp := buf[3] // ATYP: IPv4 (0x01), Domain (0x03), IPv6 (0x04)

	if ver != 0x05 {
		// SOCKS 版本不匹配，发送错误响应
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // General SOCKS server failure
		return v2net.Destination{}, errors.New("SOCKS5: 请求中 SOCKS 版本不正确")
	}
	if cmd != 0x01 { // 仅支持 CONNECT 命令
		// 发送 Command Not Supported (0x07)
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return v2net.Destination{}, errors.New("SOCKS5: 不支持的命令 (仅支持 CONNECT)")
	}

	var destAddrBytes []byte
	var destPort uint16

	switch atyp {
	case 0x01: // IPv4 地址
		destAddrBytes = make([]byte, 4)
		_, err = io.ReadFull(conn, destAddrBytes)
		if err != nil {
			return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取 IPv4 地址失败: %w", err)
		}
	case 0x03: // 域名
		_, err = io.ReadFull(conn, buf[:1]) // 读取域名长度
		if err != nil {
			return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取域名长度失败: %w", err)
		}
		domainLen := buf[0]
		destAddrBytes = make([]byte, domainLen)
		_, err = io.ReadFull(conn, destAddrBytes) // 读取域名
		if err != nil {
			return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取域名失败: %w", err)
		}
	case 0x04: // IPv6 地址
		destAddrBytes = make([]byte, 16)
		_, err = io.ReadFull(conn, destAddrBytes)
		if err != nil {
			return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取 IPv6 地址失败: %w", err)
		}
	default:
		// 发送 Address Type Not Supported (0x08)
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return v2net.Destination{}, errors.New("SOCKS5: 不支持的地址类型")
	}

	// 读取端口
	_, err = io.ReadFull(conn, buf[:2]) // 读取 2 字节端口
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 读取端口失败: %w", err)
	}
	destPort = binary.BigEndian.Uint16(buf[:2])

	// SOCKS5 请求阶段 2: 发送 REPLY (VER, REP, RSV, BND.ADDR, BND.PORT)
	// 对于 CONNECT 命令，通常回复成功 (0x00) 和一个虚拟的绑定地址/端口 (0.0.0.0:0)
	// 因为实际的连接是通过 Vyper 服务器建立的。
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return v2net.Destination{}, fmt.Errorf("SOCKS5: 发送成功响应失败: %w", err)
	}

	// 构建 v2net.Destination
	var v2Dest v2net.Destination
	switch atyp {
	case 0x01, 0x04: // IPv4 或 IPv6
		v2Dest = v2net.TCPDestination(v2net.IPAddress(destAddrBytes), v2net.Port(destPort))
	case 0x03: // 域名
		v2Dest = v2net.TCPDestination(v2net.DomainAddress(string(destAddrBytes)), v2net.Port(destPort))
	}

	log.Printf("SOCKS5: 解析到目标: %s:%d (ATYP: %x)", v2Dest.Address.String(), v2Dest.Port, atyp)
	return v2Dest, nil
}

// Close 关闭 SOCKS5 监听器。
func (s *Socks5Inbound) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr 返回监听器的网络地址。
func (s *Socks5Inbound) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

