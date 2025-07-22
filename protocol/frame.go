package protocol

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"crypto/x509" // 引入 x509 包以处理证书
)

// --- Vyper Initialization Frame 的结构 (此结构在 server.go 中被使用，因此此处也需要定义) ---
// 它包含客户端发送的认证及初始化信息。
type VyperInitializationFrame struct {
	AuthBlob           []byte
	InitialPaddingRule byte
	Reserved           []byte // 3 bytes, 协议保留字段
	ClientInfo         string // 客户端信息，此处被重用于 SessionToken 的 HTTP 请求
}

// --- Vyper Session Frame 的结构 (包括 PAD_FRAME，在 server.go 中被使用) ---
// 这是 Vyper 会话层数据传输的基本单位。
type VyperSessionFrame struct {
	FrameType byte
	Sequence  uint32
	Content   []byte // 帧的实际内容
}

// LoadCACertPool 从 PEM 编码的 CA 证书文件路径加载一个 *x509.CertPool。
// 这是 TLS 客户端/服务器验证链条中不可或缺的一部分。
func LoadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("无法读取 CA 证书文件 '%s': %w", caCertPath, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("无法从 PEM 解析 CA 证书文件 '%s'", caCertPath)
	}
	return caCertPool, nil
}

// ReadVyperInitializationFrame 从给定的 io.Reader 中读取一个完整的 Vyper Initialization Frame。
// 它严格遵循 Vyper 协议中初始化帧的字节格式和顺序：
// AuthBlob Length (2字节) | AuthBlob (可变长度) | InitialPaddingRule (1字节) | Reserved (3字节) | ClientInfo Length (2字节) | ClientInfo (可变长度)
func ReadVyperInitializationFrame(r io.Reader) (*VyperInitializationFrame, error) {
	var initFrame VyperInitializationFrame

	// 1. 读取 AuthBlob Length (2 字节, Big-Endian uint16)
	var authBlobLen uint16
	if err := binary.Read(r, binary.BigEndian, &authBlobLen); err != nil {
		return nil, fmt.Errorf("读取 AuthBlob Length 失败: %w", err)
	}
	// log.Printf("DEBUG: 读取到 AuthBlobLen: %d", authBlobLen) // 用于调试

	// 2. 读取 AuthBlob (变长)
	initFrame.AuthBlob = make([]byte, authBlobLen)
	if _, err := io.ReadFull(r, initFrame.AuthBlob); err != nil {
		return nil, fmt.Errorf("读取 AuthBlob 失败: %w", err)
	}
	// log.Printf("DEBUG: 读取到 AuthBlob: %x", initFrame.AuthBlob) // 用于调试

	// 3. 读取 InitialPaddingRule (1 字节)
	if err := binary.Read(r, binary.BigEndian, &initFrame.InitialPaddingRule); err != nil {
		return nil, fmt.Errorf("读取 InitialPaddingRule 失败: %w", err)
	}
	// log.Printf("DEBUG: 读取到 InitialPaddingRule: %d", initFrame.InitialPaddingRule) // 用于调试

	// 4. 读取 Reserved (3 字节)
	initFrame.Reserved = make([]byte, 3)
	if _, err := io.ReadFull(r, initFrame.Reserved); err != nil {
		return nil, fmt.Errorf("读取 Reserved 字段失败: %w", err)
	}
	// log.Printf("DEBUG: 读取到 Reserved: %x", initFrame.Reserved) // 用于调试

	// 5. 读取 ClientInfo Length (2 字节, Big-Endian uint16)
	var clientInfoLen uint16
	if err := binary.Read(r, binary.BigEndian, &clientInfoLen); err != nil {
		return nil, fmt.Errorf("读取 ClientInfo Length 失败: %w", err)
	}
	// log.Printf("DEBUG: 读取到 ClientInfoLen: %d", clientInfoLen) // 用于调试

	// 6. 读取 ClientInfo (变长)
	clientInfoBytes := make([]byte, clientInfoLen)
	if _, err := io.ReadFull(r, clientInfoBytes); err != nil {
		return nil, fmt.Errorf("读取 ClientInfo 失败: %w", err)
	}
	initFrame.ClientInfo = string(clientInfoBytes)
	// log.Printf("DEBUG: 读取到 ClientInfo: %s", initFrame.ClientInfo) // 用于调试

	return &initFrame, nil
}

// Base64Decode 对 Base64 标准编码的字符串进行解码，返回原始字节切片。
func Base64Decode(s string) ([]byte, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}
	return decodedBytes, nil
}

// NewPadFrame 创建一个 Vyper PAD_FRAME。
// PAD_FRAME 用于在协议中插入填充数据以增加流量的混淆性。
func NewPadFrame(content []byte) *VyperSessionFrame {
	return &VyperSessionFrame{
		FrameType: 0x06, // PAD_FRAME 的 FrameType 定义为 0x06
		Sequence:  0,    // 对于 PAD_FRAME，Sequence 字段通常可以为 0 或不重要
		Content:   content,
	}
}

// WriteFrame 将一个 VyperSessionFrame 写入到 io.Writer。
// 它严格遵循 Vyper 协议中会话帧的字节格式和顺序：
// FrameType (1字节) | Sequence (4字节, Big-Endian uint32) | Content Length (2字节, Big-Endian uint16) | Content (可变长度)
func WriteFrame(w io.Writer, frame *VyperSessionFrame) (int, error) {
	// 帧头包含 FrameType (1B) + Sequence (4B) + Content Length (2B) = 7 字节
	header := make([]byte, 7)
	header[0] = frame.FrameType
	binary.BigEndian.PutUint32(header[1:5], frame.Sequence)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(frame.Content))) // Content Length 是 Content 的长度

	n, err := w.Write(header) // 写入帧头
	if err != nil {
		return n, fmt.Errorf("写入帧头失败: %w", err)
	}

	contentN, err := w.Write(frame.Content) // 写入帧内容
	if err != nil {
		return n + contentN, fmt.Errorf("写入帧内容失败: %w", err)
	}

	return n + contentN, nil // 返回总写入字节数
}

// WriteVyperInitializationFrame 将一个 VyperInitializationFrame 写入到 io.Writer。
// 它严格遵循 Vyper 协议中初始化帧的字节格式和顺序。
func WriteVyperInitializationFrame(w io.Writer, frame *VyperInitializationFrame) (int, error) {
	totalN := 0

	// 1. 写入 AuthBlob Length (2 字节, Big-Endian uint16)
	authBlobLen := uint16(len(frame.AuthBlob))
	if err := binary.Write(w, binary.BigEndian, authBlobLen); err != nil {
		return totalN, fmt.Errorf("写入 AuthBlob Length 失败: %w", err)
	}
	totalN += 2

	// 2. 写入 AuthBlob (变长)
	n, err := w.Write(frame.AuthBlob)
	if err != nil {
		return totalN + n, fmt.Errorf("写入 AuthBlob 失败: %w", err)
	}
	totalN += n

	// 3. 写入 InitialPaddingRule (1 字节)
	if err := binary.Write(w, binary.BigEndian, frame.InitialPaddingRule); err != nil {
		return totalN, fmt.Errorf("写入 InitialPaddingRule 失败: %w", err)
	}
	totalN += 1

	// 4. 写入 Reserved (3 字节)
	n, err = w.Write(frame.Reserved)
	if err != nil {
		return totalN + n, fmt.Errorf("写入 Reserved 字段失败: %w", err)
	}
	totalN += n

	// 5. 写入 ClientInfo Length (2 字节, Big-Endian uint16)
	clientInfoLen := uint16(len(frame.ClientInfo))
	if err := binary.Write(w, binary.BigEndian, clientInfoLen); err != nil {
		return totalN, fmt.Errorf("写入 ClientInfo Length 失败: %w", err)
	}
	totalN += 2

	// 6. 写入 ClientInfo (变长)
	n, err = w.Write([]byte(frame.ClientInfo))
	if err != nil {
		return totalN + n, fmt.Errorf("写入 ClientInfo 失败: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadVyperSessionFrame 从 io.Reader 读取一个完整的 VyperSessionFrame。
// 它遵循 Vyper 协议中会话帧的字节格式。
func ReadVyperSessionFrame(r io.Reader) (*VyperSessionFrame, error) {
	frame := &VyperSessionFrame{}
	header := make([]byte, 7) // FrameType (1B) + Sequence (4B) + Content Length (2B)

	// 读取帧头
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("读取会话帧头失败: %w", err)
	}

	frame.FrameType = header[0]
	frame.Sequence = binary.BigEndian.Uint32(header[1:5])
	contentLen := binary.BigEndian.Uint16(header[5:7])

	// 读取帧内容
	if contentLen > 0 {
		frame.Content = make([]byte, contentLen)
		if _, err := io.ReadFull(r, frame.Content); err != nil {
			return nil, fmt.Errorf("读取会话帧内容失败 (预期长度 %d): %w", contentLen, err)
		}
	} else {
		frame.Content = []byte{} // 内容长度为0时，设为空字节切片
	}

	return frame, nil
}
