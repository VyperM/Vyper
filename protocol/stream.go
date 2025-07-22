package protocol

import (
	"io"
	"net"
	"sync"
	"time"

	v2mux "github.com/v2fly/v2ray-core/v5/common/mux"
	v2buf "github.com/v2fly/v2ray-core/v5/common/buf"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
)

// Stream represents an independent sub-connection (whether TCP or UDP)
// Now implements the net.Conn interface
type Stream interface {
	io.ReadWriteCloser
	StreamID() uint32
	net.Conn
	Destination() v2net.Destination // Added Destination() method to the interface
}

type v2Stream struct {
	conn         net.Conn
	session      *v2mux.Session
	dest         v2net.Destination // The destination for this stream
	closed       bool
	rLock, wLock sync.Mutex
}

func newV2Stream(conn net.Conn, session *v2mux.Session, dest v2net.Destination) *v2Stream {
	return &v2Stream{conn: conn, session: session, dest: dest}
}

func (s *v2Stream) Read(p []byte) (int, error) {
	s.rLock.Lock()
	defer s.rLock.Unlock()
	if s.closed {
		return 0, io.EOF
	}
	reader := v2buf.NewReader(s.conn)
	br, ok := reader.(*v2buf.BufferedReader)
	if !ok {
		return 0, io.ErrUnexpectedEOF
	}
	bufReader := s.session.NewReader(br)
	mb, err := bufReader.ReadMultiBuffer()
	if err != nil {
		return 0, err
	}
	if len(mb) == 0 {
		return 0, io.EOF
	}
	defer v2buf.ReleaseMulti(mb)
	n := copy(p, mb[0].Bytes())
	return n, nil
}

func (s *v2Stream) Write(p []byte) (int, error) {
	s.wLock.Lock()
	defer s.wLock.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	b := v2buf.New()
	defer b.Release()
	if _, err := b.Write(p); err != nil {
		return 0, err
	}
	mb := v2buf.MultiBuffer{b}
	writer := v2mux.NewWriter(s.session.ID, s.dest, v2buf.NewWriter(s.conn), protocol.TransferTypeStream)
	if err := writer.WriteMultiBuffer(mb); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *v2Stream) Close() error {
	s.closed = true
	return s.session.Close()
}

func (s *v2Stream) StreamID() uint32 {
	return uint32(s.session.ID)
}

// Destination returns the target destination of this stream.
func (s *v2Stream) Destination() v2net.Destination {
	return s.dest
}

// === Implement net.Conn Interface ===

func (s *v2Stream) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return nil
}

func (s *v2Stream) RemoteAddr() net.Addr {
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return nil
}

func (s *v2Stream) SetDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetDeadline(t)
	}
	return nil
}

func (s *v2Stream) SetReadDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetReadDeadline(t)
	}
	return nil
}

func (s *v2Stream) SetWriteDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetWriteDeadline(t)
	}
	return nil
}
