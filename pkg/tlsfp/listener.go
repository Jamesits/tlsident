package tlsfp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"tlsident/pkg/capture"
)

type Listener struct {
	net.Listener
}

func NewListener(inner net.Listener) *Listener {
	return &Listener{Listener: inner}
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	buffered, hello, err := readClientHelloRecord(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
	if splitErr != nil {
		host = conn.RemoteAddr().String()
	}

	return &ObservedConn{
		Conn:  conn,
		buf:   bytes.NewReader(buffered),
		hello: hello,
		connection: capture.ConnectionInfo{
			ClientIP:  host,
			Timestamp: time.Now().Unix(),
		},
	}, nil
}

type ObservedConn struct {
	net.Conn
	buf        *bytes.Reader
	hello      *ClientHello
	connection capture.ConnectionInfo
}

func (c *ObservedConn) Read(p []byte) (int, error) {
	if c.buf != nil && c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *ObservedConn) ClientHello() *ClientHello {
	return c.hello
}

func (c *ObservedConn) ConnectionInfo() capture.ConnectionInfo {
	return c.connection
}

func readClientHelloRecord(conn net.Conn) ([]byte, *ClientHello, error) {
	var raw bytes.Buffer
	var handshake bytes.Buffer
	expectedHandshakeLen := -1

	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, nil, err
		}
		raw.Write(header)

		recordType := header[0]
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLen == 0 {
			return nil, nil, fmt.Errorf("empty tls record")
		}

		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, nil, err
		}
		raw.Write(payload)

		if recordType != 22 {
			return nil, nil, fmt.Errorf("expected handshake record, got %d", recordType)
		}

		handshake.Write(payload)
		if expectedHandshakeLen == -1 && handshake.Len() >= 4 {
			bytes := handshake.Bytes()
			if bytes[0] != 1 {
				return nil, nil, fmt.Errorf("expected client hello handshake, got %d", bytes[0])
			}
			expectedHandshakeLen = int(bytes[1])<<16 | int(bytes[2])<<8 | int(bytes[3])
		}
		if expectedHandshakeLen != -1 && handshake.Len() >= 4+expectedHandshakeLen {
			message := handshake.Bytes()[4 : 4+expectedHandshakeLen]
			hello, err := ParseClientHello(message)
			if err != nil {
				return nil, nil, err
			}
			return raw.Bytes(), hello, nil
		}
	}
}
