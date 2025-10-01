package proxy

import (
	"io"
	"net"
	"sync"
)

type connListener struct {
	conn   net.Conn
	served bool
	mu     sync.Mutex
}

func (l *connListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.served {
		return nil, io.EOF
	}

	l.served = true
	return l.conn, nil
}

func (l *connListener) Close() error {
	return nil
}

func (l *connListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
