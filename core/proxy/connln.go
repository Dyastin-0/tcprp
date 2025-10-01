package proxy

import (
	"io"
	"net"
	"sync"
)

type connListener struct {
	conn net.Conn
	once sync.Once
}

func (l *connListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c != nil {
		return c, nil
	}
	return nil, io.EOF
}

func (l *connListener) Close() error {
	return nil
}

func (l *connListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
