package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Dyastin-0/tcprp/core/config"
)

// Proxy handles connection routing.
type Proxy struct {
	Config    *config.Config
	TLSConfig *tls.Config
}

func New() *Proxy {
	return &Proxy{
		Config: config.New(),
	}
}

func (p *Proxy) Handler(conn net.Conn) error {
	if p.Config.GlobalLimiter != nil && !p.Config.GlobalLimiter.Allow(conn) {
		conn.Close()
		return fmt.Errorf("global rate limit exceeded")
	}

	conn, err := TLS(conn)
	if err != nil {
		return err
	}

	sni := conn.(*TLSConn).Host()
	proxy := p.Config.GetProxy(sni)
	if proxy == nil {
		conn.Close()
		return fmt.Errorf("no proxy found for SNI: %s", sni)
	}

	if proxy.Terminate {
		conn = tls.Server(conn, p.TLSConfig)
		if proxy.Proto == ProtoHTTP {
			return p.http(conn, proxy)
		}
	}

	return p.stream(conn, proxy)
}

func (p *Proxy) http(conn net.Conn, proxy *config.Proxy) error {
	defer conn.Close()

	if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
		p.writeError(conn, http.StatusTooManyRequests, "Rate limit exceeded")
		return nil
	}

	bufrd := bufio.NewReader(conn)

	for {
		req, err := http.ReadRequest(bufrd)

		conn.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || isTimeout(err) {
				return nil
			}
			return err
		}

		route := proxy.MatchRoute(req.URL.Path)

		if route.Limiter != nil && !route.Limiter.Allow(conn) {
			p.writeError(conn, http.StatusTooManyRequests, "Rate limit exceeded")
			return nil
		}

		isWebSocket := strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
			strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")

		req.URL.Path = route.RewrittenPath
		if req.URL.RawPath != "" {
			req.URL.RawPath = route.RewrittenPath
		}

		backend, err := net.Dial("tcp", route.Target)
		if err != nil {
			p.writeError(conn, http.StatusBadGateway, "Failed to connect to backend")
			return err
		}

		if err = req.Write(backend); err != nil {
			backend.Close()
			p.writeError(conn, http.StatusBadGateway, "Failed to send request")
			return err
		}

		backendReader := bufio.NewReader(backend)
		resp, err := http.ReadResponse(backendReader, req)
		if err != nil {
			backend.Close()
			p.writeError(conn, http.StatusBadGateway, "Failed to read response")
			return err
		}

		if err := resp.Write(conn); err != nil {
			resp.Body.Close()
			backend.Close()
			return err
		}
		resp.Body.Close()

		if isWebSocket && resp.StatusCode == http.StatusSwitchingProtocols {
			clientConn := &BuffConn{Conn: conn, r: bufrd}
			backendConn := &BuffConn{Conn: backend, r: backendReader}

			var rw io.ReadWriter = clientConn
			if proxy.Metrics != nil {
				rw = proxy.Metrics.NewProxyReadWriter(clientConn)
			}

			return Stream(rw, backendConn)
		}

		backend.Close()

		if strings.EqualFold(req.Header.Get("Connection"), "close") ||
			strings.EqualFold(resp.Header.Get("Connection"), "close") {
			return nil
		}
	}
}

func (p *Proxy) stream(conn net.Conn, proxy *config.Proxy) error {
	defer conn.Close()

	if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
		return nil
	}

	backend, err := net.Dial("tcp", proxy.Target)
	if err != nil {
		return err
	}
	defer backend.Close()

	var rw io.ReadWriter = conn
	if proxy.Metrics != nil {
		rw = proxy.Metrics.NewProxyReadWriter(conn)
	}

	return Stream(rw, backend)
}

func (p *Proxy) writeError(conn net.Conn, statusCode int, message string) {
	resp := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(message)),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(message)))
	resp.Header.Set("Connection", "close")
	resp.Write(conn)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
