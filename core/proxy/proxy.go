package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

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
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		shouldClose := p.handleRequest(conn, req, proxy)
		if shouldClose {
			return nil
		}
	}
}

func (p *Proxy) handleRequest(clientConn net.Conn, req *http.Request, proxy *config.Proxy) bool {
	route := proxy.MatchRoute(req.URL.Path)

	if route.Limiter != nil && !route.Limiter.Allow(clientConn) {
		p.writeError(clientConn, http.StatusTooManyRequests, "Rate limit exceeded")
		return true
	}

	isWebSocket := strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")

	modifiedReq := req.Clone(req.Context())
	modifiedReq.URL.Path = route.RewrittenPath
	if req.URL.RawPath != "" {
		modifiedReq.URL.RawPath = route.RewrittenPath
	}

	backend, err := net.Dial("tcp", route.Target)
	if err != nil {
		p.writeError(clientConn, http.StatusBadGateway, "Failed to connect to backend")
		return true
	}
	defer backend.Close()

	if err := modifiedReq.Write(backend); err != nil {
		p.writeError(clientConn, http.StatusBadGateway, "Failed to send request")
		return true
	}

	if isWebSocket {
		return p.handleWebSocket(clientConn, backend, modifiedReq, proxy)
	}

	return p.handleHTTPResponse(clientConn, backend, modifiedReq, req, proxy)
}

func (p *Proxy) handleWebSocket(clientConn, backend net.Conn, req *http.Request, proxy *config.Proxy) bool {
	backendReader := bufio.NewReader(backend)
	resp, err := http.ReadResponse(backendReader, req)
	if err != nil {
		p.writeError(clientConn, http.StatusBadGateway, "Failed to read upgrade response")
		return true
	}

	if err := resp.Write(clientConn); err != nil {
		return true
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		var tracked io.ReadWriter = clientConn
		if proxy.Metrics != nil {
			tracked = proxy.Metrics.NewProxyReadWriter(clientConn)
		}

		Stream(tracked, backend)
	}

	return true
}

func (p *Proxy) handleHTTPResponse(clientConn, backend net.Conn, modifiedReq, originalReq *http.Request, proxy *config.Proxy) bool {
	backendReader := bufio.NewReader(backend)
	resp, err := http.ReadResponse(backendReader, modifiedReq)
	if err != nil {
		p.writeError(clientConn, http.StatusBadGateway, "Failed to read response")
		return true
	}
	defer resp.Body.Close()

	var writer io.Writer = clientConn
	if proxy.Metrics != nil {
		writer = proxy.Metrics.NewProxyReadWriter(clientConn)
	}

	if err := resp.Write(writer); err != nil {
		return true
	}

	if originalReq.ProtoMajor == 1 && originalReq.ProtoMinor == 0 {
		return !strings.EqualFold(originalReq.Header.Get("Connection"), "keep-alive")
	}

	return strings.EqualFold(originalReq.Header.Get("Connection"), "close") ||
		strings.EqualFold(resp.Header.Get("Connection"), "close")
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
