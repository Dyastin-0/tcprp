package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/Dyastin-0/mpr/core/config"
)

var (
	ErrNotConfigured = errors.New("not configured")

	sniff = Sniff{
		peekN: 24,
	}
)

// Proxy handles protocol detection and routing.
type Proxy struct {
	// config defines the user-defined proxy configurations.
	Config *config.Config
	// tlsConfig defines the tls configuration to use for all incoming tls connection.
	TLSConfig *tls.Config
}

// NewProxy return a new Proxy.
func New() *Proxy {
	return &Proxy{
		Config: config.NewConfig(),
	}
}

// Handler routes the connection based on the underlying protocol.
func (p *Proxy) Handler(conn net.Conn) error {
	protocol, peekableConn := sniff.Conn(conn)

	switch protocol {
	case ProtoTLS:
		actualProtocol, tlsConn := p.handleTLS(peekableConn)
		if actualProtocol == ProtoHTTPS {
			return p.http(tlsConn)
		}
		return p.tls(tlsConn)
	case ProtoHTTP:
		return p.http(peekableConn)
	case ProtoTCP:
		return p.tcp(peekableConn)
	default:
		return p.tcp(peekableConn)
	}
}

// handleTLS performs TLS handshake and determines if it's HTTPS or plain TLS.
func (p *Proxy) handleTLS(conn net.Conn) (string, *tls.Conn) {
	peekConn := NewPeekableConn(conn)
	tlsConn := tls.Server(peekConn, p.TLSConfig)

	err := tlsConn.Handshake()
	if err != nil {
		return ProtoTLS, tlsConn
	}

	state := tlsConn.ConnectionState()

	if state.NegotiatedProtocol == "http/1.1" || state.NegotiatedProtocol == "h2" {
		return ProtoHTTPS, tlsConn
	}

	return ProtoTLS, tlsConn
}

func (p *Proxy) http(conn net.Conn) error {
	defer conn.Close()

	bufrd := bufio.NewReader(conn)
	req, err := http.ReadRequest(bufrd)
	if err != nil {
		return err
	}

	host := req.Host
	proxy := p.Config.GetProxy(host)
	if proxy == nil {
		return ErrNotConfigured
	}

	if proxy.Limiter == nil {
		return nil
	}

	if !proxy.Limiter.Allow(conn) {
		return nil
	}

	route := proxy.MatchRoute(req.URL.Path)
	modifiedReq := req.Clone(req.Context())

	modifiedReq.URL.Path = route.RewrittenPath

	if req.URL.RawPath != "" {
		modifiedReq.URL.RawPath = route.RewrittenPath
	}

	dst, err := net.Dial("tcp", route.Target)
	if err != nil {
		return fmt.Errorf("failed to dial tcp: %w", err)
	}
	defer dst.Close()

	err = modifiedReq.Write(dst)
	if err != nil {
		return fmt.Errorf("failed to write http request: %w", err)
	}

	proxyConn := proxy.Metrics.NewProxyReadWriter(conn)

	return Stream(proxyConn, dst)
}

func (p *Proxy) tcp(conn net.Conn) error {
	conn.Close()
	return nil
}

func (p *Proxy) tls(conn *tls.Conn) error {
	defer conn.Close()

	sni := conn.ConnectionState().ServerName
	proxy := p.Config.GetProxy(sni)

	if proxy.Limiter == nil {
		return nil
	}

	if !proxy.Limiter.Allow(conn) {
		return nil
	}

	dst, err := net.Dial("tcp", proxy.Target)
	if err != nil {
		return fmt.Errorf("failed to dial tcp: %w", err)
	}

	proxyConn := proxy.Metrics.NewProxyReadWriter(conn)

	return Stream(proxyConn, dst)
}
