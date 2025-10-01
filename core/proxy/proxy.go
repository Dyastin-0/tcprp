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
	"github.com/rs/zerolog/log"
)

var sniff = Sniff{
	peekN: 24,
}

// Proxy handles protocol detection and routing.
type Proxy struct {
	// config defines the user-defined proxy configurations.
	Config *config.Config
	// tlsConfig defines the tls configuration to use for all incoming tls connection.
	TLSConfig *tls.Config
}

// New return a new Proxy.
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

	for {
		req, err := http.ReadRequest(bufrd)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		host := req.Host
		proxy := p.Config.GetProxy(host)
		if proxy == nil {
			return nil
		}

		if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
			return nil
		}

		route := proxy.MatchRoute(req.URL.Path)
		log.Debug().
			Str("host", host).
			Str("path", route.RewrittenPath).
			Str("target", route.Target).
			Msg("rewrite")

		if err := p.handleSingleRequest(req, &route, conn, proxy); err != nil {
			return err
		}

		if !shouldKeepAlive(req) {
			return nil
		}
	}
}

func (p *Proxy) handleSingleRequest(req *http.Request, route *config.RouteResult, clientConn net.Conn, proxy *config.Proxy) error {
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

	bufBackend := bufio.NewReader(dst)
	resp, err := http.ReadResponse(bufBackend, modifiedReq)
	if err != nil {
		return fmt.Errorf("failed to read http response: %w", err)
	}
	defer resp.Body.Close()

	var responseWriter io.Writer = clientConn
	if proxy.Metrics != nil {
		metricsConn := proxy.Metrics.NewProxyReadWriter(clientConn)
		responseWriter = metricsConn
	}

	err = resp.Write(responseWriter)
	if err != nil {
		return fmt.Errorf("failed to write http response: %w", err)
	}

	return nil
}

func shouldKeepAlive(req *http.Request) bool {
	// HTTP/1.0 defaults to close unless explicitly keep-alive
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return strings.ToLower(req.Header.Get("Connection")) == "keep-alive"
	}
	// HTTP/1.1 defaults to keep-alive unless explicitly close
	return strings.ToLower(req.Header.Get("Connection")) != "close"
}

func (p *Proxy) tcp(conn net.Conn) error {
	conn.Close()
	return nil
}

func (p *Proxy) tls(conn *tls.Conn) error {
	defer conn.Close()

	sni := conn.ConnectionState().ServerName
	proxy := p.Config.GetProxy(sni)
	if proxy == nil {
		return nil
	}

	if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
		return nil
	}

	dst, err := net.Dial("tcp", proxy.Target)
	if err != nil {
		return fmt.Errorf("failed to dial tcp: %w", err)
	}

	proxyConn := proxy.Metrics.NewProxyReadWriter(conn)

	return Stream(proxyConn, dst)
}
