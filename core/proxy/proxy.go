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
			p.writeErrorResponse(conn, http.StatusNotFound, "Host not found")
			return nil
		}

		if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
			p.writeErrorResponse(conn, http.StatusTooManyRequests, "Rate limit exceeded")
			return nil
		}

		route := proxy.MatchRoute(req.URL.Path)
		log.Debug().
			Str("host", host).
			Str("path", route.RewrittenPath).
			Str("target", route.Target).
			Msg("rewrite")

		shouldClose := p.handleSingleRequest(conn, req, &route, proxy)

		if shouldClose {
			return nil
		}
	}
}

func (p *Proxy) handleSingleRequest(clientConn net.Conn, req *http.Request, route *config.RouteResult, proxy *config.Proxy) bool {
	modifiedReq := req.Clone(req.Context())
	modifiedReq.URL.Path = route.RewrittenPath
	if req.URL.RawPath != "" {
		modifiedReq.URL.RawPath = route.RewrittenPath
	}

	dst, err := net.Dial("tcp", route.Target)
	if err != nil {
		log.Error().Err(err).Str("target", route.Target).Msg("failed to dial backend")
		p.writeErrorResponse(clientConn, http.StatusBadGateway, "Bad Gateway")
		return true
	}
	defer dst.Close()

	err = modifiedReq.Write(dst)
	if err != nil {
		log.Error().Err(err).Msg("failed to write request to backend")
		p.writeErrorResponse(clientConn, http.StatusBadGateway, "Bad Gateway")
		return true
	}

	backendReader := bufio.NewReader(dst)
	resp, err := http.ReadResponse(backendReader, modifiedReq)
	if err != nil {
		log.Error().Err(err).Msg("failed to read response from backend")
		p.writeErrorResponse(clientConn, http.StatusBadGateway, "Bad Gateway")
		return true
	}
	defer resp.Body.Close()

	var writer io.Writer = clientConn
	if proxy.Metrics != nil {
		metricsWriter := proxy.Metrics.NewProxyReadWriter(clientConn)
		writer = metricsWriter
	}

	err = resp.Write(writer)
	if err != nil {
		log.Error().Err(err).Msg("failed to write response to client")
		return true
	}

	shouldClose := false
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		shouldClose = !strings.EqualFold(req.Header.Get("Connection"), "keep-alive")
	} else {
		shouldClose = strings.EqualFold(req.Header.Get("Connection"), "close") ||
			strings.EqualFold(resp.Header.Get("Connection"), "close")
	}

	return shouldClose
}

func (p *Proxy) writeErrorResponse(conn net.Conn, statusCode int, message string) {
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
