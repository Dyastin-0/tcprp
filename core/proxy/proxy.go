package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		proxy := p.Config.GetProxy(host)
		if proxy == nil {
			http.Error(w, "Host not found", http.StatusNotFound)
			return
		}
		if proxy.Limiter != nil && !proxy.Limiter.Allow(conn) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		route := proxy.MatchRoute(req.URL.Path)
		log.Debug().
			Str("host", host).
			Str("path", route.RewrittenPath).
			Str("target", route.Target).
			Msg("rewrite")

		req.URL.Path = route.RewrittenPath
		if req.URL.RawPath != "" {
			req.URL.RawPath = route.RewrittenPath
		}

		target := route.Target
		if !strings.HasPrefix(target, "http://") {
			target = fmt.Sprintf("http://%s", target)
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			return
		}

		reverseProxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = targetURL.Scheme
				req.URL.Host = targetURL.Host
				req.Host = targetURL.Host
			},
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				log.Error().Err(err).Str("target", route.Target).Msg("proxy error")
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			},
		}

		reverseProxy.ServeHTTP(w, req)
	})

	server := &http.Server{
		Handler: handler,
	}

	listener := &connListener{conn: conn}
	return server.Serve(listener)
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
