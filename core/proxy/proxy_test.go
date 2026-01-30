package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func generateTestCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"app.com", "test.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}, nil
}

// TestTLSPassthrough tests TLS passthrough mode.
func TestTLSPassthrough(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    target: "localhost:8086"
`
	err = proxy.Config.LoadBytes([]byte(config))
	require.NoError(t, err)

	serverLn, err := net.Listen("tcp", ":8086")
	require.NoError(t, err)
	defer serverLn.Close()

	go func() {
		for {
			conn, er := serverLn.Accept()
			if er != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				c = tls.Server(c, tlsConfig)

				buf := make([]byte, 1024)
				n, er := c.Read(buf)
				if er != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	proxyLn, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer proxyLn.Close()

	go func() {
		for {
			conn, er := proxyLn.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	tlsClientConfig := &tls.Config{
		ServerName:         "app.com",
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "localhost:8085", tlsClientConfig)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("hello from client"))
	require.NoError(t, err)

	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello from client", string(buf[:n]))
}

// TestHTTPTermination tests HTTP with TLS termination.
func TestHTTPTermination(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    terminate: true
    proto: http
    target: "localhost:8086"
`
	err = proxy.Config.LoadBytes([]byte(config))
	require.NoError(t, err)

	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	})
	backendMux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	backend := &http.Server{
		Addr:    ":8086",
		Handler: backendMux,
	}

	go backend.ListenAndServe()
	defer backend.Close()

	proxyLn, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer proxyLn.Close()

	go func() {
		for {
			conn, er := proxyLn.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app.com",
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("https://localhost:8085/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from backend", string(body))

	resp, err = client.Post("https://localhost:8085/echo", "text/plain", strings.NewReader("test data"))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "test data", string(body))
}

// TestHTTPRouting tests HTTP path-based routing with rewrites.
func TestHTTPRouting(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    terminate: true
    proto: http
    target: "localhost:8086"
    routes:
      - pattern: "/api/*"
        target: "localhost:8087"
        rewrite:
          from: "^/api"
          to: ""
`
	err = proxy.Config.LoadBytes([]byte(config))
	require.NoError(t, err)

	defaultMux := http.NewServeMux()
	defaultMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("default backend: " + r.URL.Path))
	})
	defaultBackend := &http.Server{Addr: ":8086", Handler: defaultMux}
	go defaultBackend.ListenAndServe()
	defer defaultBackend.Close()

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("api backend: " + r.URL.Path))
	})
	apiBackend := &http.Server{Addr: ":8087", Handler: apiMux}
	go apiBackend.ListenAndServe()
	defer apiBackend.Close()

	proxyLn, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer proxyLn.Close()

	go func() {
		for {
			conn, er := proxyLn.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app.com",
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get("https://localhost:8085/test")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, "default backend: /test", string(body))

	resp, err = client.Get("https://localhost:8085/api/users")
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, "api backend: /users", string(body))
}

// TestHTTPKeepAlive tests HTTP/1.1 keep-alive.
func TestHTTPKeepAlive(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    terminate: true
    proto: http
    target: "localhost:8086"
`
	err = proxy.Config.LoadBytes([]byte(config))
	require.NoError(t, err)

	requestCount := 0
	proxyConnectionCount := 0
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("request " + string(rune('0'+requestCount))))
	})
	backend := &http.Server{Addr: ":8086", Handler: backendMux}
	go backend.ListenAndServe()
	defer backend.Close()

	proxyLn, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer proxyLn.Close()

	go func() {
		for {
			conn, er := proxyLn.Accept()
			if er != nil {
				return
			}
			proxyConnectionCount++
			go proxy.Handler(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "app.com",
				InsecureSkipVerify: true,
			},
		},
	}

	for range 3 {
		resp, err := client.Get("https://localhost:8085/")
		require.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()
	}

	require.Equal(t, 3, requestCount)
	require.Equal(t, 1, proxyConnectionCount)
}

func TestWebSocket(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    terminate: true
    proto: http
    target: "localhost:8086"
`
	err = proxy.Config.LoadBytes([]byte(config))
	require.NoError(t, err)

	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "Not a websocket upgrade", http.StatusBadRequest)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		bufrw.WriteString("Upgrade: websocket\r\n")
		bufrw.WriteString("Connection: Upgrade\r\n")
		bufrw.WriteString("\r\n")
		bufrw.Flush()

		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	})

	backend := &http.Server{Addr: ":8086", Handler: backendMux}
	go backend.ListenAndServe()
	defer backend.Close()

	proxyLn, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer proxyLn.Close()

	go func() {
		for {
			conn, er := proxyLn.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	tlsConn, err := tls.Dial("tcp", "localhost:8085", &tls.Config{
		ServerName:         "app.com",
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer tlsConn.Close()

	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: app.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	_, err = tlsConn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	bufReader := bufio.NewReader(tlsConn)
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	resp, err := http.ReadResponse(bufReader, &http.Request{Method: "GET"})
	require.NoError(t, err)
	require.Equal(t, 101, resp.StatusCode)
	require.Equal(t, "websocket", strings.ToLower(resp.Header.Get("Upgrade")))

	_, err = tlsConn.Write([]byte("test message"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	var n int

	if bufReader.Buffered() > 0 {
		n, err = bufReader.Read(buf)
	} else {
		n, err = tlsConn.Read(buf)
	}
	require.NoError(t, err)
	require.Equal(t, "test message", string(buf[:n]))
}
