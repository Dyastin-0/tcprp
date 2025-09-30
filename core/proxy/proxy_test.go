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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func NewTestHTTPServer(addr, msg string) *http.Server {
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(msg))
		}),
	}

	return server
}

func NewTestTCPServer(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return ln, err
}

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
		DNSNames:              []string{"test.com"},
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

func TestHTTP(t *testing.T) {
	proxy := New()

	config := `
proxies:
  "app.com":
    target: "localhost:8082"
`

	proxy.Config.LoadBytes([]byte(config))

	server := NewTestHTTPServer(":8082", "hello")
	go server.ListenAndServe()

	ln, err := net.Listen("tcp", ":8081")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, er := ln.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	conn, err := net.Dial("tcp", ":8081")
	require.NoError(t, err)
	defer conn.Close()

	httpRequest := "GET / HTTP/1.1\r\nHost: app.com\r\n\r\n"
	_, err = conn.Write([]byte(httpRequest))
	require.NoError(t, err)

	bufrd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufrd, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "200 OK", resp.Status)
	require.Equal(t, "hello", string(bodyBytes))
}

func TestHTTPS(t *testing.T) {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		NextProtos: []string{"http/1.1", "h2"},
	}

	proxy := New()
	proxy.TLSConfig = tlsConfig

	config := `
proxies:
  "app.com":
    target: "localhost:8084"
`

	proxy.Config.LoadBytes([]byte(config))

	server := NewTestHTTPServer(":8084", "hello")
	go server.ListenAndServe()

	ln, err := net.Listen("tcp", ":8083")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, er := ln.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	tlsClientConfig := &tls.Config{
		ServerName:         "app.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1", "h2"},
	}

	conn, err := tls.Dial("tcp", ":8083", tlsClientConfig)
	require.NoError(t, err)
	defer conn.Close()

	httpRequest := "GET / HTTP/1.1\r\nHost: app.com\r\n\r\n"
	_, err = conn.Write([]byte(httpRequest))
	require.NoError(t, err)

	bufrd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufrd, nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "200 OK", resp.Status)
	require.Equal(t, "hello", string(bodyBytes))
}

func TestTLS(t *testing.T) {
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

	proxy.Config.LoadBytes([]byte(config))

	serverLn, err := NewTestTCPServer(":8086")
	require.NoError(t, err)
	defer serverLn.Close()

	go func() {
		conn, er := serverLn.Accept()
		if er != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, er := conn.Read(buf)
		if er != nil {
			return
		}

		conn.Write(buf[:n])
	}()

	ln, err := net.Listen("tcp", ":8085")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, er := ln.Accept()
			if er != nil {
				return
			}
			go proxy.Handler(conn)
		}
	}()

	tlsClientConfig := &tls.Config{
		ServerName:         "app.com",
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", ":8085", tlsClientConfig)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf[:n]))

	defer conn.Close()
}
