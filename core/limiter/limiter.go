// Package limiter implements a network connection rate limiter.
package limiter

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	cmap "github.com/orcaman/concurrent-map/v2"
	"golang.org/x/time/rate"
)

// Limiter provides network connection-level rate limiting.
type Limiter struct {
	rate     rate.Limit
	burst    int
	cooldown time.Duration

	clients *cmap.ConcurrentMap[string, *client]
}

type client struct {
	mu       sync.RWMutex
	limiter  *rate.Limiter
	lastSeen int64
	cooldown int64
}

// New creates a new connection limiter.
func New(opts ...OptFunc) *Limiter {
	limiter := &Limiter{}

	for _, opt := range opts {
		opt(limiter)
	}

	if limiter.clients == nil {
		c := cmap.New[*client]()
		limiter.clients = &c
	}

	if limiter.cooldown == 0 {
		WithDefaultCooldown(limiter)
	}

	if limiter.burst == 0 {
		WithDefaultBurst(limiter)
	}

	if limiter.rate == 0 {
		WithDefaultRPS(limiter)
	}

	return limiter
}

// Allow checks if the connection should be allowed.
func (l *Limiter) Allow(conn net.Conn) bool {
	if l.rate == 0 || l.burst == 0 {
		return true
	}

	ip := getIP(conn)
	if ip == "" {
		return false
	}

	return l.allow(ip)
}

// AllowIP checks if the IP should be allowed (useful for testing).
func (l *Limiter) AllowIP(ip string) bool {
	if l.rate == 0 || l.burst == 0 {
		return true
	}
	return l.allow(ip)
}

func (l *Limiter) allow(ip string) bool {
	now := time.Now()
	c, exists := l.clients.Get(ip)

	if !exists {

		c = &client{
			limiter:  rate.NewLimiter(l.rate, l.burst),
			lastSeen: now.UnixNano(),
		}
		l.clients.Set(ip, c)
	}

	if now.Before(time.Unix(0, atomic.LoadInt64(&c.cooldown))) {
		return false
	}

	if !c.limiter.Allow() {
		atomic.StoreInt64(&c.cooldown, now.Add(l.cooldown).UnixNano())
		return false
	}

	atomic.StoreInt64(&c.lastSeen, now.UnixNano())
	return true
}

// Cleanup removes stale entries.
func (l *Limiter) Cleanup(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	for c := range l.clients.IterBuffered() {
		if time.Unix(0, c.Val.lastSeen).Before(cutoff) {
			l.clients.Remove(c.Key)
		}
	}
}

func getIP(conn net.Conn) string {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if addr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP.String()
		}
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
