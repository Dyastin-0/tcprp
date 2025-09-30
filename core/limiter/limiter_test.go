package limiter

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAllowIP(t *testing.T) {
	limiter := New(WithRPS(1000), WithBurst(5), WithCooldown(100*time.Millisecond))
	ip := "192.168.1.100"

	for range 5 {
		require.True(t, limiter.AllowIP(ip))
	}

	require.False(t, limiter.allow(ip))

	time.Sleep(150 * time.Millisecond)
	require.True(t, limiter.AllowIP(ip))
}

func TestAllowConnection(t *testing.T) {
	limiter := New(WithRPS(1000), WithBurst(3), WithCooldown(50*time.Millisecond))
	_, conn := net.Pipe()

	for range 3 {
		require.True(t, limiter.Allow(conn))
	}

	require.False(t, limiter.Allow(conn))
}

func TestConcurrentAccess(t *testing.T) {
	limiter := New(WithRPS(100), WithBurst(10))

	done := make(chan bool, 10)
	for i := range 10 {
		go func(id int) {
			ip := "192.168.1.1"
			for range 100 {
				limiter.AllowIP(ip)
			}
			done <- true
		}(i)
	}

	for range 10 {
		<-done
	}
}
