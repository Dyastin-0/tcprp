package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlocklistMatch(t *testing.T) {
	blocklist := NewBlocklist([]string{
		"exact.example.com",
		"*.blocked.example.com",
		"  ",
	})

	tests := []struct {
		domain string
		want   string
		ok     bool
	}{
		{"exact.example.com", "exact.example.com", true},
		{"EXACT.example.com.", "exact.example.com", true},
		{"sub.blocked.example.com", "*.blocked.example.com", true},
		{"deep.sub.blocked.example.com", "*.blocked.example.com", true},
		{"blocked.example.com", "", false},
		{"nope.example.com", "", false},
	}

	for _, tt := range tests {
		pattern, ok := blocklist.Match(tt.domain)
		require.Equal(t, tt.ok, ok, tt.domain)
		require.Equal(t, tt.want, pattern, tt.domain)
	}
}

func TestBlocklistHit(t *testing.T) {
	blocklist := NewBlocklist([]string{"bad.example.com"})

	require.True(t, blocklist.Hit("bad.example.com"))  // first hit logs
	require.False(t, blocklist.Hit("bad.example.com")) // rate-limited
	require.False(t, blocklist.Hit("unknown-pattern"))

	stats := blocklist.Snapshot()
	require.Len(t, stats, 1)
	require.Equal(t, "bad.example.com", stats[0].Pattern)
	require.Equal(t, uint64(2), stats[0].Hits)
}

func TestNilBlocklist(t *testing.T) {
	var blocklist *Blocklist
	_, ok := blocklist.Match("example.com")
	require.False(t, ok)
	require.False(t, blocklist.Hit("example.com"))
	require.Nil(t, blocklist.Snapshot())
}
