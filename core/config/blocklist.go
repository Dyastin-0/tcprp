package config

import (
	"strings"
	"sync"
	"time"

	"github.com/Dyastin-0/tcprp/core/metrics"
)

// Blocklist rejects SNIs before they are routed. Rules are exact domains or
// wildcard suffixes ("*.example.com" matches any subdomain).
type Blocklist struct {
	mu    sync.Mutex
	rules []*blockRule
}

type blockRule struct {
	pattern  string
	suffix   string
	wildcard bool
	hits     uint64
	lastLog  time.Time
}

// NewBlocklist builds a blocklist from exact and wildcard patterns.
func NewBlocklist(patterns []string) *Blocklist {
	b := &Blocklist{}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		rule := &blockRule{pattern: pattern}
		if strings.HasPrefix(pattern, "*.") {
			rule.wildcard = true
			rule.suffix = strings.TrimPrefix(pattern, "*.")
		}
		b.rules = append(b.rules, rule)
	}
	return b
}

// Match reports the first rule matching domain.
func (b *Blocklist) Match(domain string) (pattern string, ok bool) {
	if b == nil {
		return "", false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range b.rules {
		if rule.matches(domain) {
			return rule.pattern, true
		}
	}
	return "", false
}

func (r *blockRule) matches(domain string) bool {
	if r.wildcard {
		return strings.HasSuffix(domain, "."+r.suffix)
	}
	return domain == r.pattern
}

// Hit records a blocked connection and reports whether it should be logged
// (rate-limited to one line per rule every 30 seconds).
func (b *Blocklist) Hit(pattern string) (shouldLog bool) {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, rule := range b.rules {
		if rule.pattern != pattern {
			continue
		}
		rule.hits++
		if time.Since(rule.lastLog) >= 30*time.Second {
			rule.lastLog = time.Now()
			return true
		}
		return false
	}
	return false
}

// Snapshot returns the configured rules with their hit counts.
func (b *Blocklist) Snapshot() []metrics.BlockedStat {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := make([]metrics.BlockedStat, 0, len(b.rules))
	for _, rule := range b.rules {
		stats = append(stats, metrics.BlockedStat{Pattern: rule.pattern, Hits: rule.hits})
	}
	return stats
}
