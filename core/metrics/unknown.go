package metrics

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

const (
	// DefaultUnknownMaxEntries caps the number of distinct unknown SNIs tracked
	// so Prometheus label cardinality stays bounded.
	DefaultUnknownMaxEntries = 128
	maxSNILength             = 253
	noSNILabel               = "<no-sni>"
)

// UnknownEntry is a distinct SNI seen without a matching proxy rule.
type UnknownEntry struct {
	SNI   string
	Count uint64
}

// BlockedStat is a blocklist rule and its hit count.
type BlockedStat struct {
	Pattern string
	Hits    uint64
}

// Stats is a point-in-time snapshot of the global proxy metrics.
type Stats struct {
	UnknownTotal   uint64
	UnknownUnique  int
	UnknownEntries []UnknownEntry
	BlockedUnknown uint64
	Blocked        []BlockedStat
}

// UnknownSNITracker counts connections whose SNI matched no configured proxy.
// The set of distinct SNIs is capped to keep cardinality bounded.
type UnknownSNITracker struct {
	mu         sync.Mutex
	counts     map[string]uint64
	total      uint64
	blocked    uint64
	maxEntries int
}

// NewUnknownSNITracker returns a tracker holding at most maxEntries distinct SNIs.
func NewUnknownSNITracker(maxEntries int) *UnknownSNITracker {
	if maxEntries <= 0 {
		maxEntries = DefaultUnknownMaxEntries
	}
	return &UnknownSNITracker{
		counts:     make(map[string]uint64),
		maxEntries: maxEntries,
	}
}

// Observe records an unknown SNI and reports whether it is the first sighting.
func (t *UnknownSNITracker) Observe(sni string) (isNew bool) {
	sni = normalizeSNI(sni)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.total++
	if _, ok := t.counts[sni]; ok {
		t.counts[sni]++
		return false
	}
	if len(t.counts) >= t.maxEntries {
		return false
	}
	t.counts[sni] = 1
	return true
}

// Block records a rejected connection with an unknown SNI.
func (t *UnknownSNITracker) Block() {
	atomic.AddUint64(&t.blocked, 1)
}

// Snapshot returns the totals and a copy of the tracked entries, sorted by count.
func (t *UnknownSNITracker) Snapshot() (total, blocked uint64, entries []UnknownEntry) {
	t.mu.Lock()
	total = t.total
	entries = make([]UnknownEntry, 0, len(t.counts))
	for sni, count := range t.counts {
		entries = append(entries, UnknownEntry{SNI: sni, Count: count})
	}
	t.mu.Unlock()

	blocked = atomic.LoadUint64(&t.blocked)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].SNI < entries[j].SNI
	})
	return total, blocked, entries
}

func normalizeSNI(sni string) string {
	sni = strings.TrimSpace(strings.ToLower(sni))
	if sni == "" {
		return noSNILabel
	}
	if len(sni) > maxSNILength {
		sni = sni[:maxSNILength]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) && r != '"' && r != '\\' {
			return r
		}
		return -1
	}, sni)
}
