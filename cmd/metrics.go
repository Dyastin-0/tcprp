// Package cmd implements a command line interface for tcprp.
package cmd

import (
	"encoding/json"
	"net/http"

	"github.com/Dyastin-0/tcprp/core/config"
	"github.com/Dyastin-0/tcprp/core/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsHandler returns an HTTP handler exposing per-proxy metrics in the
// Prometheus exposition format, plus Go runtime, process and global metrics.
func metricsHandler(cfg *config.Config) http.Handler {
	registry := prometheus.NewRegistry()

	collector := metrics.NewPromCollector(
		func() []metrics.Snapshot {
			keys := cfg.Proxies.GetKeysWithVal()
			snapshots := make([]metrics.Snapshot, 0, len(keys))
			for _, domain := range keys {
				p := cfg.Proxies.Get(domain)
				if p == nil || *p == nil || (*p).Metrics == nil {
					continue
				}
				snapshots = append(snapshots, metrics.Snapshot{
					Domain:  domain,
					Metrics: (*p).Metrics,
				})
			}
			return snapshots
		},
		cfg.MetricsStats,
	)

	registry.MustRegister(collector)
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// unknownSNIHandler lists the unknown SNIs seen since startup as JSON.
func unknownSNIHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		total, blocked, entries := cfg.Unknown.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Total   uint64                 `json:"total"`
			Blocked uint64                 `json:"blocked"`
			Entries []metrics.UnknownEntry `json:"entries"`
		}{
			Total:   total,
			Blocked: blocked,
			Entries: entries,
		})
	}
}
