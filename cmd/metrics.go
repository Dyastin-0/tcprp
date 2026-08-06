// Package cmd implements a command line interface for tcprp.
package cmd

import (
	"net/http"

	"github.com/Dyastin-0/tcprp/core/config"
	"github.com/Dyastin-0/tcprp/core/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsHandler returns an HTTP handler exposing per-proxy metrics in the
// Prometheus exposition format, plus Go runtime and process metrics.
func metricsHandler(proxies *config.Trie[*config.Proxy]) http.Handler {
	registry := prometheus.NewRegistry()

	collector := metrics.NewPromCollector(func() []metrics.Snapshot {
		keys := proxies.GetKeysWithVal()
		snapshots := make([]metrics.Snapshot, 0, len(keys))
		for _, domain := range keys {
			p := proxies.Get(domain)
			if p == nil || *p == nil || (*p).Metrics == nil {
				continue
			}
			snapshots = append(snapshots, metrics.Snapshot{
				Domain:  domain,
				Metrics: (*p).Metrics,
			})
		}
		return snapshots
	})

	registry.MustRegister(collector)
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}
