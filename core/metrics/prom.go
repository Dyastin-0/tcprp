package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Snapshot ties a proxy domain to its metrics for collection.
type Snapshot struct {
	Domain  string
	Metrics *Metrics
}

// PromCollector implements prometheus.Collector by bridging the atomic
// counters in Metrics to Prometheus metrics, one series per proxy domain.
type PromCollector struct {
	snapshot func() []Snapshot

	ingressBytes *prometheus.Desc
	egressBytes  *prometheus.Desc
	connections  *prometheus.Desc
	activeConns  *prometheus.Desc
	rtt          *prometheus.Desc
	uptime       *prometheus.Desc
}

// NewPromCollector returns a collector that reads metrics via snapshot.
func NewPromCollector(snapshot func() []Snapshot) *PromCollector {
	labels := []string{"domain"}
	return &PromCollector{
		snapshot:     snapshot,
		ingressBytes: prometheus.NewDesc("tcprp_ingress_bytes_total", "Total bytes received from external connections (ingress).", labels, nil),
		egressBytes:  prometheus.NewDesc("tcprp_egress_bytes_total", "Total bytes sent to external connections (egress).", labels, nil),
		connections:  prometheus.NewDesc("tcprp_connections_total", "Total number of connections handled.", labels, nil),
		activeConns:  prometheus.NewDesc("tcprp_active_connections", "Current number of active connections.", labels, nil),
		rtt:          prometheus.NewDesc("tcprp_roundtrip_milliseconds", "Last measured roundtrip latency.", labels, nil),
		uptime:       prometheus.NewDesc("tcprp_uptime_seconds", "Seconds since the proxy started.", labels, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *PromCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ingressBytes
	ch <- c.egressBytes
	ch <- c.connections
	ch <- c.activeConns
	ch <- c.rtt
	ch <- c.uptime
}

// Collect implements prometheus.Collector.
func (c *PromCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.snapshot() {
		if s.Metrics == nil {
			continue
		}
		labels := []string{s.Domain}
		ch <- prometheus.MustNewConstMetric(c.ingressBytes, prometheus.CounterValue, float64(s.Metrics.GetIngressBytes()), labels...)
		ch <- prometheus.MustNewConstMetric(c.egressBytes, prometheus.CounterValue, float64(s.Metrics.GetEgressBytes()), labels...)
		ch <- prometheus.MustNewConstMetric(c.connections, prometheus.CounterValue, float64(s.Metrics.GetConnectionCount()), labels...)
		ch <- prometheus.MustNewConstMetric(c.activeConns, prometheus.GaugeValue, float64(s.Metrics.GetActiveConnections()), labels...)
		ch <- prometheus.MustNewConstMetric(c.rtt, prometheus.GaugeValue, float64(s.Metrics.GetRTT()), labels...)
		ch <- prometheus.MustNewConstMetric(c.uptime, prometheus.GaugeValue, s.Metrics.GetUptime().Seconds(), labels...)
	}
}
