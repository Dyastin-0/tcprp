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
// counters in Metrics to Prometheus metrics, one series per proxy domain,
// plus global unknown-SNI and blocklist statistics.
type PromCollector struct {
	snapshot func() []Snapshot
	stats    func() Stats

	ingressBytes *prometheus.Desc
	egressBytes  *prometheus.Desc
	connections  *prometheus.Desc
	activeConns  *prometheus.Desc
	rtt          *prometheus.Desc
	uptime       *prometheus.Desc

	httpRequests      *prometheus.Desc
	httpResponses     *prometheus.Desc
	httpDurationSum   *prometheus.Desc
	httpDurationCount *prometheus.Desc
	backendErrors     *prometheus.Desc

	unknownTotal   *prometheus.Desc
	unknownUnique  *prometheus.Desc
	unknownSeen    *prometheus.Desc
	blockedUnknown *prometheus.Desc
	blockedRule    *prometheus.Desc
}

// NewPromCollector returns a collector that reads per-domain metrics via
// snapshot and global statistics via stats.
func NewPromCollector(snapshot func() []Snapshot, stats func() Stats) *PromCollector {
	labels := []string{"domain"}
	return &PromCollector{
		snapshot:          snapshot,
		stats:             stats,
		ingressBytes:      prometheus.NewDesc("tcprp_ingress_bytes_total", "Total bytes received from external connections (ingress).", labels, nil),
		egressBytes:       prometheus.NewDesc("tcprp_egress_bytes_total", "Total bytes sent to external connections (egress).", labels, nil),
		connections:       prometheus.NewDesc("tcprp_connections_total", "Total number of connections handled.", labels, nil),
		activeConns:       prometheus.NewDesc("tcprp_active_connections", "Current number of active connections.", labels, nil),
		rtt:               prometheus.NewDesc("tcprp_roundtrip_milliseconds", "Last measured roundtrip latency.", labels, nil),
		uptime:            prometheus.NewDesc("tcprp_uptime_seconds", "Seconds since the proxy started.", labels, nil),
		httpRequests:      prometheus.NewDesc("tcprp_http_requests_total", "Total HTTP requests handled.", labels, nil),
		httpResponses:     prometheus.NewDesc("tcprp_http_responses_total", "HTTP responses by status class.", []string{"domain", "class"}, nil),
		httpDurationSum:   prometheus.NewDesc("tcprp_http_request_duration_seconds_sum", "Total time spent serving HTTP requests.", labels, nil),
		httpDurationCount: prometheus.NewDesc("tcprp_http_request_duration_seconds_count", "Number of timed HTTP requests.", labels, nil),
		backendErrors:     prometheus.NewDesc("tcprp_backend_errors_total", "Failures dialing or communicating with a backend.", labels, nil),
		unknownTotal:      prometheus.NewDesc("tcprp_unknown_sni_total", "Connections whose SNI matched no configured proxy.", nil, nil),
		unknownUnique:     prometheus.NewDesc("tcprp_unknown_sni_unique", "Distinct unknown SNIs tracked since start (capped).", nil, nil),
		unknownSeen:       prometheus.NewDesc("tcprp_unknown_sni_seen", "Connections per unknown SNI (capped set).", []string{"sni"}, nil),
		blockedUnknown:    prometheus.NewDesc("tcprp_blocked_unknown_total", "Connections rejected because their SNI was unknown.", nil, nil),
		blockedRule:       prometheus.NewDesc("tcprp_blocked_connections_total", "Connections rejected by a blocklist rule.", []string{"rule"}, nil),
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
	ch <- c.httpRequests
	ch <- c.httpResponses
	ch <- c.httpDurationSum
	ch <- c.httpDurationCount
	ch <- c.backendErrors
	ch <- c.unknownTotal
	ch <- c.unknownUnique
	ch <- c.unknownSeen
	ch <- c.blockedUnknown
	ch <- c.blockedRule
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

		requests := s.Metrics.GetHTTPRequests()
		ch <- prometheus.MustNewConstMetric(c.httpRequests, prometheus.CounterValue, float64(requests), labels...)

		classes := []string{"1xx", "2xx", "3xx", "4xx", "5xx"}
		for i, count := range s.Metrics.GetHTTPStatusCounts() {
			ch <- prometheus.MustNewConstMetric(c.httpResponses, prometheus.CounterValue, float64(count), s.Domain, classes[i])
		}

		ch <- prometheus.MustNewConstMetric(c.httpDurationSum, prometheus.CounterValue, s.Metrics.GetHTTPDuration().Seconds(), labels...)
		ch <- prometheus.MustNewConstMetric(c.httpDurationCount, prometheus.CounterValue, float64(requests), labels...)
		ch <- prometheus.MustNewConstMetric(c.backendErrors, prometheus.CounterValue, float64(s.Metrics.GetBackendErrors()), labels...)
	}

	st := c.stats()
	ch <- prometheus.MustNewConstMetric(c.unknownTotal, prometheus.CounterValue, float64(st.UnknownTotal))
	ch <- prometheus.MustNewConstMetric(c.unknownUnique, prometheus.GaugeValue, float64(st.UnknownUnique))
	for _, entry := range st.UnknownEntries {
		ch <- prometheus.MustNewConstMetric(c.unknownSeen, prometheus.GaugeValue, float64(entry.Count), entry.SNI)
	}
	ch <- prometheus.MustNewConstMetric(c.blockedUnknown, prometheus.CounterValue, float64(st.BlockedUnknown))
	for _, rule := range st.Blocked {
		ch <- prometheus.MustNewConstMetric(c.blockedRule, prometheus.CounterValue, float64(rule.Hits), rule.Pattern)
	}
}
