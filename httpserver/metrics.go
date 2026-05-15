package httpserver

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics holds the Prometheus collectors registered for jwtsmithd request observability.
type metrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// newMetrics builds and registers the standard request metrics on reg.
//
// Counter labels: path, method, status. Histogram labels: path, method.
func newMetrics(reg prometheus.Registerer) *metrics {

	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "jwtsmith",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total HTTP requests processed by jwtsmithd, partitioned by path, method, and status.",
		}, []string{"path", "method", "status"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "jwtsmith",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request handler duration in seconds, partitioned by path and method.",
			Buckets:   prometheus.ExponentialBuckets(0.0005, 2, 14),
		}, []string{"path", "method"}),
	}
	reg.MustRegister(m.requests, m.duration)
	return m
}

// observe records a single request's outcome.
func (m *metrics) observe(path, method string, status int, dur time.Duration) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(path, method, strconv.Itoa(status)).Inc()
	m.duration.WithLabelValues(path, method).Observe(dur.Seconds())
}

// instrument wraps next so each handled request updates m.
//
// Panics on construction if m is nil — required for instrumented routes.
func instrument(m *metrics, next http.Handler) http.Handler {

	if m == nil {
		panic("instrument: metrics required")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.observe(routePath(r), r.Method, rec.status, time.Since(start))
	})
}

// routePath returns the URL path used for metric labeling.
//
// Uses r.Pattern when available (Go 1.22+ ServeMux records the matched pattern), else
// r.URL.Path. Pattern keeps the cardinality bounded — without it, paths with variable
// segments could explode the label set.
func routePath(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.URL.Path
}

// metricsHandler returns an http.Handler serving the given registry's metrics.
func metricsHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
}
