package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	requests               *prometheus.CounterVec
	duration               *prometheus.HistogramVec
	passwordRehashFailures prometheus.Counter
	handler                http.Handler
}

func NewMetrics() *Metrics {
	// TODO свой registry чтобы тесты не мешали друг другу
	registry := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "auth_service",
			Name:      "http_requests_total",
			Help:      "Total HTTP requests.",
		},
		[]string{"method", "route", "status"},
	)
	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "auth_service",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "route", "status"},
	)
	rehashFailures := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "auth_service",
		Name:      "password_rehash_failures_total",
		Help:      "Password rehash attempts that failed after successful authentication.",
	})
	registry.MustRegister(
		requests,
		duration,
		rehashFailures,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return &Metrics{
		requests:               requests,
		duration:               duration,
		passwordRehashFailures: rehashFailures,
		handler:                promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	}
}

func (m *Metrics) Observe(method, route string, status int, duration time.Duration) {
	labels := []string{normalizeMethod(method), route, strconv.Itoa(status)}
	m.requests.WithLabelValues(labels...).Inc()
	m.duration.WithLabelValues(labels...).Observe(duration.Seconds())
}

func (m *Metrics) PasswordRehashFailed(error) {
	m.passwordRehashFailures.Inc()
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	m.handler.ServeHTTP(w, r)
}

func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}
