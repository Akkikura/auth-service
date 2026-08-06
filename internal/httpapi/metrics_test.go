package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsNormalizesUnknownMethods(t *testing.T) {
	metrics := NewMetrics()
	metrics.Observe("ATTACK-ONE", "/login", 405, time.Millisecond)
	metrics.Observe("ATTACK-TWO", "/login", 405, time.Millisecond)

	response := httptest.NewRecorder()
	metrics.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()

	if strings.Contains(body, "ATTACK-") {
		t.Fatalf("untrusted method leaked into metric labels: %s", body)
	}
	if !strings.Contains(body, `method="OTHER",route="/login",status="405"} 2`) {
		t.Fatalf("expected normalized metric, got: %s", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store header")
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	cases := []struct {
		duration time.Duration
		want     string
	}{
		{duration: 0, want: "1"},
		{duration: time.Millisecond, want: "1"},
		{duration: time.Second, want: "1"},
		{duration: time.Second + time.Millisecond, want: "2"},
	}
	for _, test := range cases {
		if got := retryAfterSeconds(test.duration); got != test.want {
			t.Fatalf("retryAfterSeconds(%s) = %s, want %s", test.duration, got, test.want)
		}
	}
}

func TestMetricsCountsPasswordRehashFailures(t *testing.T) {
	metrics := NewMetrics()
	metrics.PasswordRehashFailed(nil)

	response := httptest.NewRecorder()
	metrics.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(response.Body.String(), "auth_service_password_rehash_failures_total 1") {
		t.Fatalf("missing rehash failure metric: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "go_goroutines") {
		t.Fatalf("missing Go runtime metrics: %s", response.Body.String())
	}
}
