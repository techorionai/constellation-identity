package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/techorionai/constellation-identity/resources/test/mock"
)

func deniedDrops(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "identity.audit.denied_dropped" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				r, _ := dp.Attributes.Value("reason")
				got[r.AsString()] += dp.Value
			}
		}
	}
	return got
}

func withReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	old := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(old) })
	return reader
}

// Issue29_U11: a drop of the admin_denied step adds 1 to the counter.
func TestIssue29_U11_AdminDeniedCounter(t *testing.T) {
	reader := withReader(t)
	ev, rl := &mock.Events{}, &mock.RateLimiter{DenyRules: map[string]bool{"admin_denied": true}}
	rec := call(deniedServer(t, ev, rl, "identity:user:read"), http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := deniedDrops(t, reader); got["rate_limit_admin_denied"] != 1 || len(got) != 1 {
		t.Fatalf("drops = %v", got)
	}
}

// Issue29_U17: a drop of the fallback limit of the step adds 1 to the counter.
func TestIssue29_U17_AdminFallbackCounter(t *testing.T) {
	reader := withReader(t)
	ev, rl := &mock.Events{}, &mock.RateLimiter{Err: errors.New("down")}
	h := deniedServer(t, ev, rl, "identity:user:read")
	for i := range 11 {
		rec := call(h, http.MethodPatch, "/v1/users/u1", "ok", `{"name":"x"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("request %d: status = %d", i, rec.Code)
		}
	}
	if got := deniedDrops(t, reader); got["fallback_limit"] != 1 || len(got) != 1 {
		t.Fatalf("drops = %v", got)
	}
	if len(ev.Audits) != 10 {
		t.Fatalf("entries = %d, want 10", len(ev.Audits))
	}
}
