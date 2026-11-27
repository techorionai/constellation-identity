package services

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/techorionai/constellation-platform-go/executor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
	"github.com/techorionai/constellation-identity/internal/ports/manifests"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// U12: with RATE_LIMIT__ENABLED=false, the service makes no limiter checker and
// writes one warn record.
func TestU12_RateLimitDisabled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	rl := &mock.RateLimiter{}
	cfg := config.Config{RateLimit: config.RateLimit{Enabled: false}}
	limits, err := newRateLimits(cfg, options{}, rl, log)
	if err != nil || limits != nil {
		t.Fatalf("limits = %v, err = %v, want nil", limits, err)
	}
	if err := limits.Check(context.Background(), "token_ip", "k"); err != nil || len(rl.Calls) != 0 {
		t.Fatalf("err = %v, calls = %v, want no call", err, rl.Calls)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("warn records = %d, want 1: %s", n, buf.String())
	}
}

type limitedExec struct{ err error }

func (e limitedExec) Execute(context.Context, struct{}) (int, error) { return 0, e.err }

// U13: a request that a rate limit stops is not a span error and not an error
// log record. It has the log level info.
func TestU13_RateLimitedIsNotAFailure(t *testing.T) {
	limited := apperrors.NewOAuthRateLimited("token_client", 7e9)
	for name, classify := range map[string]func(error) bool{
		"issue": issueSpanError, "oauth": oauthSpanError, "publish": rateLimitClassifier,
	} {
		if classify(limited) || (name == "publish" && classify(&apperrors.RateLimitedError{})) {
			t.Errorf("%s: a rate limited request must not be a failure", name)
		}
	}
	if !oauthSpanError(apperrors.NewOAuthLimiterUnavailable(errors.New("down"))) ||
		!issueSpanError(apperrors.NewOAuthLimiterUnavailable(errors.New("down"))) {
		t.Error("an unavailable limiter must be a failure")
	}
	if errorLevel(&apperrors.RateLimitedError{}) != slog.LevelInfo || userErrorLevel(&apperrors.RateLimitedError{}) != slog.LevelInfo {
		t.Error("the log level must be info")
	}
	if !expectedUserError(&apperrors.RateLimitedError{}) {
		t.Error("a rate limited request is an expected user error")
	}
	if errorLevel(apperrors.ErrRateLimiterUnavailable) != slog.LevelError {
		t.Error("an unavailable limiter is an error")
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	var e executor.ExecutorWithReturn[struct{}, int] = limitedExec{err: &apperrors.RateLimitedError{Bucket: "api_token_create"}}
	e = withObservability(e, "PublishManifest", log)
	if _, err := e.Execute(context.Background(), struct{}{}); !errors.Is(err, apperrors.ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(buf.String(), "level=ERROR") || !strings.Contains(buf.String(), "level=INFO") {
		t.Fatalf("log = %s", buf.String())
	}
}

type stubClients struct{ clients.Repository }

type stubManifests struct{ manifests.Repository }

type oauthExec struct{ err error }

func (e oauthExec) Execute(context.Context, struct{}) (int, error) { return 0, e.err }

// spanStatuses runs fn with an in-memory tracer provider and returns the spans.
func spanStatuses(t *testing.T, fn func()) []sdktrace.ReadOnlySpan {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	fn()
	return exp.GetSpans().Snapshots()
}

// R1: the real decorators of the service wiring. A request that a rate limit
// stops has no span error and no error log record. An unavailable limiter has
// both.
func TestR1_RealDecoratorsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	limits, err := commands.NewRateLimits(commands.RateLimitsDeps{
		Limiter: &mock.RateLimiter{Deny: true}, Rules: config.DefaultRateRules(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	in := commands.PublishManifest{
		PathApp: "helpdesk", CallerClientID: "helpdesk", CallerIsService: true, PublishedBy: "helpdesk",
		Manifest: domain.Manifest{App: "helpdesk"},
	}
	limited := apperrors.NewOAuthRateLimited("token_client", 7e9)
	unavailable := apperrors.NewOAuthLimiterUnavailable(errors.New("down"))
	spans := spanStatuses(t, func() {
		publish := newPublishAPI(stubManifests{}, stubClients{}, limits, mock.Tx{}, &mock.Events{}, log)
		if _, err := publish.Execute(context.Background(), in); !errors.Is(err, apperrors.ErrRateLimited) {
			t.Errorf("publish: err = %v, want rate limited", err)
		}
		for name, e := range map[string]executor.ExecutorWithReturn[struct{}, int]{
			"issue":      traceIssue[struct{}, int](oauthExec{err: limited}),
			"introspect": traceOAuth[struct{}, int](oauthExec{err: limited}, "Introspect"),
			"exchange":   traceOAuth[struct{}, int](oauthExec{err: limited}, "TokenExchange"),
		} {
			if _, err := e.Execute(context.Background(), struct{}{}); err == nil {
				t.Errorf("%s: want an error", name)
			}
		}
	})
	if len(spans) != 4 {
		t.Fatalf("spans = %d, want 4", len(spans))
	}
	for _, sp := range spans {
		if sp.Status().Code == codes.Error {
			t.Errorf("span %s is an error span", sp.Name())
		}
	}
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("error log record for a rate limited request: %s", buf.String())
	}
	spans = spanStatuses(t, func() {
		_, _ = traceIssue[struct{}, int](oauthExec{err: unavailable}).Execute(context.Background(), struct{}{})
		_, _ = traceOAuth[struct{}, int](oauthExec{err: unavailable}, "Introspect").Execute(context.Background(), struct{}{})
	})
	if len(spans) != 2 || spans[0].Status().Code != codes.Error || spans[1].Status().Code != codes.Error {
		t.Errorf("an unavailable limiter must be a span error: %v", spans)
	}
}
