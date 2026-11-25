package services

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/techorionai/constellation-platform-go/executor"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
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
