package commands

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// The outcomes of a rate limit check. They are the values of the attribute
// outcome of the counter identity.rate_limit.decisions.
const (
	RateOutcomeAllowed  = "allowed"
	RateOutcomeLimited  = "limited"
	RateOutcomeError    = "error"
	RateOutcomeFailOpen = "fail_open"
)

// RateLimitsDeps are the dependencies of RateLimits.
type RateLimitsDeps struct {
	Limiter ratelimit.Limiter
	// Rules has the rule of each bucket.
	Rules map[string]ratelimit.Rule
	Log   *slog.Logger
}

// RateLimits checks the rate limit buckets. A nil *RateLimits does not limit.
// The service uses a nil value when the setting RATE_LIMIT__ENABLED is false.
type RateLimits struct {
	d         RateLimitsDeps
	decisions metric.Int64Counter
}

// NewRateLimits makes the checker. Each bucket must have a rule.
func NewRateLimits(d RateLimitsDeps) (*RateLimits, error) {
	if d.Limiter == nil {
		return nil, fmt.Errorf("make the rate limits: no limiter")
	}
	for _, name := range ratelimit.Buckets() {
		if _, ok := d.Rules[name]; !ok {
			return nil, fmt.Errorf("make the rate limits: no rule for the bucket %s", name)
		}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	c, err := otel.Meter("identity").Int64Counter("identity.rate_limit.decisions",
		metric.WithDescription("Rate limit decisions by bucket and outcome."))
	if err != nil {
		return nil, fmt.Errorf("make the rate limit counter: %w", err)
	}
	return &RateLimits{d: d, decisions: c}, nil
}

func (r *RateLimits) count(ctx context.Context, bucket, outcome string) {
	r.decisions.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("bucket", bucket), attribute.String("outcome", outcome)))
}

// Check counts one request in the bucket. If the limit is passed, it returns a
// *apperrors.RateLimitedError. If the limiter gives an error, it returns an
// error that wraps apperrors.ErrRateLimiterUnavailable (fail closed).
func (r *RateLimits) Check(ctx context.Context, bucket, key string) error {
	return r.check(ctx, bucket, key, false)
}

// CheckOpen is like Check, but a limiter error is not an error of the request
// (fail open).
func (r *RateLimits) CheckOpen(ctx context.Context, bucket, key string) error {
	return r.check(ctx, bucket, key, true)
}

// CoarseFactor is the multiplier of the limit of a bucket for a coarse key.
// A coarse key is the /48 prefix of an IPv6 client.
const CoarseFactor = 16

// CheckIP counts one request of a client IP. The key is the key of the client
// (an IPv4 address or an IPv6 /64 prefix). The coarse key is the IPv6 /48
// prefix, or an empty string. The coarse key has a limit that is CoarseFactor
// times the limit of the bucket. It is checked first. A request over the coarse
// limit gets the error and does not make a new key for its /64 prefix. Thus one
// /48 prefix can make only a limited number of keys in one window.
func (r *RateLimits) CheckIP(ctx context.Context, bucket, key, coarseKey string, failOpen bool) error {
	if coarseKey != "" {
		if err := r.checkRule(ctx, bucket, coarseKey, failOpen, CoarseFactor, false); err != nil {
			return err
		}
	}
	return r.checkRule(ctx, bucket, key, failOpen, 1, false)
}

func (r *RateLimits) check(ctx context.Context, bucket, key string, failOpen bool) error {
	return r.checkRule(ctx, bucket, key, failOpen, 1, false)
}

func (r *RateLimits) checkRule(ctx context.Context, bucket, key string, failOpen bool, factor int64, quiet bool) error {
	if r == nil {
		return nil
	}
	rule := r.d.Rules[bucket]
	rule.Limit *= factor
	dec, err := r.d.Limiter.Allow(ctx, rule, key)
	if err != nil {
		// The log record has the bucket and the error. It has no key.
		r.d.Log.ErrorContext(ctx, "identity.rate_limit.unavailable", "event", "identity.rate_limit.unavailable",
			"bucket", bucket, "fail_open", failOpen, "error", err)
		if failOpen {
			r.count(ctx, bucket, RateOutcomeFailOpen)
			return nil
		}
		r.count(ctx, bucket, RateOutcomeError)
		return fmt.Errorf("%w: %w", apperrors.ErrRateLimiterUnavailable, err)
	}
	if !dec.Allowed {
		r.count(ctx, bucket, RateOutcomeLimited)
		if !quiet {
			r.d.Log.InfoContext(ctx, "identity.rate_limit.limited", "event", "identity.rate_limit.limited", "bucket", bucket)
		}
		return &apperrors.RateLimitedError{Bucket: bucket, RetryAfter: dec.RetryAfter}
	}
	r.count(ctx, bucket, RateOutcomeAllowed)
	return nil
}

// oauthRateError maps the error of a bucket check to an OAuth error. It returns
// nil for a nil error.
func oauthRateError(err error) error {
	if err == nil {
		return nil
	}
	if re, ok := apperrors.AsRateLimited(err); ok {
		return apperrors.NewOAuthRateLimited(re.Bucket, re.RetryAfter)
	}
	return apperrors.NewOAuthLimiterUnavailable(err)
}

// CheckQuiet is like Check, but a refusal does not write the log record
// identity.rate_limit.limited. It still counts the decision. The gate of the
// denied token entries uses it, because it has its own log rule.
func (r *RateLimits) CheckQuiet(ctx context.Context, bucket, key string) error {
	return r.checkRule(ctx, bucket, key, false, 1, true)
}

// CheckIPQuiet is like CheckIP with fail closed, but a refusal does not write
// the log record identity.rate_limit.limited.
func (r *RateLimits) CheckIPQuiet(ctx context.Context, bucket, key, coarseKey string) error {
	if coarseKey != "" {
		if err := r.checkRule(ctx, bucket, coarseKey, false, CoarseFactor, true); err != nil {
			return err
		}
	}
	return r.checkRule(ctx, bucket, key, false, 1, true)
}
