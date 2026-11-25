package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// Limits of the rate limit settings.
const (
	MinRateLimit  = 1
	MaxRateLimit  = 1000000
	MinRateWindow = time.Second
	MaxRateWindow = 24 * time.Hour
)

// RateBucket is the config of one rate limit bucket. A field that is not set
// has the default of the bucket.
type RateBucket struct {
	Limit  *int64         `env:"LIMIT"`
	Window *time.Duration `env:"WINDOW"`
}

// RateLimit is the config of the rate limits of the public endpoints. The
// login limiter does not use these settings.
type RateLimit struct {
	Enabled          bool       `env:"ENABLED" envDefault:"true"`
	PublicMeta       RateBucket `envPrefix:"PUBLIC_META__"`
	OAuthPublic      RateBucket `envPrefix:"OAUTH_PUBLIC__"`
	OAuthBackendIP   RateBucket `envPrefix:"OAUTH_BACKEND_IP__"`
	TokenIP          RateBucket `envPrefix:"TOKEN_IP__"`
	IntrospectIP     RateBucket `envPrefix:"INTROSPECT_IP__"`
	TokenClient      RateBucket `envPrefix:"TOKEN_CLIENT__"`
	IntrospectClient RateBucket `envPrefix:"INTROSPECT_CLIENT__"`
	SetupInvite      RateBucket `envPrefix:"SETUP_INVITE__"`
	APITokenCreate   RateBucket `envPrefix:"API_TOKEN_CREATE__"`
	ManifestPublish  RateBucket `envPrefix:"MANIFEST_PUBLISH__"`
}

// DefaultRateRules returns the default rules of all buckets.
func DefaultRateRules() map[string]ratelimit.Rule {
	return map[string]ratelimit.Rule{
		ratelimit.BucketPublicMeta:       {Name: ratelimit.BucketPublicMeta, Limit: 300, Window: time.Minute},
		ratelimit.BucketOAuthPublic:      {Name: ratelimit.BucketOAuthPublic, Limit: 60, Window: time.Minute},
		ratelimit.BucketOAuthBackendIP:   {Name: ratelimit.BucketOAuthBackendIP, Limit: 600, Window: time.Minute},
		ratelimit.BucketTokenIP:          {Name: ratelimit.BucketTokenIP, Limit: 600, Window: time.Minute},
		ratelimit.BucketIntrospectIP:     {Name: ratelimit.BucketIntrospectIP, Limit: 6000, Window: time.Minute},
		ratelimit.BucketTokenClient:      {Name: ratelimit.BucketTokenClient, Limit: 300, Window: time.Minute},
		ratelimit.BucketIntrospectClient: {Name: ratelimit.BucketIntrospectClient, Limit: 6000, Window: time.Minute},
		ratelimit.BucketSetupInvite:      {Name: ratelimit.BucketSetupInvite, Limit: 10, Window: 15 * time.Minute},
		ratelimit.BucketAPITokenCreate:   {Name: ratelimit.BucketAPITokenCreate, Limit: 20, Window: time.Hour},
		ratelimit.BucketManifestPublish:  {Name: ratelimit.BucketManifestPublish, Limit: 60, Window: time.Hour},
	}
}

func (r RateLimit) buckets() map[string]RateBucket {
	return map[string]RateBucket{
		ratelimit.BucketPublicMeta:       r.PublicMeta,
		ratelimit.BucketOAuthPublic:      r.OAuthPublic,
		ratelimit.BucketOAuthBackendIP:   r.OAuthBackendIP,
		ratelimit.BucketTokenIP:          r.TokenIP,
		ratelimit.BucketIntrospectIP:     r.IntrospectIP,
		ratelimit.BucketTokenClient:      r.TokenClient,
		ratelimit.BucketIntrospectClient: r.IntrospectClient,
		ratelimit.BucketSetupInvite:      r.SetupInvite,
		ratelimit.BucketAPITokenCreate:   r.APITokenCreate,
		ratelimit.BucketManifestPublish:  r.ManifestPublish,
	}
}

// Rules returns the rule of each bucket. A value that is not set has the
// default.
func (r RateLimit) Rules() map[string]ratelimit.Rule {
	rules := DefaultRateRules()
	for name, b := range r.buckets() {
		rule := rules[name]
		if b.Limit != nil {
			rule.Limit = *b.Limit
		}
		if b.Window != nil {
			rule.Window = *b.Window
		}
		rules[name] = rule
	}
	return rules
}

// Validate checks the limits and the windows. Each error names its variable.
func (r RateLimit) Validate() []error {
	var errs []error
	buckets := r.buckets()
	for _, name := range ratelimit.Buckets() {
		b := buckets[name]
		upper := strings.ToUpper(name)
		if b.Limit != nil && (*b.Limit < MinRateLimit || *b.Limit > MaxRateLimit) {
			errs = append(errs, fmt.Errorf("%sRATE_LIMIT__%s__LIMIT must be from %d to %d", Prefix, upper, MinRateLimit, MaxRateLimit))
		}
		if b.Window != nil && (*b.Window < MinRateWindow || *b.Window > MaxRateWindow) {
			errs = append(errs, fmt.Errorf("%sRATE_LIMIT__%s__WINDOW must be from %s to %s", Prefix, upper, MinRateWindow, MaxRateWindow))
		}
	}
	return errs
}
