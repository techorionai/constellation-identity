// Package ratelimit is the port of the shared request rate limiter.
package ratelimit

import (
	"context"
	"time"
)

// Rule is the limit of one bucket.
type Rule struct {
	// Name is the bucket name, for example "token_ip".
	Name   string
	Limit  int64
	Window time.Duration
}

// Decision is the result of one Allow call.
type Decision struct {
	Allowed bool
	Count   int64
	// RetryAfter is set when Allowed is false.
	RetryAfter time.Duration
}

// Limiter counts requests in a fixed window.
type Limiter interface {
	// Allow counts one request for key in the fixed window of rule. An error
	// means the counters are not available.
	Allow(ctx context.Context, rule Rule, key string) (Decision, error)
}

// The names of the buckets.
const (
	BucketPublicMeta       = "public_meta"
	BucketOAuthPublic      = "oauth_public"
	BucketOAuthBackendIP   = "oauth_backend_ip"
	BucketTokenIP          = "token_ip"
	BucketIntrospectIP     = "introspect_ip"
	BucketTokenClient      = "token_client"
	BucketIntrospectClient = "introspect_client"
	BucketSetupInvite      = "setup_invite"
	BucketAPITokenCreate   = "api_token_create"
	BucketManifestPublish  = "manifest_publish"
	BucketMFAVerify        = "mfa_verify"
	BucketPasskey          = "passkey"
	BucketIdp              = "idp"
	// BucketAdminDenied limits the audit entries of the admin requests that the
	// scope check denies. The key is the principal ID.
	BucketAdminDenied = "admin_denied"
)

// Buckets lists the names of all buckets.
func Buckets() []string {
	return []string{
		BucketPublicMeta, BucketOAuthPublic, BucketOAuthBackendIP, BucketTokenIP, BucketIntrospectIP,
		BucketTokenClient, BucketIntrospectClient, BucketSetupInvite, BucketAPITokenCreate, BucketManifestPublish,
		BucketMFAVerify, BucketPasskey, BucketIdp, BucketAdminDenied,
	}
}
