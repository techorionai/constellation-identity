package httpapi

import (
	"context"
	"net/http"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/ports/ratelimit"
)

// DeniedRecorder writes the audit entry of an admin request that the scope
// check denied.
type DeniedRecorder interface {
	Record(ctx context.Context, action string, missingScopes []string) error
}

// adminActions gives the audit action of each admin route. The admin routes
// are all /v1 routes except the routes of the own account (/v1/me). A route of
// the scope table that has no entry here is a test failure.
var adminActions = map[string]string{
	"POST /v1/agents":                                     "identity:agent:create",
	"GET /v1/agents":                                      "identity:agent:read",
	"GET /v1/agents/{agentId}":                            "identity:agent:read",
	"PATCH /v1/agents/{agentId}":                          "identity:agent:update",
	"GET /v1/agents/{agentId}/roles":                      "identity:agent_role:read",
	"PUT /v1/agents/{agentId}/roles/{role}":               "identity:agent_role:assign",
	"DELETE /v1/agents/{agentId}/roles/{role}":            "identity:agent_role:remove",
	"DELETE /v1/api-tokens/{tokenId}":                     "identity:api_token:revoke",
	"POST /v1/clients":                                    "identity:client:create",
	"GET /v1/clients":                                     "identity:client:read",
	"GET /v1/clients/{clientId}":                          "identity:client:read",
	"PATCH /v1/clients/{clientId}":                        "identity:client:update",
	"POST /v1/clients/{clientId}/keys":                    "identity:client_key:add",
	"DELETE /v1/clients/{clientId}/keys/{kid}":            "identity:client_key:remove",
	"GET /v1/clients/{clientId}/roles":                    "identity:client_role:read",
	"PUT /v1/clients/{clientId}/roles/{role}":             "identity:client_role:assign",
	"DELETE /v1/clients/{clientId}/roles/{role}":          "identity:client_role:remove",
	"GET /v1/permission-manifests":                        "identity:manifest:read",
	"PUT /v1/permission-manifests/{app}":                  "identity:manifest:publish",
	"GET /v1/permission-manifests/{app}":                  "identity:manifest:read",
	"GET /v1/roles":                                       "identity:role:read",
	"GET /v1/roles/{role}":                                "identity:role:read",
	"DELETE /v1/sessions/{sessionId}":                     "identity:session:revoke",
	"POST /v1/users":                                      "identity:user:create",
	"GET /v1/users":                                       "identity:user:read",
	"GET /v1/users/{userId}":                              "identity:user:read",
	"PATCH /v1/users/{userId}":                            "identity:user:update",
	"GET /v1/users/{userId}/api-tokens":                   "identity:api_token:read",
	"GET /v1/users/{userId}/identity-links":               "identity:identity_link:read",
	"DELETE /v1/users/{userId}/identity-links/{provider}": "identity:identity_link:remove",
	"POST /v1/users/{userId}/invites":                     "identity:invite:create",
	"GET /v1/users/{userId}/mfa":                          "identity:mfa:read",
	"DELETE /v1/users/{userId}/mfa":                       "identity:mfa:reset",
	"GET /v1/users/{userId}/passkeys":                     "identity:passkey:read",
	"GET /v1/users/{userId}/roles":                        "identity:user_role:read",
	"PUT /v1/users/{userId}/roles/{role}":                 "identity:user_role:assign",
	"DELETE /v1/users/{userId}/roles/{role}":              "identity:user_role:remove",
	"GET /v1/users/{userId}/sessions":                     "identity:session:read",
	"DELETE /v1/users/{userId}/sessions":                  "identity:session:revoke_all",
}

// auditDenied is the step of an admin route between the token check and the
// scope check. If the principal does not have all scopes of the route, it
// writes the audit entry with the result denied. Then it passes the request to
// the scope check, which answers 403. The step does not read the response
// status.
//
// A rate limit (the bucket admin_denied, with the principal ID as key) comes
// first. A request over the limit gets 429 and writes no entry. If the limiter
// does not answer, the step writes the entry (fail open). The 403 does not
// depend on the limiter. If the entry cannot be written, the step writes a log
// record and the request still gets the 403.
func (s *Server) auditDenied(pattern string, scopes []string, next http.Handler) http.Handler {
	action, admin := adminActions[pattern]
	if !admin || s.d.Denied == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := auth.PrincipalFromContext(r.Context())
		if !ok || p.HasScopes(scopes...) {
			next.ServeHTTP(w, r)
			return
		}
		if err := s.d.RateLimits.CheckOpen(r.Context(), ratelimit.BucketAdminDenied, p.ID); err != nil {
			s.writeRateError(w, r, err)
			return
		}
		if err := s.d.Denied.Record(r.Context(), action, p.MissingScopes(scopes...)); err != nil {
			s.log.ErrorContext(r.Context(), "identity.audit.denied_failed", "event", "identity.audit.denied_failed", "action", action, "error", err)
		}
		next.ServeHTTP(w, r)
	})
}
