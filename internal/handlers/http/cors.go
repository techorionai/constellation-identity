package httpapi

import (
	"context"
	"net/http"
)

// CORSOrigins decides if a browser origin may call the endpoints that public
// clients use.
type CORSOrigins interface {
	Allowed(ctx context.Context, origin string) bool
}

// corsPaths are the endpoints that answer CORS requests.
var corsPaths = map[string]bool{"/oauth/token": true, "/oauth/revoke": true, "/oauth/userinfo": true}

// cors answers the CORS requests of the token, revoke, and userinfo endpoints.
// An allowed origin gets the headers. Another origin gets none. All responses
// have Vary: Origin. The service sends no Access-Control-Allow-Credentials.
func cors(origins CORSOrigins, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origins == nil || !corsPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		allowed := origin != "" && origins.Allowed(r.Context(), origin)
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		if r.Method == http.MethodOptions {
			if allowed {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
