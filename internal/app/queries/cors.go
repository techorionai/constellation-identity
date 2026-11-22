package queries

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/clients"
)

// DefaultCORSCacheTTL is the time that an instance keeps the set of the CORS
// origins. A change of a public client by the API on one instance is active on
// all instances in this time or less.
const DefaultCORSCacheTTL = 5 * time.Second

// CORSOrigins decides which origins may call the token, revoke, and userinfo
// endpoints from a browser. The allowed origins are the origins of the login
// redirect URIs of the public clients that are not disabled.
type CORSOrigins struct {
	repo clients.Repository
	ttl  time.Duration
	now  func() time.Time
	log  *slog.Logger

	mu     sync.Mutex
	uris   []string
	loaded time.Time
	ok     bool
}

// NewCORSOrigins makes the query. A ttl of 0 reads the database for each call.
func NewCORSOrigins(repo clients.Repository, ttl time.Duration, now func() time.Time, log *slog.Logger) *CORSOrigins {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &CORSOrigins{repo: repo, ttl: ttl, now: now, log: log}
}

func (c *CORSOrigins) registered(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok && c.ttl > 0 && c.now().Sub(c.loaded) < c.ttl {
		return c.uris, nil
	}
	uris, err := c.repo.LoginRedirectURIs(ctx)
	if err != nil {
		return nil, err
	}
	c.uris, c.loaded, c.ok = uris, c.now(), true
	return uris, nil
}

// Allowed reports whether the origin matches a registered login redirect URI.
// An error of the database gives false (fail closed).
func (c *CORSOrigins) Allowed(ctx context.Context, origin string) bool {
	uris, err := c.registered(ctx)
	if err != nil {
		c.log.WarnContext(ctx, "read the CORS origins", "error", err)
		return false
	}
	return domain.OriginAllowed(uris, origin)
}
