// Package services is the composition root. It makes all adapters and use
// cases and connects them.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/techorionai/constellation-platform-go/auth/jwt"
	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	"github.com/techorionai/constellation-platform-go/decorators"
	"github.com/techorionai/constellation-platform-go/health"
	healthpg "github.com/techorionai/constellation-platform-go/health/postgres"
	healthvk "github.com/techorionai/constellation-platform-go/health/valkey"
	"github.com/techorionai/constellation-platform-go/migrate"
	migratepg "github.com/techorionai/constellation-platform-go/migrate/postgres"
	"github.com/techorionai/constellation-platform-go/requestid"
	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"
	secretspg "github.com/techorionai/constellation-platform-go/secrets/postgres"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/api/openapi"
	adapterjose "github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	adaptersecrets "github.com/techorionai/constellation-identity/internal/adapters/secrets"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/keys"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	httpapi "github.com/techorionai/constellation-identity/internal/handlers/http"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
	"github.com/techorionai/constellation-identity/internal/ports/privatekeys"
	"github.com/techorionai/constellation-identity/migrations"
)

// Default intervals of the key loops.
const (
	defaultKeyManagerInterval = 10 * time.Minute
	defaultCacheInterval      = time.Minute
)

// ErrMasterKeyMismatch means the active signing key does not decrypt.
var ErrMasterKeyMismatch = errors.New("the active signing key does not decrypt with the master key")

type options struct {
	managerInterval time.Duration
	cacheInterval   time.Duration
	policy          *domain.KeyPolicy
	log             *slog.Logger
	// hashMemoryKiB and hashTime change the argon2id parameters. Zero means the
	// default.
	hashMemoryKiB  uint32
	hashTime       uint32
	retentionAfter func(time.Duration) <-chan time.Time
	// clock is the clock of the use cases. Nil means time.Now.
	clock func() time.Time
	// corsCacheTTL is the time of the CORS origin cache. Nil means the default.
	corsCacheTTL *time.Duration
}

// Option changes the composition. The options are for tests. Production code
// uses the config.
type Option func(*options)

// WithKeyIntervals sets the interval of the key manager and the interval of the
// key cache reload.
func WithKeyIntervals(manager, cache time.Duration) Option {
	return func(o *options) { o.managerInterval, o.cacheInterval = manager, cache }
}

// WithKeyPolicy sets the key policy. It does not go through the config checks.
func WithKeyPolicy(p domain.KeyPolicy) Option { return func(o *options) { o.policy = &p } }

// WithLogger sets the logger of the service.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.log = l } }

// WithPasswordCost sets the memory (in KiB) and the number of passes of the
// argon2id hash. A test uses a small cost to be fast. Production code uses the
// default.
func WithPasswordCost(memoryKiB, passes uint32) Option {
	return func(o *options) { o.hashMemoryKiB, o.hashTime = memoryKiB, passes }
}

// WithRetentionAfter sets the timer function of the retention runner. A test
// uses it to run a tick at once.
func WithRetentionAfter(after func(time.Duration) <-chan time.Time) Option {
	return func(o *options) { o.retentionAfter = after }
}

// WithClock sets the clock of the use cases of the users, the sessions, the
// code flow, and the admin API. A test moves the clock to test the expiry.
func WithClock(now func() time.Time) Option { return func(o *options) { o.clock = now } }

// WithCORSCacheTTL sets the time that an instance keeps the set of the CORS
// origins. A test sets 0 to read the database for each request.
func WithCORSCacheTTL(ttl time.Duration) Option { return func(o *options) { o.corsCacheTTL = &ttl } }

func newOptions(opts []Option) options {
	o := options{managerInterval: defaultKeyManagerInterval, cacheInterval: defaultCacheInterval, log: slog.Default()}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// App is a running service.
type App struct {
	cfg    config.Config
	log    *slog.Logger
	db     *clientpg.Client
	kv     *clientvk.Client
	pgChk  *healthpg.Checker
	state  *health.State
	adminL net.Listener
	admin  *http.Server
	pubL   net.Listener
	pub    *http.Server
	mgr    *keys.Manager
	cache  *keys.Cache
	verify *jwt.Verifier
	reg    metric.Registration

	sessionReg    metric.Registration
	stopRetention context.CancelFunc
	retentionWG   sync.WaitGroup

	serveWG   sync.WaitGroup
	closeOnce sync.Once
}

// PublicAddr returns the address of the public listener.
func (a *App) PublicAddr() string { return a.pubL.Addr().String() }

// AdminAddr returns the address of the admin listener.
func (a *App) AdminAddr() string { return a.adminL.Addr().String() }

type funcChecker struct {
	name string
	fn   func() error
}

func (c funcChecker) Name() string                { return c.name }
func (c funcChecker) Check(context.Context) error { return c.fn() }

// Start runs the startup order of the service and returns when the service is
// ready. On an error it releases everything that it made.
func Start(ctx context.Context, cfg config.Config, opts ...Option) (_ *App, err error) {
	o := newOptions(opts)
	log := o.log
	a := &App{cfg: cfg, log: log}
	defer func() {
		if err != nil {
			a.release(context.WithoutCancel(ctx))
		}
	}()

	// The clients file errors stop the start before any connection. So do the
	// scope table check and the check of the own manifest.
	clientConfigs, err := config.LoadClientsFile(cfg.ClientsFile)
	if err != nil {
		return nil, err
	}
	scopes, err := httpapi.NewScopeTable(openapi.Spec)
	if err != nil {
		return nil, err
	}
	ownManifest, err := loadOwnManifest()
	if err != nil {
		return nil, err
	}

	// 1. Connect to PostgreSQL and Valkey.
	if a.db, err = clientpg.New(ctx, cfg.Database); err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	if a.kv, err = clientvk.New(ctx, cfg.Valkey); err != nil {
		return nil, fmt.Errorf("connect to Valkey: %w", err)
	}
	if a.pgChk, err = healthpg.NewChecker(ctx, a.db.Pool); err != nil {
		return nil, fmt.Errorf("make PostgreSQL checker: %w", err)
	}

	// 2. Start the admin server. /livez is 200. /readyz is 503.
	var migrated atomic.Bool
	secretRepo := secretspg.NewRepository(a.db.Pool)
	ring, err := platformsecrets.NewKeyRing(cfg.Secrets)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	store := adaptersecrets.New(platformsecrets.NewService(ring, secretRepo))
	a.cache = keys.NewCache(postgres.NewSigningKeys(a.db.Pool), store, log)
	a.state = health.NewState(
		a.pgChk,
		healthvk.NewChecker(a.kv.Raw),
		funcChecker{"migrations", func() error {
			if !migrated.Load() {
				return errors.New("migrations are not done")
			}
			return nil
		}},
		funcChecker{"signing_key", func() error {
			if !a.cache.HasActive() {
				return errors.New("no active signing key")
			}
			return nil
		}},
	)
	if a.adminL, err = (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Admin.Addr); err != nil {
		return nil, fmt.Errorf("listen on the admin address: %w", err)
	}
	a.admin = &http.Server{
		Handler:           health.NewHandler(a.state, cfg.Admin),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	a.serve(a.admin, a.adminL, "admin")

	// 3. Run the migrations of the secrets store, then of the service.
	if err := RunMigrations(ctx, a.db); err != nil {
		return nil, err
	}
	migrated.Store(true)

	// Publish the own manifest before the public server starts, so that the
	// roles of the identity service exist before the first request.
	clientRepo := postgres.NewClients(a.db.Pool)
	manifestRepo := postgres.NewManifests(a.db.Pool)
	publish := decorators.ApplyTracing(decorators.ApplyLogging(
		commands.NewPublishManifest(manifestRepo, clientRepo, log), "PublishManifest",
		decorators.WithLogger(log), decorators.WithErrorLevel(errorLevel)), "PublishManifest")
	if _, err := publish.Execute(ctx, commands.PublishManifest{
		Manifest: ownManifest, PublishedBy: domain.IdentityApp, Internal: true,
	}); err != nil {
		return nil, fmt.Errorf("publish the own manifest: %w", err)
	}

	// Make the users stack and the first-admin setup token. The own manifest is
	// published already, so the role identity:admin exists.
	users, err := a.buildUsers(o)
	if err != nil {
		return nil, err
	}
	if err := a.ensureSetupToken(ctx, users); err != nil {
		return nil, err
	}

	// 4. Make the key manager and the key cache. Check that the active key
	// decrypts before the manager can change any key.
	signingRepo := postgres.NewSigningKeys(a.db.Pool)
	policy := cfg.Keys.Policy()
	if o.policy != nil {
		policy = *o.policy
	}
	a.mgr = keys.NewManager(signingRepo, store, policy, keys.WithLogger(log))
	if err := a.reloadCache(ctx); err != nil {
		return nil, err
	}
	if err := a.mgr.Run(ctx); err != nil {
		return nil, fmt.Errorf("run the key manager: %w", err)
	}
	if err := a.reloadCache(ctx); err != nil {
		return nil, err
	}
	a.mgr.Start(context.WithoutCancel(ctx), o.managerInterval)
	a.cache.Start(context.WithoutCancel(ctx), o.cacheInterval)
	if err := a.registerMetrics(); err != nil {
		return nil, err
	}
	if err := a.registerSessionGauge(users.sessions); err != nil {
		return nil, err
	}
	retentionCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	a.stopRetention = stop
	a.retentionWG.Add(1)
	go func() {
		defer a.retentionWG.Done()
		_ = users.retention.Run(retentionCtx)
	}()

	// 5. Sync the clients file.
	syncClients := decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[commands.SyncClients](
		commands.NewSyncClients(clientRepo, log), "SyncClients"), "SyncClients")
	if err := syncClients.Execute(ctx, commands.SyncClients{Clients: clientConfigs}); err != nil {
		return nil, fmt.Errorf("sync the clients file: %w", err)
	}

	// 6. Start the public server, then tell the state that the service is ready.
	jwks := decorators.ApplyTracing(decorators.ApplyLogging(
		queries.NewGetJWKS(a.cache), "GetJWKS"), "GetJWKS")
	discovery := decorators.ApplyTracing(decorators.ApplyLogging(
		queries.NewGetDiscovery(cfg.Issuer), "GetDiscovery"), "GetDiscovery")
	if a.verify, err = NewVerifier(cfg.Issuer, a.cache); err != nil {
		return nil, err
	}
	a.verify.Start(context.WithoutCancel(ctx))
	issueCmd, err := commands.NewIssueServiceToken(commands.IssueServiceTokenDeps{
		Issuer:      cfg.Issuer,
		Clients:     clientRepo,
		ClientRoles: postgres.NewClientRoles(a.db.Pool),
		Manifests:   manifestRepo,
		JTI:         postgres.NewJTIStore(a.db.Pool),
		Keys:        a.cache,
		Signer:      adapterjose.Signer{},
		Parser:      adapterjose.AssertionParser{},
		Log:         log,
	})
	if err != nil {
		return nil, err
	}
	// The command writes its own failure log, so it has no logging decorator.
	issue := decorators.ApplyTracing(issueCmd, "IssueServiceToken",
		decorators.WithErrorClassifier(func(err error) bool {
			oe, ok := apperrors.AsOAuthError(err)
			return !ok || oe.Code == apperrors.OAuthServerError
		}))
	listManifests := withObservability(queries.NewListManifests(manifestRepo), "ListManifests", log)
	getManifest := withObservability(queries.NewGetManifest(manifestRepo), "GetManifest", log)
	listRoles := withObservability(queries.NewListRoles(manifestRepo), "ListRoles", log)
	getRole := withObservability(queries.NewGetRole(manifestRepo), "GetRole", log)
	// The revoke endpoint authenticates a service client with the same checks.
	users.oidc.SetServiceAuthenticator(issueCmd)
	introspectCmd, err := commands.NewIntrospect(commands.IntrospectDeps{
		Auth: issueCmd, Tokens: users.apiTokenRepo, UserRoles: users.userRoles, Log: log, Now: o.clock,
	})
	if err != nil {
		return nil, err
	}
	// The command checks the caller and the token. It has no logging decorator,
	// because a log record must not have the token.
	introspect := decorators.ApplyTracing(introspectCmd, "Introspect",
		decorators.WithErrorClassifier(func(err error) bool {
			oe, ok := apperrors.AsOAuthError(err)
			return !ok || oe.Code == apperrors.OAuthServerError || oe.Code == apperrors.OAuthTemporarilyUnavailable
		}))
	exchangeCmd, err := commands.NewTokenExchange(commands.TokenExchangeDeps{
		Issuer: cfg.Issuer, Auth: issueCmd, Clients: clientRepo, ClientRoles: postgres.NewClientRoles(a.db.Pool),
		Manifests: manifestRepo, Users: postgres.NewUsers(a.db.Pool), UserRoles: users.userRoles,
		Agents: postgres.NewAgents(a.db.Pool), AgentRoles: postgres.NewAgentRoles(a.db.Pool),
		Keys: a.cache, Signer: adapterjose.Signer{}, Verifier: adapterjose.Verifier{}, Log: log, Now: o.clock,
	})
	if err != nil {
		return nil, err
	}
	// The command writes its own failure log, so it has no logging decorator.
	exchange := decorators.ApplyTracing(exchangeCmd, "TokenExchange",
		decorators.WithErrorClassifier(func(err error) bool {
			oe, ok := apperrors.AsOAuthError(err)
			return !ok || oe.Code == apperrors.OAuthServerError || oe.Code == apperrors.OAuthTemporarilyUnavailable
		}))
	api := httpapi.New(httpapi.Deps{
		ExchangeToken: exchange,
		JWKS:          jwks, Discovery: discovery, IssueToken: issue, PublishManifest: publish,
		ListManifests: listManifests, GetManifest: getManifest, ListRoles: listRoles, GetRole: getRole,
		ExchangeCode: users.exchangeCode, RefreshTokens: users.refreshTokens, RevokeToken: users.revokeToken, UserInfo: users.userInfo,
		Admin: users.admin, APITokens: users.apiTokens, Introspect: introspect, CreateUser: users.createUser, CreateInvite: users.createInvite, CORSOrigins: users.cors,
		Verifier: a.verify, Scopes: scopes, Log: log,
	})
	// RedactToken is outside the tracing handler, so no span has a secret value
	// of the query. RestoreQuery puts the real query back for the router.
	handler := pages.RedactToken(otelhttp.NewHandler(
		requestid.Middleware()(pages.LogRedirects(log)(pages.RestoreQuery(publicHandler(api.Handler(), users.pages.Routes())))), "identity"))
	if a.pubL, err = (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.HTTP.Addr); err != nil {
		return nil, fmt.Errorf("listen on the public address: %w", err)
	}
	a.pub = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	a.serve(a.pub, a.pubL, "public")
	a.state.MarkStarted()
	return a, nil
}

func (a *App) serve(srv *http.Server, l net.Listener, name string) {
	a.serveWG.Add(1)
	go func() {
		defer a.serveWG.Done()
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("server stopped", "server", name, "error", err)
		}
	}()
}

// reloadCache loads the key cache. A key that does not decrypt gives the
// error of the master key.
func (a *App) reloadCache(ctx context.Context) error {
	err := a.cache.Reload(ctx)
	if errors.Is(err, privatekeys.ErrUndecryptable) {
		//nolint:staticcheck // The text is the message of the plan.
		return fmt.Errorf("%w `%s`. Use the master key of the install, or run `identity rotate-signing-keys --force`.",
			ErrMasterKeyMismatch, a.cfg.Secrets.MasterKeyID)
	}
	if err != nil {
		return fmt.Errorf("load the signing keys: %w", err)
	}
	return nil
}

func (a *App) registerMetrics() error {
	meter := otel.Meter("identity")
	gauge, err := meter.Int64ObservableGauge("identity.signing_keys",
		metric.WithDescription("Signing keys by state."))
	if err != nil {
		return fmt.Errorf("make the signing key gauge: %w", err)
	}
	a.reg, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for state, n := range a.cache.Counts() {
			o.ObserveInt64(gauge, int64(n), metric.WithAttributes(attribute.String("state", string(state))))
		}
		return nil
	}, gauge)
	if err != nil {
		return fmt.Errorf("register the signing key gauge: %w", err)
	}
	return nil
}

// Shutdown stops the service in the order of the platform-go guide: drain the
// admin server, stop the public server, stop the loops, close the clients,
// and stop the admin server last.
func (a *App) Shutdown(ctx context.Context) error {
	var errs []error
	if a.state != nil {
		a.state.MarkDraining()
		t := time.NewTimer(a.cfg.Admin.DrainDelay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
	}
	if a.pub != nil {
		errs = append(errs, a.pub.Shutdown(ctx))
	}
	a.release(ctx)
	return errors.Join(errs...)
}

// release stops everything that Start made. It is safe to call it more than
// one time.
func (a *App) release(ctx context.Context) {
	a.closeOnce.Do(func() {
		if a.pub != nil {
			_ = a.pub.Close()
		}
		if a.stopRetention != nil {
			a.stopRetention()
			a.retentionWG.Wait()
		}
		if a.sessionReg != nil {
			_ = a.sessionReg.Unregister()
		}
		if a.reg != nil {
			_ = a.reg.Unregister()
		}
		if a.verify != nil {
			a.verify.Close()
		}
		if a.mgr != nil {
			a.mgr.Close()
		}
		if a.cache != nil {
			a.cache.Close()
		}
		if a.pgChk != nil {
			a.pgChk.Close()
		}
		if a.kv != nil {
			a.kv.Close()
		}
		if a.db != nil {
			a.db.Close()
		}
		if a.admin != nil {
			sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = a.admin.Shutdown(sctx)
			cancel()
		}
		if a.adminL != nil {
			_ = a.adminL.Close()
		}
		if a.pubL != nil {
			_ = a.pubL.Close()
		}
		a.serveWG.Wait()
	})
}

// RunMigrations runs the migrations of the secrets store, then the migrations
// of the service.
func RunMigrations(ctx context.Context, db *clientpg.Client) error {
	secretsMigrator, err := migratepg.NewMigrator(db.Pool, secretspg.Migrations(),
		migratepg.MigratorOptions{MigrationsTable: secretspg.MigrationsTable})
	if err != nil {
		return fmt.Errorf("make the secrets migrator: %w", err)
	}
	if _, err := migrate.Run(ctx, migratepg.NewLocker(db.Pool, secretspg.MigrationsTable), secretsMigrator,
		migrate.Options{Name: secretspg.MigrationsTable}); err != nil {
		return fmt.Errorf("run the secrets migrations: %w", err)
	}
	migrator, err := migratepg.NewMigrator(db.Pool, migrations.Files, migratepg.MigratorOptions{})
	if err != nil {
		return fmt.Errorf("make the migrator: %w", err)
	}
	if _, err := migrate.Run(ctx, migratepg.NewLocker(db.Pool, ""), migrator, migrate.Options{}); err != nil {
		return fmt.Errorf("run the migrations: %w", err)
	}
	return nil
}
