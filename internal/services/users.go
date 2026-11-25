package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	"github.com/techorionai/constellation-platform-go/decorators"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/retention"
	retentionpg "github.com/techorionai/constellation-platform-go/retention/postgres"
	transactionpg "github.com/techorionai/constellation-platform-go/transaction/postgres"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/adapters/argon2"
	adapterjose "github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	adaptervalkey "github.com/techorionai/constellation-identity/internal/adapters/valkey"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/handlers/http/pages"
)

// expectedUserError reports an error that the person at the browser caused.
func expectedUserError(err error) bool {
	for _, target := range []error{
		commands.ErrTokenInvalid, commands.ErrEmailTaken, commands.ErrUserNotFound, commands.ErrUserDisabled,
		commands.ErrUserNotInvited, commands.ErrBadCredentials, commands.ErrTooManyAttempts, commands.ErrBusy,
		domain.ErrInvalidEmail, domain.ErrInvalidName, domain.ErrPasswordTooShort, domain.ErrPasswordTooLong,
		queries.ErrNoSession,
		apperrors.ErrRateLimited,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// userErrorLevel logs an error that a person caused at the info level.
func userErrorLevel(err error) slog.Level {
	if expectedUserError(err) {
		return slog.LevelInfo
	}
	return errorLevel(err)
}

// userErrorClassifier tells the tracing decorator which errors are failures.
func userErrorClassifier(err error) bool { return !expectedUserError(err) }

func observe[P, R any](e executor.ExecutorWithReturn[P, R], name string, log *slog.Logger) executor.ExecutorWithReturn[P, R] {
	return decorators.ApplyTracing(decorators.ApplyLogging(e, name,
		decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), name,
		decorators.WithErrorClassifier(userErrorClassifier))
}

// userStack holds the use cases of the users, the invites, and the sessions.
// The admin API of a later issue uses the same use cases.
type userStack struct {
	pages     *pages.Handler
	ensure    executor.ExecutorWithReturn[commands.EnsureSetupToken, commands.EnsureSetupTokenResult]
	retention *retention.Runner
	sessions  *postgres.Sessions

	oidc          *commands.OIDC
	admin         *commands.Admin
	apiTokens     *commands.APITokens
	apiTokenRepo  *postgres.APITokens
	userRoles     *postgres.UserRoles
	cors          *queries.CORSOrigins
	exchangeCode  executor.ExecutorWithReturn[commands.ExchangeCode, commands.UserTokenResult]
	refreshTokens executor.ExecutorWithReturn[commands.RefreshTokens, commands.UserTokenResult]
	revokeToken   executor.Executor[commands.RevokeToken]
	userInfo      executor.ExecutorWithReturn[commands.UserInfo, commands.UserInfoResult]
	createUser    executor.ExecutorWithReturn[commands.CreateUser, commands.CreateUserResult]
	createInvite  executor.ExecutorWithReturn[commands.CreateInvite, commands.Link]
}

// buildUsers makes the adapters and the use cases of the users, and the page
// handler. It does not start anything.
func (a *App) buildUsers(o options) (*userStack, error) {
	cfg, log := a.cfg, a.log
	pool := a.db.Pool

	hasher, err := argon2.New(argon2.Config{
		MaxConcurrent: cfg.Password.MaxConcurrent, QueueTimeout: cfg.Password.QueueTimeout,
		MemoryKiB: o.hashMemoryKiB, Time: o.hashTime,
	})
	if err != nil {
		return nil, fmt.Errorf("make the password hasher: %w", err)
	}
	trusted, err := cfg.HTTP.TrustedProxyPrefixes()
	if err != nil {
		return nil, fmt.Errorf("%sHTTP__TRUSTED_PROXIES: %w", config.Prefix, err)
	}
	tokens := postgres.NewOneTimeTokens(pool)
	userRepo := postgres.NewUsers(pool)
	roles := postgres.NewUserRoles(pool)
	sessionRepo := postgres.NewSessions(pool)
	tx := transactionpg.NewTransactor(pool)
	limiter := adaptervalkey.NewLoginLimiter(a.kv.Raw, a.kv.Keys, cfg.Login.FailureWindow)
	policy := cfg.Session.Policy()
	clock := o.clock
	if clock == nil {
		clock = time.Now
	}
	refreshRepo := postgres.NewRefreshTokens(pool)
	apiTokenRepo := postgres.NewAPITokens(pool)
	clientRepo := postgres.NewClients(pool)
	store := adaptervalkey.NewStore(a.kv.Raw, a.kv.Keys)

	setupDeps := commands.SetupDeps{
		Issuer: cfg.Issuer, TTL: cfg.Setup.TTL, Tokens: tokens, Roles: roles, Users: userRepo,
		Session: sessionRepo, Hasher: hasher, Tx: tx, Policy: policy, Log: log, Now: clock,
	}
	inviteDeps := commands.InviteDeps{
		Issuer: cfg.Issuer, TTL: cfg.Invite.TTL, Tokens: tokens, Users: userRepo,
		Session: sessionRepo, Hasher: hasher, Tx: tx, Policy: policy, Log: log, Now: clock,
	}
	loginDeps := commands.LoginDeps{
		Users: userRepo, Session: sessionRepo, Hasher: hasher, Limiter: limiter,
		Limits: commands.LoginLimits{
			MaxFailuresPerEmail: int64(cfg.Login.MaxFailuresPerEmail), MaxFailuresPerIP: int64(cfg.Login.MaxFailuresPerIP),
		},
		Policy: policy, Log: log, Now: clock,
	}
	login, err := commands.NewLogin(loginDeps)
	if err != nil {
		return nil, err
	}

	st := &userStack{sessions: sessionRepo}
	oidc, err := commands.NewOIDC(commands.OIDCDeps{
		Issuer: cfg.Issuer, Clients: clientRepo, Users: userRepo, UserRoles: roles, Sessions: sessionRepo,
		Refresh: refreshRepo, AuthRequests: store, Codes: store.Codes(), Keys: a.cache, Signer: adapterjose.Signer{},
		Verifier: adapterjose.Verifier{}, Tx: tx, Policy: policy,
		AuthRequestTTL: cfg.OIDC.AuthRequestTTL, CodeTTL: cfg.OIDC.CodeTTL, UserTokenTTL: cfg.OIDC.UserTokenTTL,
		Log: log, Now: clock,
	})
	if err != nil {
		return nil, err
	}
	st.oidc = oidc
	st.admin = commands.NewAdmin(commands.AdminDeps{
		Users: userRepo, UserRoles: roles, Sessions: sessionRepo, Clients: clientRepo,
		ClientRoles: postgres.NewClientRoles(pool), Agents: postgres.NewAgents(pool), AgentRoles: postgres.NewAgentRoles(pool), Manifests: postgres.NewManifests(pool), Tokens: tokens,
		Refresh: refreshRepo, APITokens: apiTokenRepo, Lock: postgres.NewAdminLock(pool), Tx: tx, Log: log, Now: clock,
	})
	st.apiTokenRepo, st.userRoles = apiTokenRepo, roles
	st.apiTokens = commands.NewAPITokens(commands.APITokensDeps{
		Tokens: apiTokenRepo, Users: userRepo, UserRoles: roles, Tx: tx, Log: log, Now: clock, RateLimits: a.limits,
		Settings: commands.APITokenSettings{
			DefaultTTLDays: cfg.APIToken.DefaultTTLDays, MaxTTLDays: cfg.APIToken.MaxTTLDays, MaxPerUser: cfg.APIToken.MaxPerUser,
		},
	})
	corsTTL := queries.DefaultCORSCacheTTL
	if o.corsCacheTTL != nil {
		corsTTL = *o.corsCacheTTL
	}
	st.cors = queries.NewCORSOrigins(clientRepo, corsTTL, clock, log)
	st.exchangeCode = observe[commands.ExchangeCode, commands.UserTokenResult](executor.FuncWithReturn[commands.ExchangeCode, commands.UserTokenResult](oidc.ExchangeCode), "ExchangeCode", log)
	st.refreshTokens = observe[commands.RefreshTokens, commands.UserTokenResult](executor.FuncWithReturn[commands.RefreshTokens, commands.UserTokenResult](oidc.RefreshTokens), "RefreshTokens", log)
	st.revokeToken = decorators.ApplyTracingNoResult(executor.Func[commands.RevokeToken](oidc.RevokeToken), "RevokeToken")
	st.userInfo = decorators.ApplyTracing(executor.FuncWithReturn[commands.UserInfo, commands.UserInfoResult](oidc.GetUserInfo), "GetUserInfo",
		decorators.WithErrorClassifier(func(err error) bool {
			return !errors.Is(err, commands.ErrInvalidToken) && !errors.Is(err, commands.ErrInsufficientScope)
		}))
	st.createUser = observe[commands.CreateUser, commands.CreateUserResult](commands.NewCreateUser(inviteDeps), "CreateUser", log)
	st.createInvite = observe[commands.CreateInvite, commands.Link](commands.NewCreateInvite(inviteDeps), "CreateInvite", log)
	st.ensure = observe[commands.EnsureSetupToken, commands.EnsureSetupTokenResult](
		commands.NewEnsureSetupToken(setupDeps), "EnsureSetupToken", log)
	h, err := pages.New(pages.Deps{
		Setup:   observe[commands.CompleteSetup, commands.IssuedSession](commands.NewCompleteSetup(setupDeps), "CompleteSetup", log),
		Invite:  observe[commands.AcceptInvite, commands.IssuedSession](commands.NewAcceptInvite(inviteDeps), "AcceptInvite", log),
		Login:   decorators.ApplyTracing(login, "Login", decorators.WithErrorClassifier(userErrorClassifier)),
		Logout:  decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[commands.Logout](commands.NewLogout(loginDeps), "Logout", decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), "Logout"),
		Session: observe[queries.SessionFromCookie, queries.SessionResult](queries.NewSessionFromCookie(sessionRepo, userRepo, clock), "SessionFromCookie", log),
		Touch: decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[commands.TouchSession](
			commands.NewTouchSession(loginDeps), "TouchSession", decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), "TouchSession"),
		CheckToken:        observe[queries.CheckOneTimeToken, bool](queries.NewCheckOneTimeToken(tokens, clock), "CheckOneTimeToken", log),
		Authorize:         observe[commands.Authorize, commands.AuthorizeOutcome](executor.FuncWithReturn[commands.Authorize, commands.AuthorizeOutcome](oidc.StartAuthorization), "StartAuthorization", log),
		Continue:          observe[commands.Continue, commands.AuthorizeOutcome](executor.FuncWithReturn[commands.Continue, commands.AuthorizeOutcome](oidc.CompleteAuthorization), "CompleteAuthorization", log),
		LookupAuthRequest: observe[string, commands.AuthRequestInfo](executor.FuncWithReturn[string, commands.AuthRequestInfo](oidc.LookupAuthRequest), "LookupAuthRequest", log),
		EndSession:        observe[commands.EndSession, commands.EndSessionOutcome](executor.FuncWithReturn[commands.EndSession, commands.EndSessionOutcome](oidc.StartEndSession), "EndSession", log),
		ConfirmEndSession: decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[string](executor.Func[string](oidc.ConfirmEndSession), "ConfirmEndSession", decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), "ConfirmEndSession"),
		Now:               clock,
		Issuer:            cfg.Issuer,
		TrustedProxies:    trusted,
		RateLimits:        a.limits,
		Log:               log,
	})
	if err != nil {
		return nil, fmt.Errorf("make the pages: %w", err)
	}
	st.pages = h

	locker, err := retentionpg.NewLocker(pool)
	if err != nil {
		return nil, fmt.Errorf("make the retention locker: %w", err)
	}
	st.retention, err = retention.NewRunner(locker, []retention.Job{
		{Name: "one_time_tokens", Config: cfg.Retention.Tokens, DefaultPeriod: config.DefaultRetentionPeriod, Purger: postgres.NewTokenPurger(pool)},
		{Name: "sessions", Config: cfg.Retention.Sessions, DefaultPeriod: config.DefaultRetentionPeriod, Purger: postgres.NewSessionPurger(pool)},
		{Name: "refresh_tokens", Config: cfg.Retention.RefreshTokens, DefaultPeriod: config.DefaultRetentionPeriod, Purger: postgres.NewRefreshTokenPurger(pool)},
		{Name: "refresh_token_families", Config: cfg.Retention.RefreshTokenFamilies, DefaultPeriod: config.DefaultRetentionPeriod, Purger: postgres.NewRefreshFamilyPurger(pool)},
		{Name: "api_tokens", Config: cfg.Retention.APITokens, DefaultPeriod: config.DefaultRetentionPeriod, Purger: postgres.NewAPITokenPurger(pool)},
	}, retention.RunnerOptions{After: o.retentionAfter})
	if err != nil {
		return nil, fmt.Errorf("make the retention runner: %w", err)
	}
	return st, nil
}

// ensureSetupToken makes the setup token if the install needs one. The log
// record says that a link exists and gives its expiry. It never has the link or
// the token, because a log reader could use them to take over the install. The
// operator gets the link with the subcommand setup-link.
func (a *App) ensureSetupToken(ctx context.Context, st *userStack) error {
	res, err := st.ensure.Execute(ctx, commands.EnsureSetupToken{})
	if err != nil {
		return err
	}
	if res.Link.URL != "" {
		a.log.WarnContext(ctx, "identity: first-admin setup link pending",
			"event", "identity.setup.pending", "expires_at", res.Link.ExpiresAt,
			"hint", "run the subcommand setup-link to get the link")
	}
	return nil
}

// registerSessionGauge registers the gauge identity.sessions.active.
func (a *App) registerSessionGauge(sessions *postgres.Sessions) error {
	meter := otel.Meter("identity")
	gauge, err := meter.Int64ObservableGauge("identity.sessions.active",
		metric.WithDescription("Sessions that are not revoked and have not expired."))
	if err != nil {
		return fmt.Errorf("make the session gauge: %w", err)
	}
	a.sessionReg, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		n, err := sessions.CountActive(ctx, time.Now().UTC())
		if err != nil {
			// A gauge with no value is better than a failed scrape.
			return nil //nolint:nilerr // The callback must not fail the collection.
		}
		o.ObserveInt64(gauge, n)
		return nil
	}, gauge)
	if err != nil {
		return fmt.Errorf("register the session gauge: %w", err)
	}
	return nil
}

// publicHandler joins the API router and the pages. The pages cannot be in the
// generated router, because the OpenAPI file does not describe them.
func publicHandler(api http.Handler, pageRoutes http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", api)
	for _, p := range pages.Paths {
		mux.Handle(p, pageRoutes)
	}
	return mux
}

// SetupLink replaces the unused setup tokens and returns a new setup link. It
// returns commands.ErrAdminExists if an active admin exists. It runs the
// migrations first, so that it works on an empty database too. It needs the
// database config only.
func SetupLink(ctx context.Context, cfg config.Config, log *slog.Logger) (string, error) {
	db, err := clientpg.New(ctx, cfg.Database)
	if err != nil {
		return "", fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer db.Close()
	if err := RunMigrations(ctx, db); err != nil {
		return "", err
	}
	cmd := commands.NewReplaceSetupToken(commands.SetupDeps{
		Issuer: cfg.Issuer, TTL: cfg.Setup.TTL,
		Tokens: postgres.NewOneTimeTokens(db.Pool), Roles: postgres.NewUserRoles(db.Pool),
		Tx: transactionpg.NewTransactor(db.Pool), Log: log,
	})
	link, err := cmd.Execute(ctx, commands.ReplaceSetupToken{})
	if err != nil {
		return "", err
	}
	return link.URL, nil
}

// UnlockLogin removes the login lock of one email. It uses Valkey only. The
// result is true if the email had a failure counter.
func UnlockLogin(ctx context.Context, cfg config.Config, email string, log *slog.Logger) (bool, error) {
	kv, err := clientvk.New(ctx, cfg.Valkey)
	if err != nil {
		return false, fmt.Errorf("connect to Valkey: %w", err)
	}
	defer kv.Close()
	limiter := adaptervalkey.NewLoginLimiter(kv.Raw, kv.Keys, cfg.Login.FailureWindow)
	return commands.NewUnlockLogin(limiter, log).Execute(ctx, commands.UnlockLogin{Email: email})
}
