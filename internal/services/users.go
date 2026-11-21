package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	"github.com/techorionai/constellation-platform-go/decorators"
	"github.com/techorionai/constellation-platform-go/executor"
	"github.com/techorionai/constellation-platform-go/retention"
	retentionpg "github.com/techorionai/constellation-platform-go/retention/postgres"
	transactionpg "github.com/techorionai/constellation-platform-go/transaction/postgres"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/adapters/argon2"
	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	adaptervalkey "github.com/techorionai/constellation-identity/internal/adapters/valkey"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
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

	setupDeps := commands.SetupDeps{
		Issuer: cfg.Issuer, TTL: cfg.Setup.TTL, Tokens: tokens, Roles: roles, Users: userRepo,
		Session: sessionRepo, Hasher: hasher, Tx: tx, Policy: policy, Log: log,
	}
	inviteDeps := commands.InviteDeps{
		Issuer: cfg.Issuer, TTL: cfg.Invite.TTL, Tokens: tokens, Users: userRepo,
		Session: sessionRepo, Hasher: hasher, Tx: tx, Policy: policy, Log: log,
	}
	loginDeps := commands.LoginDeps{
		Users: userRepo, Session: sessionRepo, Hasher: hasher, Limiter: limiter,
		Limits: commands.LoginLimits{
			MaxFailuresPerEmail: int64(cfg.Login.MaxFailuresPerEmail), MaxFailuresPerIP: int64(cfg.Login.MaxFailuresPerIP),
		},
		Policy: policy, Log: log,
	}
	login, err := commands.NewLogin(loginDeps)
	if err != nil {
		return nil, err
	}

	st := &userStack{sessions: sessionRepo}
	st.ensure = observe[commands.EnsureSetupToken, commands.EnsureSetupTokenResult](
		commands.NewEnsureSetupToken(setupDeps), "EnsureSetupToken", log)
	h, err := pages.New(pages.Deps{
		Setup:   observe[commands.CompleteSetup, commands.IssuedSession](commands.NewCompleteSetup(setupDeps), "CompleteSetup", log),
		Invite:  observe[commands.AcceptInvite, commands.IssuedSession](commands.NewAcceptInvite(inviteDeps), "AcceptInvite", log),
		Login:   decorators.ApplyTracing(login, "Login", decorators.WithErrorClassifier(userErrorClassifier)),
		Logout:  decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[commands.Logout](commands.NewLogout(loginDeps), "Logout", decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), "Logout"),
		Session: observe[queries.SessionFromCookie, queries.SessionResult](queries.NewSessionFromCookie(sessionRepo, userRepo, nil), "SessionFromCookie", log),
		Touch: decorators.ApplyTracingNoResult(decorators.ApplyLoggingNoResult[commands.TouchSession](
			commands.NewTouchSession(loginDeps), "TouchSession", decorators.WithLogger(log), decorators.WithErrorLevel(userErrorLevel)), "TouchSession"),
		CheckToken:     observe[queries.CheckOneTimeToken, bool](queries.NewCheckOneTimeToken(tokens, nil), "CheckOneTimeToken", log),
		Issuer:         cfg.Issuer,
		TrustedProxies: trusted,
		Log:            log,
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
