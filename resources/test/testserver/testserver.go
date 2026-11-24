// Package testserver starts the identity service in the test process, with
// live PostgreSQL and Valkey containers. Import it from test code only.
package testserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	platformconfig "github.com/techorionai/constellation-platform-go/config"
	"github.com/techorionai/constellation-platform-go/health"
	"github.com/techorionai/constellation-platform-go/resources/test/containers"
	"github.com/techorionai/constellation-platform-go/retention"
	"github.com/techorionai/constellation-platform-go/secrets"

	"github.com/techorionai/constellation-identity/internal/config"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/services"
)

// The images are the same as in constellation-deploy.
const (
	PostgresImage = "postgres:18.7-alpine"
	ValkeyImage   = "valkey/valkey:9.0.7-alpine"
)

// Env holds the containers. Many servers can share one Env.
type Env struct {
	PG *containers.PostgresInstance
	VK *containers.ValkeyInstance
}

// NewEnv starts the PostgreSQL and Valkey containers.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	return &Env{
		PG: containers.Postgres(t, containers.WithPostgresImage(PostgresImage)),
		VK: containers.Valkey(t, containers.WithValkeyImage(ValkeyImage)),
	}
}

// DB is a database for one test.
type DB struct {
	URL  platformconfig.Secret
	Name string
}

// NewDB makes a new database.
func (e *Env) NewDB(t testing.TB) DB {
	t.Helper()
	u, name := e.PG.NewDatabase(t)
	return DB{URL: u, Name: name}
}

// MasterKey makes a random master key in the format of the config.
func MasterKey(t testing.TB) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("testserver: random master key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

type settings struct {
	db              *DB
	masterKey       string
	masterKeyID     string
	policy          *domain.KeyPolicy
	managerInterval time.Duration
	cacheInterval   time.Duration
	clientsFile     string
	logger          *slog.Logger
	configure       []func(*config.Config)
	passwordMemory  uint32
	passwordPasses  uint32
	retentionAfter  func(time.Duration) <-chan time.Time
	clock           *Clock
	corsCacheTTL    *time.Duration
}

// Option changes a test server.
type Option func(*settings)

// WithDB uses an existing database, for example for a restart.
func WithDB(db DB) Option { return func(s *settings) { s.db = &db } }

// WithMasterKey sets the master key and its ID.
func WithMasterKey(key, id string) Option {
	return func(s *settings) { s.masterKey, s.masterKeyID = key, id }
}

// WithKeyPolicy sets a short key policy. It does not go through the config checks.
func WithKeyPolicy(p domain.KeyPolicy) Option { return func(s *settings) { s.policy = &p } }

// WithKeyIntervals sets the key manager interval and the cache reload interval.
func WithKeyIntervals(manager, cache time.Duration) Option {
	return func(s *settings) { s.managerInterval, s.cacheInterval = manager, cache }
}

// WithClientsFile sets the path of the clients file.
func WithClientsFile(path string) Option { return func(s *settings) { s.clientsFile = path } }

// WithLogger sets the logger of the service, for example a LogCapture.
func WithLogger(l *slog.Logger) Option { return func(s *settings) { s.logger = l } }

// WithConfigure changes the config before the service starts. The change does
// not go through the config checks.
func WithConfigure(f func(*config.Config)) Option {
	return func(s *settings) { s.configure = append(s.configure, f) }
}

// WithPasswordCost sets the memory (in KiB) and the passes of the argon2id
// hash. The default of the test server is small, so that tests are fast.
func WithPasswordCost(memoryKiB, passes uint32) Option {
	return func(s *settings) { s.passwordMemory, s.passwordPasses = memoryKiB, passes }
}

// WithRetentionAfter sets the timer function of the retention runner.
func WithRetentionAfter(after func(time.Duration) <-chan time.Time) Option {
	return func(s *settings) { s.retentionAfter = after }
}

// WithClock gives the server a clock that the test moves. The clock is for the
// users, the sessions, the code flow, and the admin API.
func WithClock(c *Clock) Option { return func(s *settings) { s.clock = c } }

// WithCORSCacheTTL sets the time of the CORS origin cache. 0 reads the database
// for each request.
func WithCORSCacheTTL(ttl time.Duration) Option { return func(s *settings) { s.corsCacheTTL = &ttl } }

// Server is a running service.
type Server struct {
	App       *services.App
	Config    config.Config
	PublicURL string
	AdminURL  string
	DB        DB
}

// Start starts a server. It fails the test on an error and stops the server at
// the end of the test.
func (e *Env) Start(t testing.TB, opts ...Option) *Server {
	t.Helper()
	srv, err := e.TryStart(t, opts...)
	if err != nil {
		t.Fatalf("testserver: start: %v", err)
	}
	return srv
}

// TryStart starts a server and returns the start error. It is safe to call it
// from another goroutine than the test goroutine.
func (e *Env) TryStart(t testing.TB, opts ...Option) (*Server, error) {
	t.Helper()
	cfg, s, err := e.buildConfig(t, opts)
	if err != nil {
		return nil, err
	}
	svcOpts := []services.Option{services.WithPasswordCost(s.passwordMemory, s.passwordPasses)}
	if s.logger != nil {
		svcOpts = append(svcOpts, services.WithLogger(s.logger))
	}
	if s.retentionAfter != nil {
		svcOpts = append(svcOpts, services.WithRetentionAfter(s.retentionAfter))
	}
	if s.policy != nil {
		svcOpts = append(svcOpts, services.WithKeyPolicy(*s.policy))
	}
	if s.clock != nil {
		svcOpts = append(svcOpts, services.WithClock(s.clock.Now))
	}
	if s.corsCacheTTL != nil {
		svcOpts = append(svcOpts, services.WithCORSCacheTTL(*s.corsCacheTTL))
	}
	if s.managerInterval > 0 {
		svcOpts = append(svcOpts, services.WithKeyIntervals(s.managerInterval, s.cacheInterval))
	}
	app, err := services.Start(context.Background(), cfg, svcOpts...)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		App:       app,
		Config:    cfg,
		PublicURL: "http://" + app.PublicAddr(),
		AdminURL:  "http://" + app.AdminAddr(),
		DB:        *s.db,
	}
	t.Cleanup(srv.Stop)
	return srv, nil
}

// Stop stops the server. A second call does nothing.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.App.Shutdown(ctx)
}

// Pool opens a pool to the database of the server, for the checks of a test.
func (s *Server) Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), string(s.DB.URL))
	if err != nil {
		t.Fatalf("testserver: open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Response is the status and the headers of a response. The body is read and
// closed already.
type Response struct {
	StatusCode int
	Header     http.Header
	// Cookies are the cookies of the Set-Cookie headers. Only a Web client fills it.
	Cookies []*http.Cookie
}

// Get does a GET request to the public URL and returns the response and the body.
func (s *Server) Get(t testing.TB, path string) (Response, []byte) {
	t.Helper()
	return do(t, http.MethodGet, s.PublicURL+path, nil)
}

func do(t testing.TB, method, url string, body io.Reader) (Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("testserver: request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("testserver: %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testserver: read body: %v", err)
	}
	return Response{StatusCode: resp.StatusCode, Header: resp.Header}, b
}

// Post does a form POST request to the public URL.
func (s *Server) Post(t testing.TB, path string, form string) (Response, []byte) {
	t.Helper()
	return do(t, http.MethodPost, s.PublicURL+path, strings.NewReader(form))
}

func (e *Env) buildConfig(t testing.TB, opts []Option) (config.Config, *settings, error) {
	t.Helper()
	s := &settings{passwordMemory: 1024, passwordPasses: 1}
	for _, o := range opts {
		o(s)
	}
	if s.db == nil {
		db := e.NewDB(t)
		s.db = &db
	}
	if s.masterKey == "" {
		s.masterKey, s.masterKeyID = MasterKey(t), "test"
	}
	port, err := freePort()
	if err != nil {
		return config.Config{}, nil, err
	}
	user, password := e.VK.NewACLUser(t, "identity")
	cfg := config.Config{
		Issuer: fmt.Sprintf("http://localhost:%d", port),
		HTTP:   config.HTTP{Addr: fmt.Sprintf("127.0.0.1:%d", port)},
		Admin:  health.Config{Addr: "127.0.0.1:0", CheckTimeout: 2 * time.Second, DrainDelay: time.Millisecond},
		Database: clientpg.Config{
			URL: s.db.URL, Database: s.db.Name, MaxConns: 10, ConnectTimeout: 5 * time.Second,
		},
		Valkey: clientvk.Config{
			Address: e.VK.Address(), Username: user, Password: password, KeyPrefix: "identity", DialTimeout: 5 * time.Second,
		},
		Secrets:  secrets.Config{MasterKey: platformconfig.Secret(s.masterKey), MasterKeyID: s.masterKeyID},
		Keys:     config.Keys{RotationPeriod: 2160 * time.Hour, PublishDelay: time.Hour, RetireAfter: 24 * time.Hour},
		Setup:    config.Setup{TTL: 24 * time.Hour},
		Invite:   config.Invite{TTL: 72 * time.Hour},
		Session:  config.Session{IdleTimeout: 12 * time.Hour, AbsoluteTimeout: 168 * time.Hour},
		Password: config.Password{MaxConcurrent: 4, QueueTimeout: 5 * time.Second},
		Login:    config.Login{MaxFailuresPerEmail: 5, MaxFailuresPerIP: 50, FailureWindow: 15 * time.Minute},
		Retention: config.Retention{
			Tokens:   retention.Config{Interval: time.Hour, BatchSize: 1000},
			Sessions: retention.Config{Interval: time.Hour, BatchSize: 1000},

			RefreshTokens:        retention.Config{Interval: time.Hour, BatchSize: 1000},
			RefreshTokenFamilies: retention.Config{Interval: time.Hour, BatchSize: 1000},
			APITokens:            retention.Config{Interval: time.Hour, BatchSize: 1000},
		},
		APIToken:    config.APIToken{DefaultTTLDays: 90, MaxTTLDays: 365, MaxPerUser: 50},
		OIDC:        config.OIDC{AuthRequestTTL: 10 * time.Minute, CodeTTL: time.Minute, UserTokenTTL: 15 * time.Minute},
		ClientsFile: s.clientsFile,
	}
	for _, f := range s.configure {
		f(&cfg)
	}
	return cfg, s, nil
}

func freePort() (int, error) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("find a free port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
