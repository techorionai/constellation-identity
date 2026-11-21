// Package config holds the configuration of the identity service. The values
// come from environment variables with the prefix IDENTITY_.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	platformconfig "github.com/techorionai/constellation-platform-go/config"
	"github.com/techorionai/constellation-platform-go/health"
	"github.com/techorionai/constellation-platform-go/retention"
	"github.com/techorionai/constellation-platform-go/secrets"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// Prefix is the prefix of all environment variables of the service.
const Prefix = "IDENTITY_"

// Minimum values of the key settings.
const (
	// MinPublishDelay is more than the refresh interval of a verifier (10
	// minutes) plus the key cache reload (1 minute) plus the JWKS max-age (5
	// minutes).
	MinPublishDelay = 20 * time.Minute
	MinRetireAfter  = 30 * time.Minute
)

// HTTP is the config of the public listener.
type HTTP struct {
	Addr string `env:"ADDR" envDefault:":8080"`
	// TrustedProxies is a list of CIDR ranges. The service uses the
	// X-Forwarded-For header only for a request from one of these ranges.
	TrustedProxies []string `env:"TRUSTED_PROXIES"`
}

// TrustedProxyPrefixes parses TrustedProxies.
func (h HTTP) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(h.TrustedProxies))
	for _, s := range h.TrustedProxies {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR range", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Limits of the setup, invite, session, password, and login settings.
const (
	MinSetupTTL         = 10 * time.Minute
	MaxSetupTTL         = 7 * 24 * time.Hour
	MinInviteTTL        = 10 * time.Minute
	MaxInviteTTL        = 30 * 24 * time.Hour
	MinIdleTimeout      = 5 * time.Minute
	MinAbsoluteTimeout  = time.Hour
	MaxAbsoluteTimeout  = 90 * 24 * time.Hour
	MinQueueTimeout     = 100 * time.Millisecond
	MaxQueueTimeout     = 30 * time.Second
	MinFailureWindow    = time.Minute
	MaxFailureWindow    = 24 * time.Hour
	MaxConcurrentHashes = 64
)

// Setup is the config of the first-admin setup token.
type Setup struct {
	TTL time.Duration `env:"TTL" envDefault:"24h"`
}

// Invite is the config of the invite tokens.
type Invite struct {
	TTL time.Duration `env:"TTL" envDefault:"72h"`
}

// Session is the config of the browser sessions.
type Session struct {
	IdleTimeout     time.Duration `env:"IDLE_TIMEOUT" envDefault:"12h"`
	AbsoluteTimeout time.Duration `env:"ABSOLUTE_TIMEOUT" envDefault:"168h"`
}

// Policy returns the session policy.
func (s Session) Policy() domain.SessionPolicy {
	return domain.SessionPolicy{IdleTimeout: s.IdleTimeout, AbsoluteTimeout: s.AbsoluteTimeout}
}

// Password is the config of the password hash.
type Password struct {
	MaxConcurrent int           `env:"MAX_CONCURRENT" envDefault:"4"`
	QueueTimeout  time.Duration `env:"QUEUE_TIMEOUT" envDefault:"2s"`
}

// Login is the config of the login failure limit.
type Login struct {
	MaxFailuresPerEmail int           `env:"MAX_FAILURES_PER_EMAIL" envDefault:"5"`
	MaxFailuresPerIP    int           `env:"MAX_FAILURES_PER_IP" envDefault:"50"`
	FailureWindow       time.Duration `env:"FAILURE_WINDOW" envDefault:"15m"`
}

// Retention is the config of the retention jobs. A job deletes the rows 7 days
// after the end of the token or session, unless Period says otherwise.
type Retention struct {
	Tokens   retention.Config `envPrefix:"TOKENS__"`
	Sessions retention.Config `envPrefix:"SESSIONS__"`
}

// DefaultRetentionPeriod is the default age after which the retention jobs
// delete expired tokens and sessions.
const DefaultRetentionPeriod = 7 * 24 * time.Hour

// Keys is the config of the signing key lifecycle.
type Keys struct {
	RotationPeriod time.Duration `env:"ROTATION_PERIOD" envDefault:"2160h"`
	PublishDelay   time.Duration `env:"PUBLISH_DELAY" envDefault:"1h"`
	RetireAfter    time.Duration `env:"RETIRE_AFTER" envDefault:"24h"`
}

// Config is the config of the service.
type Config struct {
	LogLevel    slog.Level      `env:"LOG_LEVEL" envDefault:"INFO"`
	Issuer      string          `env:"ISSUER,required"`
	HTTP        HTTP            `envPrefix:"HTTP__"`
	Admin       health.Config   `envPrefix:"ADMIN__"`
	Database    clientpg.Config `envPrefix:"DATABASE__"`
	Valkey      clientvk.Config `envPrefix:"VALKEY__"`
	Secrets     secrets.Config  `envPrefix:"SECRETS__"`
	Keys        Keys            `envPrefix:"KEYS__"`
	Setup       Setup           `envPrefix:"SETUP__"`
	Invite      Invite          `envPrefix:"INVITE__"`
	Session     Session         `envPrefix:"SESSION__"`
	Password    Password        `envPrefix:"PASSWORD__"`
	Login       Login           `envPrefix:"LOGIN__"`
	Retention   Retention       `envPrefix:"RETENTION__"`
	ClientsFile string          `env:"CLIENTS_FILE"`
}

// Load reads the environment and checks the values.
func Load() (Config, error) {
	var cfg Config
	if err := platformconfig.Load(Prefix, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the values that the env loader cannot check. Each error
// names its variable.
func (c Config) Validate() error {
	var errs []error
	if err := ValidateIssuer(c.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("%sISSUER: %w", Prefix, err))
	}
	errs = append(errs, c.Keys.Validate()...)
	errs = append(errs, c.validateUsers()...)
	return errors.Join(errs...)
}

// validateUsers checks the settings of the users, the sessions, and the login.
func (c Config) validateUsers() []error {
	var errs []error
	bad := func(name, rule string) { errs = append(errs, fmt.Errorf("%s%s %s", Prefix, name, rule)) }
	if c.Setup.TTL < MinSetupTTL || c.Setup.TTL > MaxSetupTTL {
		bad("SETUP__TTL", fmt.Sprintf("must be from %s to %s", MinSetupTTL, MaxSetupTTL))
	}
	if c.Invite.TTL < MinInviteTTL || c.Invite.TTL > MaxInviteTTL {
		bad("INVITE__TTL", fmt.Sprintf("must be from %s to %s", MinInviteTTL, MaxInviteTTL))
	}
	if c.Session.AbsoluteTimeout < MinAbsoluteTimeout || c.Session.AbsoluteTimeout > MaxAbsoluteTimeout {
		bad("SESSION__ABSOLUTE_TIMEOUT", fmt.Sprintf("must be from %s to %s", MinAbsoluteTimeout, MaxAbsoluteTimeout))
	}
	if c.Session.IdleTimeout < MinIdleTimeout || c.Session.IdleTimeout > c.Session.AbsoluteTimeout {
		bad("SESSION__IDLE_TIMEOUT", fmt.Sprintf("must be from %s to %sSESSION__ABSOLUTE_TIMEOUT", MinIdleTimeout, Prefix))
	}
	if c.Password.MaxConcurrent < 1 || c.Password.MaxConcurrent > MaxConcurrentHashes {
		bad("PASSWORD__MAX_CONCURRENT", fmt.Sprintf("must be from 1 to %d", MaxConcurrentHashes))
	}
	if c.Password.QueueTimeout < MinQueueTimeout || c.Password.QueueTimeout > MaxQueueTimeout {
		bad("PASSWORD__QUEUE_TIMEOUT", fmt.Sprintf("must be from %s to %s", MinQueueTimeout, MaxQueueTimeout))
	}
	if c.Login.MaxFailuresPerEmail < 1 || c.Login.MaxFailuresPerEmail > 100 {
		bad("LOGIN__MAX_FAILURES_PER_EMAIL", "must be from 1 to 100")
	}
	if c.Login.MaxFailuresPerIP < 1 || c.Login.MaxFailuresPerIP > 10000 {
		bad("LOGIN__MAX_FAILURES_PER_IP", "must be from 1 to 10000")
	}
	if c.Login.FailureWindow < MinFailureWindow || c.Login.FailureWindow > MaxFailureWindow {
		bad("LOGIN__FAILURE_WINDOW", fmt.Sprintf("must be from %s to %s", MinFailureWindow, MaxFailureWindow))
	}
	if _, err := c.HTTP.TrustedProxyPrefixes(); err != nil {
		bad("HTTP__TRUSTED_PROXIES", "has a value that is not a CIDR range: "+err.Error())
	}
	if err := c.Retention.Tokens.Validate(); err != nil {
		bad("RETENTION__TOKENS__*", err.Error())
	}
	if err := c.Retention.Sessions.Validate(); err != nil {
		bad("RETENTION__SESSIONS__*", err.Error())
	}
	return errs
}

// Policy returns the key policy.
func (k Keys) Policy() domain.KeyPolicy {
	return domain.KeyPolicy{RotationPeriod: k.RotationPeriod, PublishDelay: k.PublishDelay, RetireAfter: k.RetireAfter}
}

// Validate checks the key settings.
func (k Keys) Validate() []error {
	var errs []error
	if k.PublishDelay < MinPublishDelay {
		errs = append(errs, fmt.Errorf("%sKEYS__PUBLISH_DELAY must be %s or more", Prefix, MinPublishDelay))
	}
	if k.RetireAfter < MinRetireAfter {
		errs = append(errs, fmt.Errorf("%sKEYS__RETIRE_AFTER must be %s or more", Prefix, MinRetireAfter))
	}
	if k.RotationPeriod <= k.PublishDelay {
		errs = append(errs, fmt.Errorf("%sKEYS__ROTATION_PERIOD must be more than %sKEYS__PUBLISH_DELAY", Prefix, Prefix))
	}
	return errs
}

// ValidateIssuer checks the issuer URL. It must be absolute, with no query and
// no fragment, no white space, no trailing slash, and a port from 1 to 65535
// if it has a port. The scheme must be https. The scheme http is accepted only for
// localhost, 127.0.0.1, and [::1].
func ValidateIssuer(s string) error {
	if s == "" {
		return errors.New("is required")
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("must have no white space and no control characters")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	if !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return errors.New("must be an absolute URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return errors.New("must have no query and no fragment")
	}
	if u.User != nil {
		return errors.New("must have no user information")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("must have a port from 1 to 65535")
		}
	}
	if strings.HasSuffix(u.Path, "/") {
		return errors.New("must not end with a slash")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return errors.New("must use https. http is allowed only for localhost, 127.0.0.1, and [::1]")
	default:
		return errors.New("must use https")
	}
}
