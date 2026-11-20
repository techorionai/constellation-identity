// Package config holds the configuration of the identity service. The values
// come from environment variables with the prefix IDENTITY_.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	clientpg "github.com/techorionai/constellation-platform-go/clients/postgres"
	clientvk "github.com/techorionai/constellation-platform-go/clients/valkey"
	platformconfig "github.com/techorionai/constellation-platform-go/config"
	"github.com/techorionai/constellation-platform-go/health"
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
}

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
	return errors.Join(errs...)
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
