package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/techorionai/constellation-identity/internal/domain"
)

type rawFile struct {
	Clients []rawClient `yaml:"clients"`
}

type rawClient struct {
	ID   string   `yaml:"id"`
	App  string   `yaml:"app"`
	Name string   `yaml:"name"`
	Type string   `yaml:"type"`
	Keys []rawKey `yaml:"keys"`
}

type rawKey struct {
	KID string         `yaml:"kid"`
	JWK map[string]any `yaml:"jwk"`
}

// LoadClientsFile reads and checks the clients file. An empty path gives no
// clients. An error names the client and the field.
func LoadClientsFile(path string) ([]domain.ClientConfig, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // The operator gives the path.
	if err != nil {
		return nil, fmt.Errorf("clients file: %w", err)
	}
	return ParseClientsFile(data)
}

// ParseClientsFile parses and checks the content of a clients file.
func ParseClientsFile(data []byte) ([]domain.ClientConfig, error) {
	var raw rawFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("clients file: %w", err)
	}

	var (
		errs []error
		out  []domain.ClientConfig
		ids  = map[string]bool{}
	)
	for i, rc := range raw.Clients {
		label := rc.ID
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		bad := func(field, format string, args ...any) {
			errs = append(errs, fmt.Errorf("clients file: client %q: field %s: %s", label, field, fmt.Sprintf(format, args...)))
		}
		if !domain.ValidAppKey(rc.ID) {
			bad("id", "must match ^[a-z][a-z0-9_]{0,31}$")
		}
		if ids[rc.ID] {
			bad("id", "is used two times")
		}
		ids[rc.ID] = true
		if !domain.ValidAppKey(rc.App) {
			bad("app", "must match ^[a-z][a-z0-9_]{0,31}$")
		} else if rc.App == domain.IdentityApp {
			bad("app", "must not be %q for a service client", domain.IdentityApp)
		}
		switch rc.Type {
		case "", string(domain.ClientTypeService):
		default:
			bad("type", "must be %q", domain.ClientTypeService)
		}
		name := rc.Name
		if name == "" {
			name = rc.ID
		}

		cc := domain.ClientConfig{Client: domain.Client{
			ID: rc.ID, Type: domain.ClientTypeService, App: rc.App, Name: name, Source: domain.SourceConfig,
		}}
		kids := map[string]bool{}
		for j, rk := range rc.Keys {
			field := fmt.Sprintf("keys[%d]", j)
			if rk.KID == "" {
				bad(field+".kid", "is required")
			}
			if kids[rk.KID] {
				bad(field+".kid", "%q is used two times", rk.KID)
			}
			kids[rk.KID] = true
			jwk, jerrs := parseJWK(rk.JWK, rk.KID)
			for _, e := range jerrs {
				bad(field+".jwk", "%s", e)
			}
			cc.Keys = append(cc.Keys, domain.ClientKey{ClientID: rc.ID, KID: rk.KID, PublicJWK: jwk})
		}
		out = append(out, cc)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

var jwkAllowed = map[string]bool{"kty": true, "crv": true, "x": true, "y": true, "kid": true, "use": true, "alg": true}

func parseJWK(m map[string]any, kid string) (domain.PublicJWK, []string) {
	var errs []string
	if m == nil {
		return domain.PublicJWK{}, []string{"is required"}
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	str := func(name string) string {
		v, ok := m[name]
		if !ok {
			return ""
		}
		s, ok := v.(string)
		if !ok {
			errs = append(errs, fmt.Sprintf("member %s must be a string", name))
		}
		return s
	}
	for _, name := range names {
		switch {
		case domain.IsPrivateJWKField(name):
			errs = append(errs, fmt.Sprintf("must not have the private member %s", name))
		case !jwkAllowed[name] && name != "n" && name != "e":
			errs = append(errs, fmt.Sprintf("has the unknown member %s", name))
		}
	}
	jwk := domain.PublicJWK{Kty: str("kty"), Crv: str("crv"), X: str("x"), Y: str("y"), Use: str("use"), Alg: str("alg")}
	if k := str("kid"); k != "" && k != kid {
		errs = append(errs, "member kid must be equal to the kid of the key")
	}
	if len(errs) == 0 {
		if err := domain.ValidatePublicJWK(jwk); err != nil {
			errs = append(errs, err.Error())
		}
	} else if jwk.Kty != "EC" && jwk.Kty != "" {
		errs = append(errs, "kty must be EC")
	}
	jwk.Kid = kid
	return jwk, errs
}
