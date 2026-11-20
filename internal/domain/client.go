package domain

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"regexp"
	"time"
)

// ClientType is the type of an OAuth client.
type ClientType string

// ClientTypeService is a service client. It uses private_key_jwt.
const ClientTypeService ClientType = "service"

// ClientSource tells where a client comes from.
type ClientSource string

// The sources of a client.
const (
	SourceConfig ClientSource = "config"
	SourceAPI    ClientSource = "api"
)

// Client is an OAuth client.
type Client struct {
	ID        string
	Type      ClientType
	App       string
	Name      string
	Disabled  bool
	Source    ClientSource
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ClientKey is a public key of a client.
type ClientKey struct {
	ClientID  string
	KID       string
	PublicJWK PublicJWK
	CreatedAt time.Time
}

// ClientConfig is a client with its keys, as the clients file gives it.
type ClientConfig struct {
	Client Client
	Keys   []ClientKey
}

// IdentityApp is the application key of the identity service.
const IdentityApp = "identity"

var appKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ValidAppKey reports whether s is an application key.
func ValidAppKey(s string) bool { return appKeyPattern.MatchString(s) }

// privateJWKFields are the members of a private JWK. A public key must have
// none of them.
var privateJWKFields = map[string]bool{"d": true, "p": true, "q": true, "dp": true, "dq": true, "qi": true, "k": true, "oth": true}

// IsPrivateJWKField reports whether name is a member of a private JWK.
func IsPrivateJWKField(name string) bool { return privateJWKFields[name] }

// ValidatePublicJWK checks that jwk is a public EC P-256 key with a point on
// the curve.
func ValidatePublicJWK(jwk PublicJWK) error {
	if jwk.Kty != "EC" {
		return errors.New("kty must be EC")
	}
	if jwk.Crv != "P-256" {
		return errors.New("crv must be P-256")
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(x) != 32 {
		return errors.New("x must be 32 bytes in base64url form")
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(y) != 32 {
		return errors.New("y must be 32 bytes in base64url form")
	}
	point := append([]byte{4}, append(x, y...)...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return errors.New("the point is not on the curve P-256")
	}
	return nil
}
