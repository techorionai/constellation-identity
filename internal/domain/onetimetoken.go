package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// TokenPurpose tells what a one-time token is for.
type TokenPurpose string

// The purposes of a one-time token.
const (
	PurposeSetup  TokenPurpose = "setup"
	PurposeInvite TokenPurpose = "invite"
)

// MaxTokenValueLength is the longest token value that the service accepts.
const MaxTokenValueLength = 128

// OneTimeToken is the stored record of a setup token or an invite token. The
// value is never stored. The record has the SHA-256 hash.
type OneTimeToken struct {
	Hash      string
	Purpose   TokenPurpose
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// NewSecret makes a random value of 32 bytes in base64url form, and the hash
// that the service stores. It is used for one-time tokens and session tokens.
func NewSecret() (value, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("random bytes: %w", err)
	}
	value = base64.RawURLEncoding.EncodeToString(b)
	return value, HashSecret(value), nil
}

// HashSecret returns the hex SHA-256 of a token value.
func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
