package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// Lengths of the PKCE values (RFC 7636).
const (
	minCodeVerifierLength = 43
	maxCodeVerifierLength = 128
	codeChallengeLength   = 43
)

// ValidCodeChallenge reports whether s is the form of an S256 code challenge:
// 43 base64url characters.
func ValidCodeChallenge(s string) bool {
	if len(s) != codeChallengeLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// ValidCodeVerifier reports whether s has 43 to 128 characters of the set of
// RFC 7636 section 4.1.
func ValidCodeVerifier(s string) bool {
	if len(s) < minCodeVerifierLength || len(s) > maxCodeVerifierLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '-' && c != '.' && c != '_' && c != '~' {
			return false
		}
	}
	return true
}

// VerifyPKCE reports whether BASE64URL(SHA256(verifier)) equals the challenge.
// Only the method S256 exists. The compare takes constant time.
func VerifyPKCE(challenge, verifier string) bool {
	if !ValidCodeVerifier(verifier) || !ValidCodeChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
