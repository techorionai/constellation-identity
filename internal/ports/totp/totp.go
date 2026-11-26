// Package totp is the port of the TOTP codes (RFC 6238).
package totp

import "time"

// Service makes secrets and checks codes. The parameters are SHA-1, 6 digits,
// and a period of 30 seconds. A code is good for one step before and one step
// after the step of the time.
type Service interface {
	// NewSecret makes a new secret of 20 random bytes.
	NewSecret() ([]byte, error)
	// Check checks a code at the time at. It returns the time step of the code
	// and true if the code is good for the step of at, the step before, or the
	// step after. The code has 6 digits.
	Check(secret []byte, code string, at time.Time) (step int64, ok bool)
	// URI returns the otpauth URI of the secret.
	URI(issuer, account string, secret []byte) string
	// QRCode returns the PNG image of the otpauth URI.
	QRCode(uri string) ([]byte, error)
	// Base32 returns the secret in base32 form with no padding.
	Base32(secret []byte) string
}
