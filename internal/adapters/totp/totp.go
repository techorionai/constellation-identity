// Package totp is the adapter of the port totp. It uses github.com/pquerna/otp.
package totp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	pqtotp "github.com/pquerna/otp/totp"

	porttotp "github.com/techorionai/constellation-identity/internal/ports/totp"
)

// Parameters of the codes. These are the values that the common authenticator
// apps support.
const (
	period     = 30
	secretSize = 20
	digits     = otp.DigitsSix
	// qrSize is the width and the height of the QR code in pixels.
	qrSize = 256
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Service is the adapter.
type Service struct{}

var _ porttotp.Service = Service{}

// New makes the adapter.
func New() Service { return Service{} }

// NewSecret makes a secret of 20 random bytes.
func (Service) NewSecret() ([]byte, error) {
	b := make([]byte, secretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random bytes: %w", err)
	}
	return b, nil
}

// Base32 returns the secret in base32 form with no padding.
func (Service) Base32(secret []byte) string { return b32.EncodeToString(secret) }

// Check checks a code for the step of at, the step before, and the step after.
// The comparison takes the same time for each code.
func (s Service) Check(secret []byte, code string, at time.Time) (int64, bool) {
	// An authenticator app can show the code in two groups. Spaces do not count.
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	encoded := s.Base32(secret)
	current := at.Unix() / period
	found, step := false, int64(0)
	for _, d := range []int64{-1, 0, 1} {
		n := current + d
		if n < 0 {
			continue
		}
		want, err := hotp.GenerateCodeCustom(encoded, uint64(n), hotp.ValidateOpts{Digits: digits, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			continue
		}
		// Compare all three steps, so the time does not show which step matched.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			found, step = true, n
		}
	}
	return step, found
}

func (Service) key(issuer, account string, secret []byte) (*otp.Key, error) {
	return pqtotp.Generate(pqtotp.GenerateOpts{
		Issuer: issuer, AccountName: account, Period: period, Secret: secret,
		Digits: digits, Algorithm: otp.AlgorithmSHA1,
	})
}

// URI returns the otpauth URI.
func (s Service) URI(issuer, account string, secret []byte) string {
	k, err := s.key(issuer, account, secret)
	if err != nil {
		// Only an empty issuer or an empty account name gives an error. The
		// service checks both before it calls.
		return ""
	}
	return k.URL()
}

// QRCode returns the PNG image of the URI.
func (Service) QRCode(uri string) ([]byte, error) {
	if _, err := url.Parse(uri); err != nil {
		return nil, fmt.Errorf("parse the otpauth URI: %w", err)
	}
	k, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return nil, fmt.Errorf("read the otpauth URI: %w", err)
	}
	img, err := k.Image(qrSize, qrSize)
	if err != nil {
		return nil, fmt.Errorf("make the QR code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("encode the QR code: %w", err)
	}
	return buf.Bytes(), nil
}
