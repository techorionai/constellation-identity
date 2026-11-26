package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The values of amr (RFC 8176) that this service writes.
const (
	AMRPassword = "pwd"
	AMROTP      = "otp"
	AMRRecovery = "rec"
	AMRMFA      = "mfa"
)

// MethodsPassword is the amr of a login with a password only.
func MethodsPassword() []string { return []string{AMRPassword} }

// MethodsTOTP is the amr of a login with a password and a TOTP code.
func MethodsTOTP() []string { return []string{AMRPassword, AMROTP, AMRMFA} }

// MethodsRecovery is the amr of a login with a password and a recovery code.
func MethodsRecovery() []string { return []string{AMRPassword, AMRRecovery, AMRMFA} }

// HasMFA reports whether the methods show a second factor.
func HasMFA(methods []string) bool { return slices.Contains(methods, AMRMFA) }

// NeedsMFA is the rule "MFA for admins". A user needs MFA when the setting is
// on and the user has the permission identity:admin.
func NeedsMFA(requireForAdmins bool, granted []string) bool {
	return requireForAdmins && slices.Contains(granted, AdminPermission)
}

// MaxFreshAge is the longest age of a login that a change of the MFA settings
// accepts.
const MaxFreshAge = 5 * time.Minute

// FreshLogin reports whether the auth time is not more than MaxFreshAge before
// now.
func FreshLogin(authTime, now time.Time) bool {
	return !authTime.IsZero() && now.Sub(authTime) <= MaxFreshAge
}

// Recovery code rules.
const (
	// RecoveryCodeCount is the number of codes of one set.
	RecoveryCodeCount = 10
	// recoveryCodeLength is the number of base32 characters of a code (50 bits).
	recoveryCodeLength = 10
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalidRecoveryCode means the text is not the form of a recovery code.
var ErrInvalidRecoveryCode = errors.New("the recovery code is not valid")

// NewRecoveryCode makes a recovery code in the normalized form (10 upper case
// base32 characters).
func NewRecoveryCode() (string, error) {
	b := make([]byte, 7)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return recoveryEncoding.EncodeToString(b)[:recoveryCodeLength], nil
}

// FormatRecoveryCode shows a normalized code as two groups of 5.
func FormatRecoveryCode(code string) string {
	if len(code) != recoveryCodeLength {
		return code
	}
	return code[:5] + "-" + code[5:]
}

// NormalizeRecoveryCode removes spaces and hyphens and makes the letters upper
// case. It returns ErrInvalidRecoveryCode if the result is not 10 base32
// characters.
func NormalizeRecoveryCode(s string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7'):
			b.WriteRune(r)
		default:
			return "", ErrInvalidRecoveryCode
		}
	}
	if b.Len() != recoveryCodeLength {
		return "", ErrInvalidRecoveryCode
	}
	return b.String(), nil
}

// HashRecoveryCode returns the SHA-256 of a normalized code. The code has 50
// bits of entropy, so a fast hash is enough.
func HashRecoveryCode(normalized string) []byte {
	sum := sha256.Sum256([]byte(normalized))
	return sum[:]
}

// NewRecoveryCodes makes a set of codes. It returns the normalized codes.
func NewRecoveryCodes() ([]string, error) {
	seen := make(map[string]bool, RecoveryCodeCount)
	out := make([]string, 0, RecoveryCodeCount)
	for len(out) < RecoveryCodeCount {
		c, err := NewRecoveryCode()
		if err != nil {
			return nil, err
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, nil
}

// TOTPRecord is the stored TOTP factor of a user.
type TOTPRecord struct {
	UserID string
	// Secret is the sealed secret (an envelope). It is never the secret in clear text.
	Secret       []byte
	KeyID        string
	LastUsedStep int64
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// MFAState is the MFA data of a user.
type MFAState struct {
	// HasTOTP is true when a TOTP row exists.
	HasTOTP    bool
	TOTPAt     time.Time
	LastUsedAt *time.Time
	// CodesRemaining is the number of recovery codes that are not used.
	CodesRemaining int
}

// Enabled reports whether the user has a second factor: a TOTP row or an
// unused recovery code.
func (s MFAState) Enabled() bool { return s.HasTOTP || s.CodesRemaining > 0 }

// PendingLogin is the state between the first factor and the second factor of
// a login. The store keeps it for a short time. The login that makes it has
// the user, the first factor, and the place to go after the login.
type PendingLogin struct {
	UserID string `json:"user_id"`
	// Methods are the methods of the first factor.
	Methods     []string `json:"methods"`
	AuthRequest string   `json:"auth_request"`
	ReturnTo    string   `json:"return_to"`
	// LimiterEmail and LimiterIP are the keys of the login counters. The
	// second factor resets them after a full login.
	LimiterEmail string `json:"limiter_email"`
	LimiterIP    string `json:"limiter_ip"`
	// ExpiresAt is the end of the pending login. The check uses the clock of the
	// service.
	ExpiresAt time.Time `json:"expires_at"`
}
