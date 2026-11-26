package domain

import (
	"errors"
	"regexp"
	"time"
	"unicode/utf8"
)

// MaxPasskeys is the largest number of passkeys of one user.
const MaxPasskeys = 10

// Limits of the name of a passkey.
const (
	MinPasskeyNameLength = 1
	MaxPasskeyNameLength = 64
)

// ErrInvalidPasskeyName means the name of a passkey does not follow the rule.
var ErrInvalidPasskeyName = errors.New("the passkey name is not valid")

// passkeyNamePattern is the pattern of the contract. It is the same in Go RE2
// and in ECMAScript in Unicode mode. The name has no leading or trailing white
// space, no control character, no format character, and no line or paragraph
// separator.
var passkeyNamePattern = regexp.MustCompile(
	`^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}](?:[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}]*[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}])?$`)

// ValidatePasskeyName checks the name of a passkey. It is the one check for the
// hosted pages and the API. It counts the characters as runes. It does not
// change the name.
func ValidatePasskeyName(name string) error {
	n := utf8.RuneCountInString(name)
	if !utf8.ValidString(name) || n < MinPasskeyNameLength || n > MaxPasskeyNameLength {
		return ErrInvalidPasskeyName
	}
	if !passkeyNamePattern.MatchString(name) {
		return ErrInvalidPasskeyName
	}
	return nil
}

// Passkey is a passkey of a user, without key material.
type Passkey struct {
	// ID is the ID in the service. It is not the credential ID.
	ID         string
	UserID     string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	// BackupState is the flag BS of the last registration or assertion.
	BackupState bool
}

// PasskeyCredential is the stored credential with the data that the check of an
// assertion needs. The public key is not a secret, but it is not shown.
type PasskeyCredential struct {
	Passkey
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
}

// SignCountAccepted is the rule of WebAuthn Level 3 section 7.2. The rule
// applies when the new count or the stored count is not 0. Then the new count
// must be larger than the stored count.
func SignCountAccepted(stored, next uint32) bool {
	if stored == 0 && next == 0 {
		return true
	}
	return next > stored
}

// WebAuthn user handle rules.
const (
	// UserHandleLength is the number of random bytes of a user handle.
	UserHandleLength = 32
)

// More values of amr (RFC 8176).
const (
	// AMRHardwareKey is a proof of a key that the user holds: a passkey.
	AMRHardwareKey = "hwk"
	// AMRUser is a proof of the presence and the verification of the user.
	AMRUser = "user"
)

// MethodsPasskeyLogin is the amr of a login with a passkey and no password.
func MethodsPasskeyLogin() []string { return []string{AMRHardwareKey, AMRUser, AMRMFA} }

// PasskeyFactor returns the factor values of a passkey as a second factor. The
// value user is set when the authenticator verified the user.
func PasskeyFactor(verified bool) []string {
	if verified {
		return []string{AMRHardwareKey, AMRUser}
	}
	return []string{AMRHardwareKey}
}

// Ceremony is the state of a WebAuthn ceremony between the options and the
// finish step. The store keeps it for a short time.
type Ceremony struct {
	// State is the opaque data of the ceremony from the WebAuthn adapter.
	State  []byte `json:"state"`
	UserID string `json:"user_id,omitempty"`
	// Name is the name that the user gave to a new passkey.
	Name        string `json:"name,omitempty"`
	AuthRequest string `json:"auth_request,omitempty"`
	ReturnTo    string `json:"return_to,omitempty"`
}
