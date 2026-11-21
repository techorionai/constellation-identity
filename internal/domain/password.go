package domain

import (
	"errors"
	"unicode/utf8"
)

// The length limits of a password after normalization. There are no
// composition rules (NIST SP 800-63B).
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

// Errors of the password policy.
var (
	ErrPasswordTooShort = errors.New("the password is too short")
	ErrPasswordTooLong  = errors.New("the password is too long")
)

// CheckPassword checks a password that is in NFC form. The length is the
// number of characters (code points).
func CheckPassword(normalized string) error {
	n := utf8.RuneCountInString(normalized)
	switch {
	case n < MinPasswordLength:
		return ErrPasswordTooShort
	case n > MaxPasswordLength:
		return ErrPasswordTooLong
	}
	return nil
}
