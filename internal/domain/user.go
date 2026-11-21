package domain

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// UserStatus is the state of a user.
type UserStatus string

// The states of a user.
const (
	UserInvited  UserStatus = "invited"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

// AdminRole is the role that the first admin gets.
var AdminRole = RoleRef{App: IdentityApp, Role: "admin"}

// User is a human principal.
type User struct {
	ID    string
	Email string
	Name  string
	// Status is the state of the user.
	Status UserStatus
	// PasswordHash is the PHC string of the password. It is empty until the
	// user sets a password.
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Errors of the user rules.
var (
	ErrInvalidEmail = errors.New("the email is not valid")
	ErrInvalidName  = errors.New("the name is not valid")
)

// Limits of the user data.
const (
	minEmailLength = 3
	maxEmailLength = 254
	maxNameLength  = 200
)

// NormalizeEmail trims the spaces and makes the value lowercase. The result
// has 3 to 254 characters and exactly one "@". The standard parser must accept
// it as an address with no name part.
func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < minEmailLength || len(s) > maxEmailLength || strings.Count(s, "@") != 1 {
		return "", ErrInvalidEmail
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`"<>(),;:\`, r) {
			return "", ErrInvalidEmail
		}
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", ErrInvalidEmail
	}
	return s, nil
}

// CheckName trims the name and checks it. A name has 1 to 200 characters and no
// control character.
func CheckName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxNameLength || !utf8.ValidString(s) {
		return "", ErrInvalidName
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", ErrInvalidName
		}
	}
	return s, nil
}
