package domain

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// PrincipalAgent is the principal_type of an agent in the act claim.
const PrincipalAgent = "agent"

// ErrInvalidAgentName means a name breaks the rules of an agent name.
var ErrInvalidAgentName = errors.New("the agent name is not valid")

// Agent is a principal that acts for a user. It belongs to one service client.
type Agent struct {
	ID        string
	Name      string
	ClientID  string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CheckAgentName trims the name and checks it. The name must be valid UTF-8,
// must have no control character, and must have 1 to 100 characters after the
// trim.
func CheckAgentName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) < 1 || utf8.RuneCountInString(n) > 100 {
		return "", ErrInvalidAgentName
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return "", ErrInvalidAgentName
		}
	}
	return n, nil
}
