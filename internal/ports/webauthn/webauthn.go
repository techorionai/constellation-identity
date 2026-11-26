// Package webauthn is the port of the WebAuthn ceremonies. It has its own
// types, so no type of the WebAuthn library leaves the adapter.
package webauthn

import (
	"context"
	"errors"
)

// Errors of a ceremony. The command maps each one to an outcome and to a
// refusal that the user sees.
var (
	// ErrBadOrigin means the origin or the RP ID hash does not match.
	ErrBadOrigin = errors.New("the origin does not match")
	// ErrBadSignature means the response is not valid: the signature, the
	// challenge, the type, or the format.
	ErrBadSignature = errors.New("the response is not valid")
	// ErrUserVerification means the authenticator did not verify the user where
	// the ceremony needs it.
	ErrUserVerification = errors.New("the user was not verified")
	// ErrUnknownCredential means no stored credential fits the response.
	ErrUnknownCredential = errors.New("the credential is not known")
)

// User is the account data of a registration or a second factor.
type User struct {
	// Handle is the WebAuthn user handle.
	Handle      []byte
	Name        string
	DisplayName string
}

// Credential is a credential of a user with the data that a check needs.
type Credential struct {
	ID             []byte
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
	BackupState    bool
}

// Options is the result of the first step of a ceremony.
type Options struct {
	// JSON is the options object for the browser. It is public data.
	JSON []byte
	// State is the opaque state of the ceremony. The caller keeps it for a short
	// time and gives it to the finish step.
	State []byte
}

// Registered is the result of a good registration.
type Registered struct {
	Credential Credential
}

// Asserted is the result of a good assertion.
type Asserted struct {
	CredentialID []byte
	// SignCount is the counter in the response.
	SignCount   uint32
	BackupState bool
	// UserVerified is the flag UV of this assertion.
	UserVerified bool
}

// Service runs the WebAuthn ceremonies.
type Service interface {
	// BeginRegistration makes the options of a registration. The options need a
	// resident key and user verification, ask for no attestation, and exclude the
	// credentials in existing.
	BeginRegistration(ctx context.Context, u User, existing []Credential) (Options, error)
	// FinishRegistration checks the response against the state and returns the new
	// credential.
	FinishRegistration(ctx context.Context, u User, state, response []byte) (Registered, error)
	// BeginLogin makes the options of a login with no password. The options have
	// no list of allowed credentials, and need user verification.
	BeginLogin(ctx context.Context) (Options, error)
	// ParseAssertion reads the credential ID and the user handle from the response
	// of a login with no password, before the check.
	ParseAssertion(response []byte) (credentialID, userHandle []byte, err error)
	// FinishLogin checks the response of a login with no password against the
	// state, the stored credential, and the user handle of its user.
	FinishLogin(ctx context.Context, state, response []byte, u User, c Credential) (Asserted, error)
	// BeginSecondFactor makes the options of a second factor. They list the
	// credentials of the user and ask for user verification as preferred.
	BeginSecondFactor(ctx context.Context, u User, creds []Credential) (Options, error)
	// FinishSecondFactor checks the response of a second factor for the user.
	FinishSecondFactor(ctx context.Context, u User, creds []Credential, state, response []byte) (Asserted, error)
}
