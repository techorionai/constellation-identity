// Package webauthn is the adapter of the port webauthn. It uses
// github.com/go-webauthn/webauthn. The types of the library do not leave this
// package.
package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	port "github.com/techorionai/constellation-identity/internal/ports/webauthn"
)

// Config is the relying party.
type Config struct {
	// RPID is the host of the issuer, with no port.
	RPID string
	// Origin is the scheme, the host, and the port of the issuer.
	Origin string
	// RPName is the name that the authenticator shows.
	RPName string
}

// RelyingParty derives the RP ID and the allowed origin from the issuer URL.
// The RP ID is the host with no port. The origin has the scheme, the host, and
// the port. It returns ok false when the host is an IP address, because
// WebAuthn does not accept an IP address as the RP ID.
func RelyingParty(issuer string) (rpID, origin string, ok bool) {
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	host := u.Hostname()
	if isIPHost(host) {
		return "", "", false
	}
	return host, u.Scheme + "://" + u.Host, true
}

func isIPHost(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	// A host with four numeric labels is an IPv4 address.
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// Adapter runs the ceremonies.
type Adapter struct {
	w *gowebauthn.WebAuthn
}

var _ port.Service = (*Adapter)(nil)

// New makes the adapter.
func New(c Config) (*Adapter, error) {
	w, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                  c.RPID,
		RPDisplayName:         c.RPName,
		RPOrigins:             []string{c.Origin},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("make the WebAuthn relying party: %w", err)
	}
	return &Adapter{w: w}, nil
}

// user is the library view of a user.
type user struct {
	u     port.User
	creds []gowebauthn.Credential
}

func (u user) WebAuthnID() []byte                           { return u.u.Handle }
func (u user) WebAuthnName() string                         { return u.u.Name }
func (u user) WebAuthnDisplayName() string                  { return u.u.DisplayName }
func (u user) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

func libCredential(c port.Credential) gowebauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, t := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return gowebauthn.Credential{
		ID:        c.ID,
		PublicKey: c.PublicKey,
		Transport: transports,
		Flags: gowebauthn.CredentialFlags{
			UserPresent: true, UserVerified: true, BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		},
		Authenticator: gowebauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
	}
}

func libCredentials(cs []port.Credential) []gowebauthn.Credential {
	out := make([]gowebauthn.Credential, 0, len(cs))
	for _, c := range cs {
		out = append(out, libCredential(c))
	}
	return out
}

func descriptors(cs []port.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(cs))
	for _, c := range cs {
		d := protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID}
		for _, t := range c.Transports {
			d.Transport = append(d.Transport, protocol.AuthenticatorTransport(t))
		}
		out = append(out, d)
	}
	return out
}

// algorithms are EdDSA, ES256, and RS256, in this order of preference.
func algorithms() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
	}
}

// BeginRegistration makes the creation options.
func (a *Adapter) BeginRegistration(_ context.Context, u port.User, existing []port.Credential) (port.Options, error) {
	required := true
	creation, session, err := a.w.BeginRegistration(user{u: u},
		gowebauthn.WithCredentialParameters(algorithms()),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &required,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		}),
		gowebauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		gowebauthn.WithExclusions(descriptors(existing)),
	)
	if err != nil {
		return port.Options{}, fmt.Errorf("begin the registration: %w", err)
	}
	return encode(creation, session)
}

func encode(options any, session *gowebauthn.SessionData) (port.Options, error) {
	j, err := json.Marshal(options)
	if err != nil {
		return port.Options{}, fmt.Errorf("encode the options: %w", err)
	}
	st, err := json.Marshal(session)
	if err != nil {
		return port.Options{}, fmt.Errorf("encode the state: %w", err)
	}
	return port.Options{JSON: j, State: st}, nil
}

func decodeState(state []byte) (gowebauthn.SessionData, error) {
	var s gowebauthn.SessionData
	if err := json.Unmarshal(state, &s); err != nil {
		return gowebauthn.SessionData{}, fmt.Errorf("decode the state: %w", err)
	}
	return s, nil
}

// FinishRegistration checks a creation response.
func (a *Adapter) FinishRegistration(_ context.Context, u port.User, state, response []byte) (port.Registered, error) {
	session, err := decodeState(state)
	if err != nil {
		return port.Registered{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return port.Registered{}, mapError(err)
	}
	cred, err := a.w.CreateCredential(user{u: u}, session, parsed)
	if err != nil {
		return port.Registered{}, mapError(err)
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	return port.Registered{Credential: port.Credential{
		ID: cred.ID, PublicKey: cred.PublicKey, SignCount: cred.Authenticator.SignCount,
		AAGUID: cred.Authenticator.AAGUID, Transports: transports,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
	}}, nil
}

// BeginLogin makes the options of a login with no password.
func (a *Adapter) BeginLogin(_ context.Context) (port.Options, error) {
	assertion, session, err := a.w.BeginDiscoverableLogin(gowebauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return port.Options{}, fmt.Errorf("begin the login: %w", err)
	}
	return encode(assertion, session)
}

// ParseAssertion reads the credential ID and the user handle of a response.
func (a *Adapter) ParseAssertion(response []byte) ([]byte, []byte, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, nil, mapError(err)
	}
	return parsed.RawID, parsed.Response.UserHandle, nil
}

// FinishLogin checks the response of a login with no password.
func (a *Adapter) FinishLogin(_ context.Context, state, response []byte, u port.User, c port.Credential) (port.Asserted, error) {
	session, err := decodeState(state)
	if err != nil {
		return port.Asserted{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return port.Asserted{}, mapError(err)
	}
	lib := user{u: u, creds: []gowebauthn.Credential{libCredential(c)}}
	handler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		if string(userHandle) != string(u.Handle) || string(rawID) != string(c.ID) {
			return nil, errors.New("the credential or the user handle does not match")
		}
		return lib, nil
	}
	if _, _, err := a.w.ValidatePasskeyLogin(handler, session, parsed); err != nil {
		return port.Asserted{}, mapError(err)
	}
	return asserted(parsed), nil
}

func asserted(p *protocol.ParsedCredentialAssertionData) port.Asserted {
	f := p.Response.AuthenticatorData.Flags
	return port.Asserted{
		CredentialID: p.RawID, SignCount: p.Response.AuthenticatorData.Counter,
		BackupState: f.HasBackupState(), UserVerified: f.HasUserVerified(),
	}
}

// BeginSecondFactor makes the options of a second factor.
func (a *Adapter) BeginSecondFactor(_ context.Context, u port.User, creds []port.Credential) (port.Options, error) {
	assertion, session, err := a.w.BeginLogin(user{u: u, creds: libCredentials(creds)},
		gowebauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return port.Options{}, fmt.Errorf("begin the second factor: %w", err)
	}
	return encode(assertion, session)
}

// FinishSecondFactor checks the response of a second factor.
func (a *Adapter) FinishSecondFactor(_ context.Context, u port.User, creds []port.Credential, state, response []byte) (port.Asserted, error) {
	session, err := decodeState(state)
	if err != nil {
		return port.Asserted{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return port.Asserted{}, mapError(err)
	}
	if _, err := a.w.ValidateLogin(user{u: u, creds: libCredentials(creds)}, session, parsed); err != nil {
		return port.Asserted{}, mapError(err)
	}
	return asserted(parsed), nil
}

// mapError turns an error of the library into an error of the port. The text of
// the library error is not in the result, because it can have values of the
// request.
func mapError(err error) error {
	var unknown *protocol.ErrorUnknownCredential
	if errors.As(err, &unknown) {
		return port.ErrUnknownCredential
	}
	var pe *protocol.Error
	if errors.As(err, &pe) {
		text := strings.ToLower(pe.Details + " " + pe.DevInfo)
		switch {
		case strings.Contains(text, "origin") || strings.Contains(text, "rp hash"):
			return port.ErrBadOrigin
		case strings.Contains(text, "user verification"):
			return port.ErrUserVerification
		}
	}
	return port.ErrBadSignature
}
