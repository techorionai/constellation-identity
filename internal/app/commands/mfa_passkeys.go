package commands

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/passkeys"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/users"
	"github.com/techorionai/constellation-identity/internal/ports/webauthn"
)

// Errors of the passkeys. A handler maps them to a page or a status.
var (
	// ErrPasskeysOff means the service does not accept passkeys.
	ErrPasskeysOff = errors.New("passkeys are off")
	// ErrPasskeyNotFound means the user has no passkey with the ID.
	ErrPasskeyNotFound = errors.New("passkey_not_found")
	// ErrPasskeyLimit means the user has the largest number of passkeys.
	ErrPasskeyLimit = errors.New("passkey_limit")
	// ErrPasskeyInvalid means a ceremony failed. The user sees one text for all
	// causes.
	ErrPasskeyInvalid = errors.New("the passkey is not valid")
	// ErrCeremonyGone means the state of the ceremony does not exist or has
	// expired. The user must start again.
	ErrCeremonyGone = errors.New("the ceremony has expired")
)

// CeremonyTTL is the life of the state of a ceremony.
const CeremonyTTL = 5 * time.Minute

// Values of the attribute type of the metric identity.passkey.ceremonies.
const (
	CeremonyTypeRegister     = "register"
	CeremonyTypeLogin        = "login"
	CeremonyTypeSecondFactor = "second_factor"
)

// Values of the attribute outcome of the metric identity.passkey.ceremonies.
const (
	CeremonyOutcomeOK                = "ok"
	CeremonyOutcomeBadSignature      = "bad_signature"
	CeremonyOutcomeBadOrigin         = "bad_origin"
	CeremonyOutcomeUnknownCredential = "unknown_credential"
	CeremonyOutcomeCloneWarning      = "clone_warning"
	CeremonyOutcomeLimited           = "limited"
	CeremonyOutcomeExpired           = "expired"
)

// methodHWK is the value of the attribute method for a passkey.
const methodHWK = domain.AMRHardwareKey

func (m *MFA) ceremony(ctx context.Context, typ, outcome string) {
	m.ceremonies.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("type", typ), attribute.String("outcome", outcome)))
}

// passkeysReady reports whether the use case can run a ceremony.
func (m *MFA) passkeysReady() bool {
	return m.d.PasskeysOn && m.d.Passkeys != nil && m.d.WebAuthn != nil && m.d.Ceremonies != nil
}

func portCredential(c domain.PasskeyCredential) webauthn.Credential {
	return webauthn.Credential{
		ID: c.CredentialID, PublicKey: c.PublicKey, SignCount: c.SignCount, AAGUID: c.AAGUID,
		Transports: c.Transports, BackupEligible: c.BackupEligible, BackupState: c.BackupState,
	}
}

func portCredentials(cs []domain.PasskeyCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(cs))
	for _, c := range cs {
		out = append(out, portCredential(c))
	}
	return out
}

// userHandle returns the WebAuthn user handle of the user. It makes the handle
// at the first call.
func (m *MFA) userHandle(ctx context.Context, userID string) ([]byte, error) {
	candidate := make([]byte, domain.UserHandleLength)
	if _, err := rand.Read(candidate); err != nil {
		return nil, fmt.Errorf("random bytes: %w", err)
	}
	h, err := m.d.Passkeys.EnsureUserHandle(ctx, userID, candidate)
	if err != nil {
		return nil, fmt.Errorf("get the user handle: %w", err)
	}
	return h, nil
}

func (m *MFA) webauthnUser(ctx context.Context, u domain.User) (webauthn.User, error) {
	h, err := m.userHandle(ctx, u.ID)
	if err != nil {
		return webauthn.User{}, err
	}
	return webauthn.User{Handle: h, Name: u.Email, DisplayName: u.Name}, nil
}

// ceremonyOutcome maps an error of the WebAuthn port to the value of the metric.
func ceremonyOutcome(err error) string {
	switch {
	case errors.Is(err, webauthn.ErrBadOrigin):
		return CeremonyOutcomeBadOrigin
	case errors.Is(err, webauthn.ErrUnknownCredential):
		return CeremonyOutcomeUnknownCredential
	}
	return CeremonyOutcomeBadSignature
}

// --- registration ---

// BeginPasskey is the input of the first step of a registration.
type BeginPasskey struct {
	SessionID string
	UserID    string
	// Name is the name that the user gives to the new passkey.
	Name string
	// AuthRequest and ReturnTo are the place to go after the registration of a
	// user that must have MFA. They are optional.
	AuthRequest string
	ReturnTo    string
}

// BeginPasskeyRegistration checks the name and the limit, makes the creation
// options, and keeps the state of the ceremony. It returns the options for the
// browser. The errors: ErrPasskeysOff, domain.ErrInvalidPasskeyName,
// ErrPasskeyLimit, and ErrMFAUnavailable.
func (m *MFA) BeginPasskeyRegistration(ctx context.Context, in BeginPasskey) ([]byte, error) {
	if !m.passkeysReady() {
		return nil, ErrPasskeysOff
	}
	if err := domain.ValidatePasskeyName(in.Name); err != nil {
		return nil, err
	}
	creds, err := m.d.Passkeys.Credentials(ctx, in.UserID)
	if err != nil {
		return nil, fmt.Errorf("list the passkeys: %w", err)
	}
	if len(creds) >= domain.MaxPasskeys {
		return nil, ErrPasskeyLimit
	}
	user, err := m.d.Users.GetByID(ctx, in.UserID)
	if err != nil {
		return nil, fmt.Errorf("get the user: %w", err)
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	opts, err := m.d.WebAuthn.BeginRegistration(ctx, wu, portCredentials(creds))
	if err != nil {
		return nil, err
	}
	err = m.d.Ceremonies.Put(ctx, mfaflow.CeremonyRegister, domain.HashSecret(in.SessionID), domain.Ceremony{
		State: opts.State, UserID: in.UserID, Name: in.Name, AuthRequest: in.AuthRequest, ReturnTo: in.ReturnTo,
	}, CeremonyTTL)
	if err != nil {
		return nil, m.unavailable(ctx, "store the registration state", err)
	}
	return opts.JSON, nil
}

// FinishPasskey is the input of the last step of a registration.
type FinishPasskey struct {
	SessionID string
	UserID    string
	// SessionMethods are the methods (amr) of the session now.
	SessionMethods []string
	// Body is the response of the browser. It is not a secret, but it is not logged.
	Body []byte
}

// PasskeyAdded is the result of a good registration.
type PasskeyAdded struct {
	Passkey     domain.Passkey
	AuthRequest string
	ReturnTo    string
}

// withPasskeyMethods adds the methods of a passkey to the methods of a
// session that has no second factor.
func withPasskeyMethods(methods []string) []string {
	if domain.HasMFA(methods) {
		return methods
	}
	out := slices.Clone(methods)
	for _, v := range domain.MethodsPasskeyLogin() {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// FinishPasskeyRegistration checks the response of the browser and stores the
// passkey. A session with no second factor gets the methods hwk, user, and mfa.
func (m *MFA) FinishPasskeyRegistration(ctx context.Context, in FinishPasskey) (PasskeyAdded, error) {
	if !m.passkeysReady() {
		return PasskeyAdded{}, ErrPasskeysOff
	}
	cer, err := m.d.Ceremonies.Take(ctx, mfaflow.CeremonyRegister, domain.HashSecret(in.SessionID))
	if errors.Is(err, mfaflow.ErrNotFound) || (err == nil && cer.UserID != in.UserID) {
		m.ceremony(ctx, CeremonyTypeRegister, CeremonyOutcomeExpired)
		return PasskeyAdded{}, ErrCeremonyGone
	}
	if err != nil {
		return PasskeyAdded{}, m.unavailable(ctx, "take the registration state", err)
	}
	user, err := m.d.Users.GetByID(ctx, in.UserID)
	if err != nil {
		return PasskeyAdded{}, fmt.Errorf("get the user: %w", err)
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return PasskeyAdded{}, err
	}
	res, err := m.d.WebAuthn.FinishRegistration(ctx, wu, cer.State, in.Body)
	if err != nil {
		m.ceremony(ctx, CeremonyTypeRegister, ceremonyOutcome(err))
		m.d.Log.InfoContext(ctx, "identity.passkey.refused", "event", "identity.passkey.refused", "type", CeremonyTypeRegister, "user_id", in.UserID)
		return PasskeyAdded{}, ErrPasskeyInvalid
	}
	now := m.now()
	c := res.Credential
	pk := domain.PasskeyCredential{
		Passkey: domain.Passkey{
			ID: uuid.NewString(), UserID: in.UserID, Name: cer.Name, CreatedAt: now, BackupState: c.BackupState,
		},
		CredentialID: c.ID, PublicKey: c.PublicKey, SignCount: c.SignCount, AAGUID: c.AAGUID,
		Transports: c.Transports, BackupEligible: c.BackupEligible,
	}
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		// Lock the user row, then check the session again. A reset of the MFA
		// that ran first revoked the session, so the insert does not happen (R11).
		if _, err := m.d.Users.LockByID(ctx, in.UserID); err != nil {
			return err
		}
		sess, err := m.d.Sessions.GetByID(ctx, in.SessionID)
		if errors.Is(err, sessions.ErrNotFound) || (err == nil && !sess.Valid(m.now())) {
			return ErrCeremonyGone
		}
		if err != nil {
			return err
		}
		if err := m.d.Passkeys.Insert(ctx, pk, domain.MaxPasskeys); err != nil {
			return err
		}
		if !domain.HasMFA(in.SessionMethods) {
			return m.d.Sessions.SetMethods(ctx, in.SessionID, withPasskeyMethods(in.SessionMethods))
		}
		return nil
	}, txName("finish_passkey_registration"))
	switch {
	case errors.Is(err, ErrCeremonyGone):
		m.ceremony(ctx, CeremonyTypeRegister, CeremonyOutcomeExpired)
		return PasskeyAdded{}, ErrCeremonyGone
	case errors.Is(err, passkeys.ErrLimit):
		return PasskeyAdded{}, ErrPasskeyLimit
	case errors.Is(err, passkeys.ErrCredentialExists):
		m.ceremony(ctx, CeremonyTypeRegister, CeremonyOutcomeBadSignature)
		return PasskeyAdded{}, ErrPasskeyInvalid
	case err != nil:
		return PasskeyAdded{}, fmt.Errorf("store the passkey: %w", err)
	}
	m.ceremony(ctx, CeremonyTypeRegister, CeremonyOutcomeOK)
	m.d.Log.InfoContext(ctx, "identity.passkey.registered", "event", "identity.passkey.registered", "user_id", in.UserID)
	m.securityEvent(ctx, securityevents.ActionPasskeyAdd, securityevents.NoticePasskeyAdded, in.UserID, in.UserID)
	return PasskeyAdded{Passkey: pk.Passkey, AuthRequest: cer.AuthRequest, ReturnTo: cer.ReturnTo}, nil
}

// --- login with a passkey and no password ---

// BeginPasskeyLogin is the input of the first step of a login with no password.
type BeginPasskeyLogin struct {
	AuthRequest string
	ReturnTo    string
}

// PasskeyLoginOptions is the result of the first step of a login with no password.
type PasskeyLoginOptions struct {
	// Token is the value of the cookie that binds the ceremony to the browser. It
	// is a secret.
	Token string
	// JSON is the options for the browser.
	JSON []byte
}

// BeginPasskeyLogin makes the options of a login with no password.
func (m *MFA) BeginPasskeyLogin(ctx context.Context, in BeginPasskeyLogin) (PasskeyLoginOptions, error) {
	if !m.passkeysReady() {
		return PasskeyLoginOptions{}, ErrPasskeysOff
	}
	opts, err := m.d.WebAuthn.BeginLogin(ctx)
	if err != nil {
		return PasskeyLoginOptions{}, err
	}
	value, hash, err := domain.NewSecret()
	if err != nil {
		return PasskeyLoginOptions{}, err
	}
	err = m.d.Ceremonies.Put(ctx, mfaflow.CeremonyLogin, hash, domain.Ceremony{
		State: opts.State, AuthRequest: in.AuthRequest, ReturnTo: in.ReturnTo,
	}, CeremonyTTL)
	if err != nil {
		return PasskeyLoginOptions{}, m.unavailable(ctx, "store the login state", err)
	}
	return PasskeyLoginOptions{Token: value, JSON: opts.JSON}, nil
}

// PasskeyLogin is the input of the last step of a login with no password.
type PasskeyLogin struct {
	// Token is the value of the cookie of the first step.
	Token string
	Body  []byte
	IP    string
	// UserAgent and PreviousToken are for the session.
	UserAgent     string
	PreviousToken string
}

// FinishPasskeyLogin checks the response of a login with no password. The
// session gets the methods hwk, user, and mfa. It does not change the counters
// of the password login.
func (m *MFA) FinishPasskeyLogin(ctx context.Context, in PasskeyLogin) (VerifiedLogin, error) {
	if !m.passkeysReady() {
		return VerifiedLogin{}, ErrPasskeysOff
	}
	if in.Token == "" || len(in.Token) > domain.MaxTokenValueLength {
		return VerifiedLogin{}, ErrCeremonyGone
	}
	cer, err := m.d.Ceremonies.Take(ctx, mfaflow.CeremonyLogin, domain.HashSecret(in.Token))
	if errors.Is(err, mfaflow.ErrNotFound) {
		m.ceremony(ctx, CeremonyTypeLogin, CeremonyOutcomeExpired)
		return VerifiedLogin{}, ErrCeremonyGone
	}
	if err != nil {
		return VerifiedLogin{}, m.unavailable(ctx, "take the login state", err)
	}
	refuse := func(outcome string) (VerifiedLogin, error) {
		m.ceremony(ctx, CeremonyTypeLogin, outcome)
		m.d.Log.InfoContext(ctx, "identity.passkey.refused", "event", "identity.passkey.refused", "type", CeremonyTypeLogin, "outcome", outcome)
		return VerifiedLogin{}, ErrPasskeyInvalid
	}
	credID, handle, err := m.d.WebAuthn.ParseAssertion(in.Body)
	if err != nil {
		return refuse(ceremonyOutcome(err))
	}
	cred, err := m.d.Passkeys.ByCredentialID(ctx, credID)
	if errors.Is(err, passkeys.ErrNotFound) {
		return refuse(CeremonyOutcomeUnknownCredential)
	}
	if err != nil {
		return VerifiedLogin{}, fmt.Errorf("get the credential: %w", err)
	}
	user, err := m.d.Users.GetByID(ctx, cred.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return refuse(CeremonyOutcomeUnknownCredential)
	}
	if err != nil {
		return VerifiedLogin{}, fmt.Errorf("get the user: %w", err)
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return VerifiedLogin{}, err
	}
	// The user handle of the response and the user of the credential must be the
	// same user. A disabled user cannot log in.
	if string(handle) != string(wu.Handle) || user.Status != domain.UserActive {
		return refuse(CeremonyOutcomeUnknownCredential)
	}
	res, err := m.d.WebAuthn.FinishLogin(ctx, cer.State, in.Body, wu, portCredential(cred))
	if err != nil {
		return refuse(ceremonyOutcome(err))
	}
	if !domain.SignCountAccepted(cred.SignCount, res.SignCount) {
		m.cloneWarning(ctx, user.ID)
		return refuse(CeremonyOutcomeCloneWarning)
	}
	var issued IssuedSession
	errNotAdvanced := errors.New("the sign count was not advanced")
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		advanced, err := m.d.Passkeys.AdvanceSignCount(ctx, cred.ID, res.SignCount, res.BackupState, m.now())
		if err != nil {
			return err
		}
		if !advanced {
			return errNotAdvanced
		}
		issued, err = sessionStarter{sessionIssuer{repo: m.d.Sessions, policy: m.d.Policy, now: m.d.Now}}.
			start(ctx, user.ID, in.PreviousToken, in.UserAgent, in.IP, domain.MethodsPasskeyLogin())
		return err
	}, txName("passkey_login"))
	if errors.Is(err, errNotAdvanced) {
		m.cloneWarning(ctx, user.ID)
		return refuse(CeremonyOutcomeCloneWarning)
	}
	if err != nil {
		return VerifiedLogin{}, err
	}
	m.ceremony(ctx, CeremonyTypeLogin, CeremonyOutcomeOK)
	m.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", user.ID, "method", methodHWK)
	return VerifiedLogin{Session: issued, AuthRequest: cer.AuthRequest, ReturnTo: cer.ReturnTo}, nil
}

// cloneWarning logs the use of a credential with a sign count that is not
// larger. The record has no credential ID.
func (m *MFA) cloneWarning(ctx context.Context, userID string) {
	m.d.Log.WarnContext(ctx, "identity.passkey.clone_warning", "event", "identity.passkey.clone_warning", "user_id", userID)
}

// --- second factor ---

// BeginPasskeySecondFactor makes the options of a second factor for the user
// of a pending login. It returns ErrMFAPendingGone for a pending login that is
// gone, and ErrPasskeyInvalid for a user that has no passkey.
func (m *MFA) BeginPasskeySecondFactor(ctx context.Context, pendingToken string) ([]byte, error) {
	if !m.passkeysReady() {
		return nil, ErrPasskeysOff
	}
	p, err := m.pending(ctx, pendingToken)
	if err != nil {
		return nil, err
	}
	user, err := m.d.Users.GetByID(ctx, p.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return nil, ErrMFAPendingGone
	}
	if err != nil {
		return nil, fmt.Errorf("get the user: %w", err)
	}
	creds, err := m.d.Passkeys.Credentials(ctx, p.UserID)
	if err != nil {
		return nil, fmt.Errorf("list the passkeys: %w", err)
	}
	if len(creds) == 0 {
		return nil, ErrPasskeyInvalid
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	opts, err := m.d.WebAuthn.BeginSecondFactor(ctx, wu, portCredentials(creds))
	if err != nil {
		return nil, err
	}
	err = m.d.Ceremonies.Put(ctx, mfaflow.CeremonySecondFactor, domain.HashSecret(pendingToken), domain.Ceremony{
		State: opts.State, UserID: p.UserID,
	}, CeremonyTTL)
	if err != nil {
		return nil, m.unavailable(ctx, "store the second factor state", err)
	}
	return opts.JSON, nil
}

// PasskeySecondFactor is the input of the second factor step with a passkey.
type PasskeySecondFactor struct {
	PendingToken  string
	Body          []byte
	IP            string
	UserAgent     string
	PreviousToken string
}

// FinishPasskeySecondFactor checks the response of a passkey as the second
// factor of a pending login. The attempt limit and the failure counters of the
// TOTP check apply. The session gets the methods pwd, hwk, and mfa, and user if
// the authenticator verified the user.
func (m *MFA) FinishPasskeySecondFactor(ctx context.Context, in PasskeySecondFactor) (VerifiedLogin, error) {
	if !m.passkeysReady() {
		return VerifiedLogin{}, ErrPasskeysOff
	}
	p, err := m.pending(ctx, in.PendingToken)
	if err != nil {
		return VerifiedLogin{}, err
	}
	hash := domain.HashSecret(in.PendingToken)
	n, err := m.d.Pending.Attempt(ctx, hash, PendingLoginTTL)
	if err != nil {
		return VerifiedLogin{}, m.unavailable(ctx, "count the attempt", err)
	}
	if n > MaxPendingAttempts {
		_ = m.d.Pending.Delete(ctx, hash)
		return VerifiedLogin{}, ErrMFAPendingGone
	}
	limited, err := m.reserveFailure(ctx, p.UserID)
	if err != nil {
		return VerifiedLogin{}, err
	}
	if limited {
		m.count(ctx, methodHWK, MFAOutcomeLimited)
		m.ceremony(ctx, CeremonyTypeSecondFactor, CeremonyOutcomeLimited)
		m.d.Log.InfoContext(ctx, "identity.mfa.limited", "event", "identity.mfa.limited", "user_id", p.UserID)
		return VerifiedLogin{}, ErrTooManyAttempts
	}
	user, err := m.d.Users.GetByID(ctx, p.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && user.Status != domain.UserActive) {
		_ = m.d.Pending.Delete(ctx, hash)
		return VerifiedLogin{}, ErrMFAPendingGone
	}
	if err != nil {
		return VerifiedLogin{}, fmt.Errorf("get the user: %w", err)
	}
	bad := func(outcome string) (VerifiedLogin, error) {
		m.ceremony(ctx, CeremonyTypeSecondFactor, outcome)
		m.count(ctx, methodHWK, MFAOutcomeBadCode)
		m.d.Log.InfoContext(ctx, "identity.mfa.failed", "event", "identity.mfa.failed", "user_id", p.UserID, "method", methodHWK, "outcome", outcome)
		if n >= MaxPendingAttempts {
			_ = m.d.Pending.Delete(ctx, hash)
		}
		return VerifiedLogin{}, ErrPasskeyInvalid
	}
	cer, err := m.d.Ceremonies.Take(ctx, mfaflow.CeremonySecondFactor, hash)
	if errors.Is(err, mfaflow.ErrNotFound) || (err == nil && cer.UserID != p.UserID) {
		return bad(CeremonyOutcomeExpired)
	}
	if err != nil {
		return VerifiedLogin{}, m.unavailable(ctx, "take the second factor state", err)
	}
	creds, err := m.d.Passkeys.Credentials(ctx, p.UserID)
	if err != nil {
		return VerifiedLogin{}, fmt.Errorf("list the passkeys: %w", err)
	}
	wu, err := m.webauthnUser(ctx, user)
	if err != nil {
		return VerifiedLogin{}, err
	}
	res, err := m.d.WebAuthn.FinishSecondFactor(ctx, wu, portCredentials(creds), cer.State, in.Body)
	if err != nil {
		return bad(ceremonyOutcome(err))
	}
	idx := slices.IndexFunc(creds, func(c domain.PasskeyCredential) bool { return string(c.CredentialID) == string(res.CredentialID) })
	if idx < 0 {
		return bad(CeremonyOutcomeUnknownCredential)
	}
	cred := creds[idx]
	if !domain.SignCountAccepted(cred.SignCount, res.SignCount) {
		m.cloneWarning(ctx, p.UserID)
		return bad(CeremonyOutcomeCloneWarning)
	}
	if _, err := m.d.Pending.Take(ctx, hash); errors.Is(err, mfaflow.ErrNotFound) {
		return VerifiedLogin{}, ErrMFAPendingGone
	} else if err != nil {
		return VerifiedLogin{}, m.unavailable(ctx, "take the pending login", err)
	}
	var issued IssuedSession
	errNotAdvanced := errors.New("the sign count was not advanced")
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		advanced, err := m.d.Passkeys.AdvanceSignCount(ctx, cred.ID, res.SignCount, res.BackupState, m.now())
		if err != nil {
			return err
		}
		if !advanced {
			return errNotAdvanced
		}
		issued, err = sessionStarter{sessionIssuer{repo: m.d.Sessions, policy: m.d.Policy, now: m.d.Now}}.
			start(ctx, p.UserID, in.PreviousToken, in.UserAgent, in.IP, domain.MethodsPasskeySecondFactor(res.UserVerified))
		return err
	}, txName("verify_passkey_second_factor"))
	if errors.Is(err, errNotAdvanced) {
		m.cloneWarning(ctx, p.UserID)
		return bad(CeremonyOutcomeCloneWarning)
	}
	if err != nil {
		return VerifiedLogin{}, err
	}
	m.releaseFailure(ctx, p.UserID)
	m.count(ctx, methodHWK, MFAOutcomeOK)
	m.ceremony(ctx, CeremonyTypeSecondFactor, CeremonyOutcomeOK)
	m.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", p.UserID, "method", methodHWK)
	return VerifiedLogin{Session: issued, AuthRequest: p.AuthRequest, ReturnTo: p.ReturnTo}, nil
}

// --- list, rename, and removal ---

// ListPasskeys returns a page of the passkeys of a user. If checkUser is true,
// it returns ErrUserNotFound for a user that does not exist.
func (m *MFA) ListPasskeys(ctx context.Context, userID string, p ListPage, checkUser bool) (Page[domain.Passkey], error) {
	n, err := p.size()
	if err != nil {
		return Page[domain.Passkey]{}, err
	}
	cur, err := decodeUUIDCursor(p.Token)
	if err != nil {
		return Page[domain.Passkey]{}, err
	}
	if checkUser {
		if !uuidPattern.MatchString(userID) {
			return Page[domain.Passkey]{}, ErrUserNotFound
		}
		if _, err := m.d.Users.GetByID(ctx, userID); errors.Is(err, users.ErrNotFound) {
			return Page[domain.Passkey]{}, ErrUserNotFound
		} else if err != nil {
			return Page[domain.Passkey]{}, fmt.Errorf("get the user: %w", err)
		}
	}
	if m.d.Passkeys == nil {
		return Page[domain.Passkey]{}, nil
	}
	items, err := m.d.Passkeys.List(ctx, userID, cur, n+1)
	if err != nil {
		return Page[domain.Passkey]{}, fmt.Errorf("list the passkeys: %w", err)
	}
	out := Page[domain.Passkey]{Items: items}
	if len(items) > n {
		out.Items = items[:n]
		last := out.Items[n-1]
		out.Next = EncodeTimeCursor(last.CreatedAt, last.ID)
	}
	return out, nil
}

// RenamePasskey is the input of the rename of a passkey.
type RenamePasskey struct {
	UserID    string
	PasskeyID string
	Name      string
	// Actor is the ID of the principal that does the rename.
	Actor string
}

// RenamePasskey renames a passkey of a user. The order of the checks:
// ErrPasskeyNotFound for an ID that is not a UUID or not a passkey of the user,
// then domain.ErrInvalidPasskeyName. It writes the audit entry with the old
// name and the new name.
func (m *MFA) RenamePasskey(ctx context.Context, in RenamePasskey) (domain.Passkey, error) {
	if m.d.Passkeys == nil || !uuidPattern.MatchString(in.PasskeyID) {
		return domain.Passkey{}, ErrPasskeyNotFound
	}
	pk, err := m.d.Passkeys.Get(ctx, in.UserID, in.PasskeyID)
	if errors.Is(err, passkeys.ErrNotFound) {
		return domain.Passkey{}, ErrPasskeyNotFound
	}
	if err != nil {
		return domain.Passkey{}, fmt.Errorf("get the passkey: %w", err)
	}
	if err := domain.ValidatePasskeyName(in.Name); err != nil {
		return domain.Passkey{}, err
	}
	old, err := m.d.Passkeys.Rename(ctx, in.UserID, in.PasskeyID, in.Name)
	if errors.Is(err, passkeys.ErrNotFound) {
		return domain.Passkey{}, ErrPasskeyNotFound
	}
	if err != nil {
		return domain.Passkey{}, fmt.Errorf("rename the passkey: %w", err)
	}
	pk.Name = in.Name
	if err := m.d.Events.RecordAudit(ctx, securityevents.AuditEntry{
		Action: securityevents.ActionPasskeyRename, Actor: in.Actor, TargetUserID: in.UserID,
		Result: securityevents.ResultSuccess, At: m.now(),
		Changes: map[string]string{"old_name": old, "new_name": in.Name},
	}); err != nil {
		m.d.Log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed", "action", securityevents.ActionPasskeyRename, "error", err)
	}
	return pk, nil
}

// RemovePasskey is the input of the removal of a passkey.
type RemovePasskey struct {
	UserID    string
	PasskeyID string
	// Actor is the ID of the principal that does the removal.
	Actor string
}

// RemovePasskey removes a passkey of a user and revokes the sessions and the
// refresh token families of the user that were made with a passkey. The order
// of the checks: ErrPasskeyNotFound, then ErrMFARequired when the policy needs
// MFA for the user and the passkey is the last second factor that the service
// accepts. It writes the audit entry and sends the notice.
func (m *MFA) RemovePasskey(ctx context.Context, in RemovePasskey) error {
	if m.d.Passkeys == nil || !uuidPattern.MatchString(in.PasskeyID) {
		return ErrPasskeyNotFound
	}
	// The user row is locked first, so two removals of one user run in sequence.
	// The check of the rule and the removal are in the same transaction (R1).
	err := m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := m.d.Users.LockByID(ctx, in.UserID); err != nil {
			return err
		}
		if _, err := m.d.Passkeys.Get(ctx, in.UserID, in.PasskeyID); err != nil {
			return err
		}
		state, err := m.state(ctx, in.UserID)
		if err != nil {
			return fmt.Errorf("read the MFA state: %w", err)
		}
		required, err := m.needsMFA(ctx, in.UserID)
		if err != nil {
			return err
		}
		// Before the removal the user has an accepted second factor if TOTP exists or
		// an accepted passkey exists. The removal must not take the last one.
		if required && !state.HasTOTP && state.AcceptedPasskeys() == 1 {
			return ErrMFARequired
		}
		if err := m.d.Passkeys.Remove(ctx, in.UserID, in.PasskeyID); err != nil {
			return err
		}
		// A session does not record which passkey made it. All sessions and
		// families with a passkey end.
		_, err = m.d.Sessions.RevokeWithMethod(ctx, in.UserID, domain.AMRHardwareKey, m.now())
		return err
	}, txName("remove_passkey"))
	if errors.Is(err, ErrMFARequired) {
		return ErrMFARequired
	}
	if errors.Is(err, users.ErrNotFound) {
		return ErrPasskeyNotFound
	}
	if errors.Is(err, passkeys.ErrNotFound) {
		return ErrPasskeyNotFound
	}
	if err != nil {
		return fmt.Errorf("remove the passkey: %w", err)
	}
	m.d.Log.InfoContext(ctx, "identity.passkey.removed", "event", "identity.passkey.removed", "user_id", in.UserID)
	m.securityEvent(ctx, securityevents.ActionPasskeyRemove, securityevents.NoticePasskeyRemoved, in.Actor, in.UserID)
	return nil
}
