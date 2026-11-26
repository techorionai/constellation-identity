package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/techorionai/constellation-platform-go/transaction"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/loginlimiter"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/passkeys"
	"github.com/techorionai/constellation-identity/internal/ports/secretbox"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/totp"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
	"github.com/techorionai/constellation-identity/internal/ports/webauthn"
)

// Errors of the second factor. A handler maps them to a page or a status.
var (
	// ErrMFAUnavailable means a store of the second factor does not answer. The
	// login fails closed.
	ErrMFAUnavailable = errors.New("the second factor store is not available")
	// ErrMFAPendingGone means the pending login does not exist, has expired, or
	// has no attempt left. The user must log in again.
	ErrMFAPendingGone = errors.New("the pending login is gone")
	// ErrMFABadCode means the code is not correct.
	ErrMFABadCode = errors.New("the code is not correct")
	// ErrMFAReplay means the code is correct but its time step was used already.
	ErrMFAReplay = errors.New("the code was used already")
	// ErrTOTPEnabled means the user has a TOTP factor already.
	ErrTOTPEnabled = errors.New("totp is enabled already")
	// ErrTOTPNotFound means the user has no TOTP factor.
	ErrTOTPNotFound = errors.New("totp_not_found")
	// ErrSetupExpired means the setup secret does not exist or has expired.
	ErrSetupExpired = errors.New("the setup has expired")
	// ErrMFARequired means the change would leave a user with no second factor
	// where the policy needs one, or an admin would reset the own MFA.
	ErrMFARequired = errors.New("mfa_required")
)

// Settings of the pending login and the setup.
const (
	// PendingLoginTTL is the life of a pending login.
	PendingLoginTTL = 5 * time.Minute
	// MaxPendingAttempts is the number of attempts on one pending login.
	MaxPendingAttempts = 5
	// SetupTTL is the life of a TOTP setup secret.
	SetupTTL = 10 * time.Minute
	// DailyMaxFailures is the long failure limit of one user.
	DailyMaxFailures = 30
	// DailyFailureWindow is the window of DailyMaxFailures.
	DailyFailureWindow = 24 * time.Hour
)

// Values of the attribute outcome of the metric identity.mfa.verifications.
const (
	MFAOutcomeOK      = "ok"
	MFAOutcomeBadCode = "bad_code"
	MFAOutcomeReplay  = "replay"
	MFAOutcomeLimited = "limited"
)

// MFADeps are the ports and the settings of the second factor use cases.
type MFADeps struct {
	Users     users.Repository
	UserRoles userroles.Repository
	Sessions  sessions.Repository
	MFA       mfa.Repository
	TOTP      totp.Service
	Sealer    secretbox.Sealer
	// Passkeys, WebAuthn, and Ceremonies are the ports of the passkeys. A nil
	// Passkeys means that the use case has no passkeys. A nil WebAuthn or Ceremonies
	// means that the use case cannot run a ceremony.
	Passkeys   passkeys.Repository
	WebAuthn   webauthn.Service
	Ceremonies mfaflow.Ceremonies
	// PasskeysOn is true when the service accepts passkeys. A stored passkey is a
	// second factor only then.
	PasskeysOn bool
	Pending    mfaflow.PendingLogins
	Setups     mfaflow.SetupSecrets
	Failures   mfaflow.Failures
	Limiter    loginlimiter.Limiter
	Events     securityevents.Events
	Tx         transaction.Transactor
	Policy     domain.SessionPolicy
	// RequireMFAForAdmins is the setting IDENTITY_MFA__REQUIRE_FOR_ADMINS.
	RequireMFAForAdmins bool
	// Issuer is the issuer name in the authenticator app.
	Issuer string
	// MaxFailures and FailureWindow are the failure limit of one user.
	MaxFailures   int64
	FailureWindow time.Duration
	Log           *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// MFA holds the use cases of the second factor.
type MFA struct {
	d             MFADeps
	verifications metric.Int64Counter
	ceremonies    metric.Int64Counter
}

// NewMFA makes the use cases.
func NewMFA(d MFADeps) (*MFA, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	c, err := otel.Meter("identity").Int64Counter("identity.mfa.verifications",
		metric.WithDescription("Second factor checks by method and outcome."))
	if err != nil {
		return nil, fmt.Errorf("make the MFA counter: %w", err)
	}
	ceremonies, err := otel.Meter("identity").Int64Counter("identity.passkey.ceremonies",
		metric.WithDescription("Passkey ceremonies by type and outcome."))
	if err != nil {
		return nil, fmt.Errorf("make the passkey counter: %w", err)
	}
	return &MFA{d: d, verifications: c, ceremonies: ceremonies}, nil
}

// state reads the MFA data of a user and sets the flag of the passkey rule.
func (m *MFA) state(ctx context.Context, userID string) (domain.MFAState, error) {
	st, err := m.d.MFA.State(ctx, userID)
	if err != nil {
		return domain.MFAState{}, err
	}
	st.PasskeysOn = m.d.PasskeysOn
	return st, nil
}

func (m *MFA) now() time.Time { return m.d.Now().UTC().Truncate(time.Microsecond) }

func (m *MFA) count(ctx context.Context, method, outcome string) {
	m.verifications.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("method", method), attribute.String("outcome", outcome)))
}

func (m *MFA) unavailable(ctx context.Context, what string, err error) error {
	m.d.Log.ErrorContext(ctx, "identity.mfa.unavailable", "event", "identity.mfa.unavailable", "step", what, "error", err)
	return ErrMFAUnavailable
}

// --- second factor of the login ---

// VerifyLogin is the input of the second factor step of a login.
type VerifyLogin struct {
	// PendingToken is the value of the cookie of the pending login.
	PendingToken string
	// Code is the TOTP code, or the recovery code if Recovery is true. It is a secret.
	Code     string
	Recovery bool
	IP       string
	// UserAgent and PreviousToken are for the session.
	UserAgent     string
	PreviousToken string
}

// VerifiedLogin is the result of a good second factor.
type VerifiedLogin struct {
	Session IssuedSession
	// AuthRequest and ReturnTo are the place to go, from the first step.
	AuthRequest string
	ReturnTo    string
}

// PendingInfo is what the second factor page needs from a pending login.
type PendingInfo struct {
	// AuthRequest is the ID of the auth request of the login, or empty.
	AuthRequest string
	// HasTOTP, HasRecoveryCodes, and HasPasskey tell which second factors the
	// page offers. HasPasskey is true only when the service accepts passkeys.
	HasTOTP          bool
	HasRecoveryCodes bool
	HasPasskey       bool
}

// CheckPending tells whether the pending login exists and has not expired. It
// returns ErrMFAPendingGone if not.
func (m *MFA) CheckPending(ctx context.Context, token string) (PendingInfo, error) {
	p, err := m.pending(ctx, token)
	if err != nil {
		return PendingInfo{}, err
	}
	st, err := m.state(ctx, p.UserID)
	if err != nil {
		return PendingInfo{}, m.unavailable(ctx, "read the MFA state", err)
	}
	return PendingInfo{
		AuthRequest: p.AuthRequest, HasTOTP: st.HasTOTP, HasRecoveryCodes: st.CodesRemaining > 0,
		HasPasskey: st.AcceptedPasskeys() > 0,
	}, nil
}

func (m *MFA) pending(ctx context.Context, token string) (domain.PendingLogin, error) {
	if token == "" || len(token) > domain.MaxTokenValueLength {
		return domain.PendingLogin{}, ErrMFAPendingGone
	}
	hash := domain.HashSecret(token)
	p, err := m.d.Pending.Get(ctx, hash)
	if errors.Is(err, mfaflow.ErrNotFound) {
		return domain.PendingLogin{}, ErrMFAPendingGone
	}
	if err != nil {
		return domain.PendingLogin{}, m.unavailable(ctx, "get the pending login", err)
	}
	if !m.now().Before(p.ExpiresAt) {
		_ = m.d.Pending.Delete(ctx, hash)
		return domain.PendingLogin{}, ErrMFAPendingGone
	}
	return p, nil
}

// VerifyLogin checks the second factor of a pending login. On a good code it
// removes the pending login and makes or keeps the session with the new methods.
func (m *MFA) VerifyLogin(ctx context.Context, in VerifyLogin) (VerifiedLogin, error) {
	method := domain.AMROTP
	if in.Recovery {
		method = domain.AMRRecovery
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
	// Reserve the attempt before the check, so parallel requests cannot all pass
	// the limit. Two counters apply: a short window and a long window.
	limited, err := m.reserveFailure(ctx, p.UserID)
	if err != nil {
		return VerifiedLogin{}, err
	}
	if limited {
		m.count(ctx, method, MFAOutcomeLimited)
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

	// The check does not change the factor. The factor is used only in the
	// transaction that starts the session (R2).
	var (
		consume func(context.Context) (bool, error)
		methods []string
	)
	if in.Recovery {
		consume, err = m.checkRecovery(ctx, p.UserID, in.Code)
		methods = domain.MethodsRecovery()
	} else {
		consume, err = m.checkTOTP(ctx, p.UserID, in.Code)
		methods = domain.MethodsTOTP()
	}
	if err != nil && !errors.Is(err, ErrMFAReplay) {
		return VerifiedLogin{}, err
	}
	if consume == nil {
		return VerifiedLogin{}, m.badCode(ctx, p.UserID, method, hash, n, err)
	}

	if _, err := m.d.Pending.Take(ctx, hash); errors.Is(err, mfaflow.ErrNotFound) {
		return VerifiedLogin{}, ErrMFAPendingGone
	} else if err != nil {
		return VerifiedLogin{}, m.unavailable(ctx, "take the pending login", err)
	}
	// The session and the use of the code change in one transaction. If the
	// session cannot start, or a parallel request used the code, the transaction
	// ends with no change. The code stays valid in the first case.
	var issued IssuedSession
	errNotUsed := errors.New("the factor was not used")
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		issued, err = sessionStarter{sessionIssuer{repo: m.d.Sessions, policy: m.d.Policy, now: m.d.Now}}.
			start(ctx, p.UserID, in.PreviousToken, in.UserAgent, in.IP, methods)
		if err != nil {
			return err
		}
		used, err := consume(ctx)
		if err != nil {
			return err
		}
		if !used {
			return errNotUsed
		}
		return nil
	}, txName("verify_second_factor"))
	if errors.Is(err, errNotUsed) {
		// A parallel request used the same code.
		return VerifiedLogin{}, m.badCode(ctx, p.UserID, method, hash, n, ErrMFAReplay)
	}
	if err != nil {
		return VerifiedLogin{}, err
	}
	m.releaseFailure(ctx, p.UserID)
	m.count(ctx, method, MFAOutcomeOK)
	m.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", p.UserID, "method", method)
	if in.Recovery {
		m.d.Log.InfoContext(ctx, "identity.mfa.recovery_code_used", "event", "identity.mfa.recovery_code_used", "user_id", p.UserID)
	}
	return VerifiedLogin{Session: issued, AuthRequest: p.AuthRequest, ReturnTo: p.ReturnTo}, nil
}

// badCode counts and logs a wrong or used code and returns the error for the user.
func (m *MFA) badCode(ctx context.Context, userID, method, hash string, attempts int64, cause error) error {
	outcome := MFAOutcomeBadCode
	if errors.Is(cause, ErrMFAReplay) {
		outcome = MFAOutcomeReplay
	}
	m.count(ctx, method, outcome)
	m.d.Log.InfoContext(ctx, "identity.mfa.failed", "event", "identity.mfa.failed", "user_id", userID, "method", method, "outcome", outcome)
	if attempts >= MaxPendingAttempts {
		_ = m.d.Pending.Delete(ctx, hash)
	}
	if outcome == MFAOutcomeReplay {
		return ErrMFAReplay
	}
	return ErrMFABadCode
}

// failureKeys are the keys of the two failure counters of a user. The second
// counter has a long window, so a slow guess loop is also limited (R13).
func failureKeys(userID string) [2]string { return [2]string{userID, "day:" + userID} }

// reserveFailure adds one attempt to both counters. It returns true if one
// counter is over its limit. At the first attempt over a limit it sends a
// notice to the user.
func (m *MFA) reserveFailure(ctx context.Context, userID string) (bool, error) {
	keys := failureKeys(userID)
	limits := [2]struct {
		window time.Duration
		max    int64
	}{{m.d.FailureWindow, m.d.MaxFailures}, {DailyFailureWindow, DailyMaxFailures}}
	limited := false
	for i, key := range keys {
		n, err := m.d.Failures.Reserve(ctx, key, limits[i].window)
		if err != nil {
			return false, m.unavailable(ctx, "reserve the failure counter", err)
		}
		if n > limits[i].max {
			limited = true
		}
		if n == limits[i].max+1 {
			m.notifyLimit(ctx, userID)
		}
	}
	return limited, nil
}

func (m *MFA) releaseFailure(ctx context.Context, userID string) {
	for _, key := range failureKeys(userID) {
		if err := m.d.Failures.Release(ctx, key); err != nil {
			m.d.Log.WarnContext(ctx, "identity.mfa.release_failed", "event", "identity.mfa.release_failed", "error", err)
		}
	}
}

// notifyLimit tells the user that the second factor attempts reached a limit.
// This can mean that someone knows the password.
func (m *MFA) notifyLimit(ctx context.Context, userID string) {
	m.d.Log.WarnContext(ctx, "identity.mfa.limit_reached", "event", "identity.mfa.limit_reached", "user_id", userID)
	if err := m.d.Events.NotifyUser(ctx, securityevents.Notice{Kind: securityevents.NoticeMfaLimited, TargetUserID: userID, At: m.now()}); err != nil {
		m.d.Log.ErrorContext(ctx, "identity.security_notice.failed", "event", "identity.security_notice.failed", "kind", securityevents.NoticeMfaLimited, "error", err)
	}
}

// checkTOTP checks a TOTP code against the secret of the user. It does not
// use the time step. It returns a function that uses the step, or nil for a
// wrong code. It returns ErrMFAReplay with a nil function for a good code with
// a step that was used.
func (m *MFA) checkTOTP(ctx context.Context, userID, code string) (func(context.Context) (bool, error), error) {
	rec, err := m.d.MFA.GetTOTP(ctx, userID)
	if errors.Is(err, mfa.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get the totp factor: %w", err)
	}
	secret, err := m.d.Sealer.Open(userID, rec.Secret)
	if err != nil {
		return nil, fmt.Errorf("open the totp secret: %w", err)
	}
	defer clear(secret)
	now := m.now()
	step, ok := m.d.TOTP.Check(secret, code, now)
	if !ok {
		return nil, nil
	}
	if step <= rec.LastUsedStep {
		return nil, ErrMFAReplay
	}
	return func(ctx context.Context) (bool, error) {
		advanced, err := m.d.MFA.AdvanceStep(ctx, userID, step, now)
		if err != nil {
			return false, fmt.Errorf("use the time step: %w", err)
		}
		return advanced, nil
	}, nil
}

// checkRecovery checks a recovery code. It does not use the code. It returns a
// function that uses the code, or nil for a code that is not valid.
func (m *MFA) checkRecovery(ctx context.Context, userID, code string) (func(context.Context) (bool, error), error) {
	norm, err := domain.NormalizeRecoveryCode(code)
	if err != nil {
		return nil, nil
	}
	hash := domain.HashRecoveryCode(norm)
	has, err := m.d.MFA.HasRecoveryCode(ctx, userID, hash)
	if err != nil {
		return nil, fmt.Errorf("find the recovery code: %w", err)
	}
	if !has {
		return nil, nil
	}
	return func(ctx context.Context) (bool, error) {
		used, err := m.d.MFA.UseRecoveryCode(ctx, userID, hash, m.now())
		if err != nil {
			return false, fmt.Errorf("use the recovery code: %w", err)
		}
		return used, nil
	}, nil
}

// --- state ---

// MFAStatus is the MFA data of a user and the policy for the user.
type MFAStatus struct {
	State domain.MFAState
	// Required is true when the policy needs MFA for the user.
	Required bool
}

// Status returns the MFA data of a user. It returns ErrUserNotFound for a user
// that does not exist.
func (m *MFA) Status(ctx context.Context, userID string) (MFAStatus, error) {
	if !uuidPattern.MatchString(userID) {
		return MFAStatus{}, ErrUserNotFound
	}
	if _, err := m.d.Users.GetByID(ctx, userID); errors.Is(err, users.ErrNotFound) {
		return MFAStatus{}, ErrUserNotFound
	} else if err != nil {
		return MFAStatus{}, fmt.Errorf("get the user: %w", err)
	}
	return m.status(ctx, userID)
}

func (m *MFA) status(ctx context.Context, userID string) (MFAStatus, error) {
	state, err := m.state(ctx, userID)
	if err != nil {
		return MFAStatus{}, fmt.Errorf("read the MFA state: %w", err)
	}
	required, err := m.needsMFA(ctx, userID)
	if err != nil {
		return MFAStatus{}, err
	}
	return MFAStatus{State: state, Required: required}, nil
}

func (m *MFA) needsMFA(ctx context.Context, userID string) (bool, error) {
	if !m.d.RequireMFAForAdmins {
		return false, nil
	}
	granted, err := m.d.UserRoles.GrantedPermissions(ctx, userID, domain.ImplicitUserRoles(domain.UserActive)...)
	if err != nil {
		return false, fmt.Errorf("get the permissions: %w", err)
	}
	return domain.NeedsMFA(true, granted), nil
}

// --- setup ---

// BeginSetup is the input of the first step of the TOTP setup.
type BeginSetup struct {
	SessionID string
	UserID    string
	// Account is the label in the authenticator app (the email of the user).
	Account string
}

// SetupInfo is the data that the setup page shows. The values are secrets.
type SetupInfo struct {
	Secret string
	URI    string
	QRPNG  []byte
}

func setupKey(sessionID string) string { return domain.HashSecret(sessionID) }

// setupSealID is the identifier that binds a sealed setup secret. It is not the
// ID of the user, so a sealed setup secret does not open as the stored factor.
func setupSealID(userID string) string { return "setup:" + userID }

// readSetup reads and opens the setup secret. The store holds it sealed (R3).
func (m *MFA) readSetup(ctx context.Context, userID, key string) ([]byte, error) {
	sealed, err := m.d.Setups.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	secret, err := m.d.Sealer.Open(setupSealID(userID), sealed)
	if err != nil {
		return nil, fmt.Errorf("open the setup secret: %w", err)
	}
	return secret, nil
}

// createSetup makes a secret and stores it sealed if the key has no value. If a
// parallel request stored a secret first, it returns that secret (R10).
func (m *MFA) createSetup(ctx context.Context, userID, key string) ([]byte, error) {
	secret, err := m.d.TOTP.NewSecret()
	if err != nil {
		return nil, fmt.Errorf("make the secret: %w", err)
	}
	sealed, _, err := m.d.Sealer.Seal(setupSealID(userID), secret)
	if err != nil {
		return nil, fmt.Errorf("seal the setup secret: %w", err)
	}
	created, err := m.d.Setups.PutIfAbsent(ctx, key, sealed, SetupTTL)
	if err != nil {
		return nil, err
	}
	if created {
		return secret, nil
	}
	clear(secret)
	return m.readSetup(ctx, userID, key)
}

// BeginSetup makes the secret of the setup, or reads the secret that the same
// session made before. It returns ErrTOTPEnabled if the user has a factor.
func (m *MFA) BeginSetup(ctx context.Context, in BeginSetup) (SetupInfo, error) {
	state, err := m.state(ctx, in.UserID)
	if err != nil {
		return SetupInfo{}, fmt.Errorf("read the MFA state: %w", err)
	}
	if state.HasTOTP {
		return SetupInfo{}, ErrTOTPEnabled
	}
	key := setupKey(in.SessionID)
	secret, err := m.readSetup(ctx, in.UserID, key)
	if errors.Is(err, mfaflow.ErrNotFound) {
		secret, err = m.createSetup(ctx, in.UserID, key)
	}
	if err != nil {
		return SetupInfo{}, m.unavailable(ctx, "store the setup secret", err)
	}
	defer clear(secret)
	uri := m.d.TOTP.URI(m.d.Issuer, in.Account, secret)
	qr, err := m.d.TOTP.QRCode(uri)
	if err != nil {
		return SetupInfo{}, fmt.Errorf("make the QR code: %w", err)
	}
	return SetupInfo{Secret: m.d.TOTP.Base32(secret), URI: uri, QRPNG: qr}, nil
}

// FinishSetup is the input of the last step of the TOTP setup.
type FinishSetup struct {
	SessionID string
	UserID    string
	// Code is the first TOTP code. It is a secret.
	Code string
}

// SetupResult is the result of a good setup. The recovery codes are secrets.
// They are in the form of two groups of 5.
type SetupResult struct {
	RecoveryCodes []string
}

// FinishSetup checks the first code, stores the secret, and makes the
// recovery codes. The session gets the methods otp and mfa.
func (m *MFA) FinishSetup(ctx context.Context, in FinishSetup) (SetupResult, error) {
	failures, err := m.d.Failures.Reserve(ctx, in.UserID, m.d.FailureWindow)
	if err != nil {
		return SetupResult{}, m.unavailable(ctx, "reserve the failure counter", err)
	}
	if failures > m.d.MaxFailures {
		m.count(ctx, domain.AMROTP, MFAOutcomeLimited)
		return SetupResult{}, ErrTooManyAttempts
	}
	key := setupKey(in.SessionID)
	secret, err := m.readSetup(ctx, in.UserID, key)
	if errors.Is(err, mfaflow.ErrNotFound) {
		return SetupResult{}, ErrSetupExpired
	}
	if err != nil {
		return SetupResult{}, m.unavailable(ctx, "read the setup secret", err)
	}
	defer clear(secret)
	now := m.now()
	step, ok := m.d.TOTP.Check(secret, in.Code, now)
	if !ok {
		m.count(ctx, domain.AMROTP, MFAOutcomeBadCode)
		return SetupResult{}, ErrMFABadCode
	}
	sealed, keyID, err := m.d.Sealer.Seal(in.UserID, secret)
	if err != nil {
		return SetupResult{}, err
	}
	codes, err := domain.NewRecoveryCodes()
	if err != nil {
		return SetupResult{}, err
	}
	hashes := make([][]byte, len(codes))
	shown := make([]string, len(codes))
	for i, c := range codes {
		hashes[i], shown[i] = domain.HashRecoveryCode(c), domain.FormatRecoveryCode(c)
	}
	// The time step of the first code counts as used, so the same code cannot log in.
	// The factor and the session methods change in one transaction. A failure
	// leaves no factor, so the user can try again and sees the recovery codes (R5).
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		err := m.d.MFA.EnableTOTP(ctx, domain.TOTPRecord{
			UserID: in.UserID, Secret: sealed, KeyID: keyID, LastUsedStep: step, CreatedAt: now,
		}, hashes, now)
		if err != nil {
			return err
		}
		return m.d.Sessions.SetMethods(ctx, in.SessionID, domain.MethodsTOTP())
	}, txName("finish_totp_setup"))
	if errors.Is(err, mfa.ErrAlreadyEnabled) {
		return SetupResult{}, ErrTOTPEnabled
	}
	if err != nil {
		return SetupResult{}, fmt.Errorf("store the totp factor: %w", err)
	}
	if err := m.d.Setups.Delete(ctx, key); err != nil {
		m.d.Log.WarnContext(ctx, "identity.mfa.setup_cleanup_failed", "event", "identity.mfa.setup_cleanup_failed", "error", err)
	}
	if err := m.d.Failures.Release(ctx, in.UserID); err != nil {
		m.d.Log.WarnContext(ctx, "identity.mfa.release_failed", "event", "identity.mfa.release_failed", "error", err)
	}
	m.count(ctx, domain.AMROTP, MFAOutcomeOK)
	m.d.Log.InfoContext(ctx, "identity.mfa.enabled", "event", "identity.mfa.enabled", "user_id", in.UserID)
	return SetupResult{RecoveryCodes: shown}, nil
}

// RegenerateRecoveryCodes replaces the recovery codes of a user that has TOTP.
// It returns the new codes in the form of two groups of 5.
func (m *MFA) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	state, err := m.state(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("read the MFA state: %w", err)
	}
	if !state.HasTOTP {
		return nil, ErrTOTPNotFound
	}
	codes, err := domain.NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(codes))
	shown := make([]string, len(codes))
	for i, c := range codes {
		hashes[i], shown[i] = domain.HashRecoveryCode(c), domain.FormatRecoveryCode(c)
	}
	if err := m.d.MFA.ReplaceRecoveryCodes(ctx, userID, hashes, m.now()); err != nil {
		return nil, fmt.Errorf("replace the recovery codes: %w", err)
	}
	m.d.Log.InfoContext(ctx, "identity.mfa.recovery_codes_replaced", "event", "identity.mfa.recovery_codes_replaced", "user_id", userID)
	return shown, nil
}

// --- removal and reset ---

// RemoveTOTP is the input of the removal of the TOTP factor.
type RemoveTOTP struct {
	UserID string
	// Actor is the ID of the principal that does the removal.
	Actor string
}

// RemoveTOTP removes the TOTP factor and the recovery codes of a user. It does
// not remove the passkeys. The order of the checks: ErrTOTPNotFound, then
// ErrMFARequired when the policy needs MFA for the user and no passkey that the
// service accepts stays. It writes the audit entry and sends the notice.
func (m *MFA) RemoveTOTP(ctx context.Context, in RemoveTOTP) error {
	state, err := m.state(ctx, in.UserID)
	if err != nil {
		return fmt.Errorf("read the MFA state: %w", err)
	}
	if !state.HasTOTP {
		return ErrTOTPNotFound
	}
	required, err := m.needsMFA(ctx, in.UserID)
	if err != nil {
		return err
	}
	// A passkey that the service accepts stays as the second factor.
	if required && state.AcceptedPasskeys() == 0 {
		return ErrMFARequired
	}
	// The other sessions and the refresh token families of the user lose the
	// methods of the second factor (R4).
	err = m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := m.d.MFA.RemoveAll(ctx, in.UserID); err != nil {
			return err
		}
		return m.d.Sessions.DropSecondFactor(ctx, in.UserID)
	}, txName("remove_totp"))
	if err != nil {
		return fmt.Errorf("remove the factors: %w", err)
	}
	m.d.Log.InfoContext(ctx, "identity.mfa.removed", "event", "identity.mfa.removed", "user_id", in.UserID)
	m.securityEvent(ctx, securityevents.ActionTotpRemove, securityevents.NoticeTotpRemoved, in.Actor, in.UserID)
	return nil
}

// ResetMFA is the input of the reset of the MFA of a user.
type ResetMFA struct {
	UserID string
	// Actor is the ID of the admin, or securityevents.ActorCLI for the subcommand.
	Actor string
}

// ResetMFA removes the factors of a user and revokes all sessions and refresh
// token families of the user. It does not remove the password or the API
// tokens. The order of the checks: ErrUserNotFound, then ErrMFARequired when
// the actor is the user (R8). The audit entry and the notice follow the change.
func (m *MFA) ResetMFA(ctx context.Context, in ResetMFA) error {
	if !uuidPattern.MatchString(in.UserID) {
		return ErrUserNotFound
	}
	if _, err := m.d.Users.GetByID(ctx, in.UserID); errors.Is(err, users.ErrNotFound) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("get the user: %w", err)
	}
	if in.Actor == in.UserID {
		return ErrMFARequired
	}
	err := m.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := m.d.MFA.RemoveAll(ctx, in.UserID); err != nil {
			return err
		}
		if m.d.Passkeys != nil {
			if _, err := m.d.Passkeys.RemoveAll(ctx, in.UserID); err != nil {
				return err
			}
		}
		if _, err := m.d.Sessions.RevokeAllOfUser(ctx, in.UserID, m.now()); err != nil {
			return err
		}
		return nil
	}, txName("reset_mfa"))
	if err != nil {
		return fmt.Errorf("reset the MFA: %w", err)
	}
	m.d.Log.InfoContext(ctx, "identity.mfa.reset", "event", "identity.mfa.reset", "user_id", in.UserID)
	m.securityEvent(ctx, securityevents.ActionMfaReset, securityevents.NoticeMfaReset, in.Actor, in.UserID)
	return nil
}

// securityEvent writes the audit entry and sends the notice. A failure of the
// port is logged. It does not undo the change.
func (m *MFA) securityEvent(ctx context.Context, action, notice, actor, target string) {
	now := m.now()
	if err := m.d.Events.RecordAudit(ctx, securityevents.AuditEntry{
		Action: action, Actor: actor, TargetUserID: target, Result: securityevents.ResultSuccess, At: now,
	}); err != nil {
		m.d.Log.ErrorContext(ctx, "identity.audit.failed", "event", "identity.audit.failed", "action", action, "error", err)
	}
	if err := m.d.Events.NotifyUser(ctx, securityevents.Notice{Kind: notice, TargetUserID: target, At: now}); err != nil {
		m.d.Log.ErrorContext(ctx, "identity.security_notice.failed", "event", "identity.security_notice.failed", "kind", notice, "error", err)
	}
}
