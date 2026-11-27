package commands

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/techorionai/constellation-platform-go/audit"
	"github.com/techorionai/constellation-platform-go/transaction"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/identitylinks"
	"github.com/techorionai/constellation-identity/internal/ports/idpflow"
	"github.com/techorionai/constellation-identity/internal/ports/mfa"
	"github.com/techorionai/constellation-identity/internal/ports/mfaflow"
	"github.com/techorionai/constellation-identity/internal/ports/onetimetokens"
	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/internal/ports/upstreamidp"
	"github.com/techorionai/constellation-identity/internal/ports/userroles"
	"github.com/techorionai/constellation-identity/internal/ports/users"
)

// Errors of the upstream flows. A handler maps each one to a page.
var (
	// ErrIdpProviderOff means the provider name is not valid or the provider is off.
	ErrIdpProviderOff = errors.New("the provider is off")
	// ErrIdpFailed means the flow did not complete. The page does not tell why.
	ErrIdpFailed = errors.New("the login did not complete")
	// ErrIdpProviderDown means the provider did not answer at the start (502).
	ErrIdpProviderDown = errors.New("the provider did not answer")
	// ErrIdpExpired means the state is unknown, used, or bound to another browser.
	ErrIdpExpired = errors.New("the login expired")
	// ErrIdpNotLinked means no user has the upstream account.
	ErrIdpNotLinked = errors.New("the account is not linked")
	// ErrIdpLinkedElsewhere means another user has the upstream account.
	ErrIdpLinkedElsewhere = errors.New("the account is linked to another user")
	// ErrIdpAlreadyLinked means the user has a link for the provider.
	ErrIdpAlreadyLinked = errors.New("the user has a link for the provider")
	// ErrIdpMismatch means the account does not match the invitation.
	ErrIdpMismatch = errors.New("the account does not match the invitation")
	// ErrIdpReauth means the link flow needs a fresh session.
	ErrIdpReauth = errors.New("a fresh login is necessary")
	// ErrIdpConfirm means the link flow needs the check of a local factor first
	// (P23). The hosted page sends the user to the confirm page.
	ErrIdpConfirm = errors.New("a local factor check is necessary")
	// ErrIdpUnavailable means the store of the flow does not answer.
	ErrIdpUnavailable = errors.New("the flow store is not available")
)

// IdpFlowTTL is the life of the record of a flow.
const IdpFlowTTL = 10 * time.Minute

// IdpConfirmTTL is the life of the record that a local factor check leaves.
const IdpConfirmTTL = 5 * time.Minute

// Values of the attribute outcome of the metric identity.idp.logins.
const (
	IdpOutcomeOK              = "ok"
	IdpOutcomeNotLinked       = "not_linked"
	IdpOutcomeLinkedElsewhere = "linked_elsewhere"
	IdpOutcomeEmailMismatch   = "email_mismatch"
	IdpOutcomeBadState        = "bad_state"
	IdpOutcomeProviderError   = "provider_error"
	IdpOutcomeTokenInvalid    = "token_invalid"
	IdpOutcomeNotFresh        = "not_fresh"
	IdpOutcomeLimited         = "limited"
	// IdpOutcomeRefused is a start that the rules refuse: a purpose that is not
	// valid, or a request from another site (R15).
	IdpOutcomeRefused = "refused"
	// IdpOutcomeUserInactive is a login of a user that is not active (R15).
	IdpOutcomeUserInactive = "user_inactive"
)

// LocalFactors is the check of the local factors of a user (P23). The use cases
// of the second factor implement it.
type LocalFactors interface {
	// HasLocalFactor reports whether the user has a password, a TOTP factor, or a
	// passkey.
	HasLocalFactor(ctx context.Context, userID string) (bool, error)
	// VerifyLocalFactor checks a password or a code of the user.
	VerifyLocalFactor(ctx context.Context, in LocalFactor) error
	// BeginPasskeyConfirm and FinishPasskeyConfirm are the passkey check. The
	// session hash binds the ceremony to one session.
	BeginPasskeyConfirm(ctx context.Context, userID, sessionHash string) ([]byte, error)
	FinishPasskeyConfirm(ctx context.Context, in PasskeyConfirm) error
}

// LinkRemover removes a link. The use cases of the identity links implement it.
type LinkRemover interface {
	Remove(ctx context.Context, in RemoveIdentityLink) error
}

// IdpDeps are the ports of the upstream flows.
type IdpDeps struct {
	Client   upstreamidp.Client
	Flows    idpflow.Store
	Links    identitylinks.Repository
	Users    users.Repository
	Sessions sessions.Repository
	Tokens   onetimetokens.Repository
	MFA      mfa.Repository
	// UserRoles is for the rule "MFA for admins". Pending holds the pending logins.
	UserRoles userroles.Repository
	Pending   mfaflow.PendingLogins
	// Factors checks the local factors of a user for the purpose link. A nil
	// value means that no user has a local factor.
	Factors LocalFactors
	// Remover removes a link for the purpose unlink.
	Remover LinkRemover
	Events  securitynotices.Notices
	Audit   audit.Writer
	Tx      transaction.Transactor
	Policy  domain.SessionPolicy
	// LookupAuthRequest checks that an auth request exists.
	LookupAuthRequest func(ctx context.Context, id string) (AuthRequestInfo, error)
	// PasskeysOn is true when the service accepts passkeys.
	PasskeysOn          bool
	RequireMFAForAdmins bool
	// Timeout is the one deadline of the outbound calls of one request.
	Timeout time.Duration
	Log     *slog.Logger
	// Now is the clock. The default is time.Now.
	Now Clock
}

// Idp has the use cases of the upstream flows.
type Idp struct {
	d      IdpDeps
	logins metric.Int64Counter
}

// NewIdp makes the use cases.
func NewIdp(d IdpDeps) (*Idp, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Timeout <= 0 {
		d.Timeout = 10 * time.Second
	}
	c, err := otel.Meter("identity").Int64Counter("identity.idp.logins",
		metric.WithDescription("Upstream login flows by provider, purpose, and outcome."))
	if err != nil {
		return nil, fmt.Errorf("make the upstream login counter: %w", err)
	}
	return &Idp{d: d, logins: c}, nil
}

func (i *Idp) now() time.Time { return i.d.Now().UTC().Truncate(time.Microsecond) }

func (i *Idp) count(ctx context.Context, provider, purpose, outcome string) {
	i.logins.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("provider", provider), attribute.String("purpose", purpose), attribute.String("outcome", outcome)))
}

func (i *Idp) failed(ctx context.Context, provider, purpose, outcome string) {
	i.count(ctx, provider, purpose, outcome)
	i.d.Log.InfoContext(ctx, "identity.idp.login_failed", "event", "identity.idp.login_failed",
		"provider", provider, "purpose", purpose, "outcome", outcome)
}

// --- start ---

// StartIdp is the input of the start of a flow.
type StartIdp struct {
	Provider string
	Purpose  string
	// AuthRequest and ReturnTo are the place to go after a login (purpose login).
	AuthRequest string
	ReturnTo    string
	// InviteToken is the invite token (purpose invite). It is a secret.
	InviteToken string
	// SessionToken is the session cookie value (purpose link). It is a secret.
	SessionToken string
	// Fresh is true when the login page asked for prompt=login.
	Fresh bool
	// SecFetchSite is the value of the request header Sec-Fetch-Site.
	SecFetchSite string
	// Confirm is the value that ConfirmLink gave (purpose link). It is a secret.
	Confirm string
	// RemoveProvider is the provider of the link to remove (purpose unlink).
	RemoveProvider string
}

// StartedIdp is the result of the start.
type StartedIdp struct {
	// Location is the URL of the authorization request of the provider.
	Location string
	// Binding is the value of the cookie that binds the flow to the browser. It
	// is a secret.
	Binding string
	// Flow is the ID of the flow. The name of the cookie has it (R8).
	Flow string
}

// Start checks the request, makes the flow record, and returns the URL of the
// provider. The checks come first, so a wrong request makes no record.
func (i *Idp) Start(ctx context.Context, in StartIdp) (StartedIdp, error) {
	if !domain.ValidProvider(in.Provider) || !i.d.Client.Enabled(in.Provider) {
		return StartedIdp{}, ErrIdpProviderOff
	}
	if !domain.ValidFlowPurpose(in.Purpose) || !domain.SecFetchSiteAllowed(in.Purpose, in.SecFetchSite) {
		i.failed(ctx, in.Provider, in.Purpose, IdpOutcomeRefused)
		return StartedIdp{}, ErrIdpFailed
	}
	rec := domain.IdpFlow{Provider: in.Provider, Purpose: in.Purpose, Fresh: in.Fresh}
	switch in.Purpose {
	case domain.FlowLogin:
		if err := i.checkPlace(ctx, in.AuthRequest, in.ReturnTo); err != nil {
			return StartedIdp{}, err
		}
		rec.AuthRequest, rec.ReturnTo = in.AuthRequest, in.ReturnTo
	case domain.FlowLink:
		sess, err := i.session(ctx, in.SessionToken)
		if err != nil {
			return StartedIdp{}, err
		}
		if !domain.FreshLogin(sess.AuthTime, i.now()) {
			return StartedIdp{}, ErrIdpReauth
		}
		rec.SessionHash, rec.Fresh = sess.TokenHash, true
		// A user with a local factor must prove it before the link. A user with
		// no local factor needs an ID token with a valid auth_time (P23).
		has, err := i.hasLocalFactor(ctx, sess.UserID)
		if err != nil {
			return StartedIdp{}, err
		}
		if has {
			if err := i.takeConfirm(ctx, in.Confirm, in.Provider, sess); err != nil {
				return StartedIdp{}, err
			}
		} else {
			rec.NeedAuthTime = true
		}
	case domain.FlowUnlink:
		if err := i.startUnlink(ctx, in, &rec); err != nil {
			return StartedIdp{}, err
		}
	case domain.FlowInvite:
		if err := checkTokenValid(ctx, i.d.Tokens, in.InviteToken, domain.PurposeInvite, i.now()); err != nil {
			return StartedIdp{}, i.invalidStart(ctx, in, err)
		}
		rec.InviteHash = domain.HashSecret(in.InviteToken)
	}
	ctx, cancel := context.WithTimeout(ctx, i.d.Timeout)
	defer cancel()
	state, stateHash, err := domain.NewSecret()
	if err != nil {
		return StartedIdp{}, err
	}
	nonce, _, err := domain.NewSecret()
	if err != nil {
		return StartedIdp{}, err
	}
	verifier, _, err := domain.NewSecret()
	if err != nil {
		return StartedIdp{}, err
	}
	binding, bindingHash, err := domain.NewSecret()
	if err != nil {
		return StartedIdp{}, err
	}
	rec.Nonce, rec.Verifier, rec.BindingHash = nonce, verifier, bindingHash
	loc, err := i.d.Client.AuthCodeURL(ctx, in.Provider, upstreamidp.AuthParams{
		State: state, Nonce: nonce, Verifier: verifier, Fresh: rec.Fresh,
	})
	if err != nil {
		i.failed(ctx, in.Provider, in.Purpose, IdpOutcomeProviderError)
		return StartedIdp{}, fmt.Errorf("%w: %w", ErrIdpProviderDown, err)
	}
	if err := i.d.Flows.Put(ctx, stateHash, rec, IdpFlowTTL); err != nil {
		i.d.Log.ErrorContext(ctx, "identity.idp.flow_unavailable", "event", "identity.idp.flow_unavailable", "error", err)
		return StartedIdp{}, ErrIdpUnavailable
	}
	return StartedIdp{Location: loc, Binding: binding, Flow: domain.FlowID(state)}, nil
}

// startUnlink checks the start of the removal of a link by a user that has no
// local factor (P23). A user with a local factor proves it on the page, with no
// upstream login. The ID token must have a valid auth_time.
func (i *Idp) startUnlink(ctx context.Context, in StartIdp, rec *domain.IdpFlow) error {
	if !domain.ValidProvider(in.RemoveProvider) {
		i.failed(ctx, in.Provider, in.Purpose, IdpOutcomeRefused)
		return ErrIdpFailed
	}
	sess, err := i.session(ctx, in.SessionToken)
	if err != nil {
		return err
	}
	if !domain.FreshLogin(sess.AuthTime, i.now()) {
		return ErrIdpReauth
	}
	has, err := i.hasLocalFactor(ctx, sess.UserID)
	if err != nil {
		return err
	}
	if has {
		i.failed(ctx, in.Provider, in.Purpose, IdpOutcomeRefused)
		return ErrIdpFailed
	}
	rec.SessionHash, rec.Fresh, rec.NeedAuthTime, rec.RemoveProvider = sess.TokenHash, true, true, in.RemoveProvider
	return nil
}

// hasLocalFactor reports whether the user has a local factor.
func (i *Idp) hasLocalFactor(ctx context.Context, userID string) (bool, error) {
	if i.d.Factors == nil {
		return false, nil
	}
	return i.d.Factors.HasLocalFactor(ctx, userID)
}

// takeConfirm uses the record of a local factor check one time. The record must
// be for the same provider and the same session.
func (i *Idp) takeConfirm(ctx context.Context, confirm, provider string, sess domain.Session) error {
	if confirm == "" || len(confirm) > domain.MaxTokenValueLength {
		return ErrIdpConfirm
	}
	rec, err := i.d.Flows.Take(ctx, domain.HashSecret(confirm))
	if errors.Is(err, idpflow.ErrNotFound) {
		return ErrIdpConfirm
	}
	if err != nil {
		i.d.Log.ErrorContext(ctx, "identity.idp.flow_unavailable", "event", "identity.idp.flow_unavailable", "error", err)
		return ErrIdpUnavailable
	}
	if rec.Purpose != domain.FlowConfirm || rec.Provider != provider ||
		subtle.ConstantTimeCompare([]byte(rec.SessionHash), []byte(sess.TokenHash)) != 1 {
		return ErrIdpConfirm
	}
	return nil
}

// ConfirmLink is the input of the check of a local factor before a link.
type ConfirmLink struct {
	Provider string
	// SessionToken, Password, and Code are secrets.
	SessionToken string
	Password     string
	Code         string
	// PasskeyBody is the response of a passkey. If it is not empty, the check
	// uses the passkey and not the password or the code.
	PasskeyBody []byte
}

// ConfirmLink checks the local factor of the user of the session before the
// start of a link flow. It returns the value that the start needs, or an empty
// value for a user that has no local factor: that user needs no check, and the
// callback needs an ID token with a valid auth_time (P23). The value works one
// time, for the same provider and the same session.
func (i *Idp) ConfirmLink(ctx context.Context, in ConfirmLink) (string, error) {
	if !domain.ValidProvider(in.Provider) || !i.d.Client.Enabled(in.Provider) {
		return "", ErrIdpProviderOff
	}
	sess, err := i.session(ctx, in.SessionToken)
	if err != nil {
		return "", err
	}
	if !domain.FreshLogin(sess.AuthTime, i.now()) {
		return "", ErrIdpReauth
	}
	has, err := i.hasLocalFactor(ctx, sess.UserID)
	if err != nil || !has {
		return "", err
	}
	if len(in.PasskeyBody) > 0 {
		if err := i.d.Factors.FinishPasskeyConfirm(ctx, PasskeyConfirm{UserID: sess.UserID, SessionHash: sess.TokenHash, Body: in.PasskeyBody}); err != nil {
			return "", err
		}
	} else if err := i.d.Factors.VerifyLocalFactor(ctx, LocalFactor{UserID: sess.UserID, Password: in.Password, Code: in.Code}); err != nil {
		return "", err
	}
	value, hash, err := domain.NewSecret()
	if err != nil {
		return "", err
	}
	rec := domain.IdpFlow{Provider: in.Provider, Purpose: domain.FlowConfirm, SessionHash: sess.TokenHash}
	if err := i.d.Flows.Put(ctx, hash, rec, IdpConfirmTTL); err != nil {
		i.d.Log.ErrorContext(ctx, "identity.idp.flow_unavailable", "event", "identity.idp.flow_unavailable", "error", err)
		return "", ErrIdpUnavailable
	}
	return value, nil
}

// BeginPasskeyConfirm makes the options of the passkey check of the session. It
// needs a fresh session. The same options serve a link and a link removal.
func (i *Idp) BeginPasskeyConfirm(ctx context.Context, sessionToken string) ([]byte, error) {
	sess, err := i.session(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	if !domain.FreshLogin(sess.AuthTime, i.now()) {
		return nil, ErrIdpReauth
	}
	if i.d.Factors == nil {
		return nil, ErrPasskeysOff
	}
	return i.d.Factors.BeginPasskeyConfirm(ctx, sess.UserID, sess.TokenHash)
}

func (i *Idp) invalidStart(ctx context.Context, in StartIdp, err error) error {
	if errors.Is(err, ErrTokenInvalid) {
		i.failed(ctx, in.Provider, in.Purpose, IdpOutcomeProviderError)
		return ErrIdpFailed
	}
	return err
}

// checkPlace checks the place to go after a login: the auth request must exist,
// and the return_to value must be a local path.
func (i *Idp) checkPlace(ctx context.Context, authRequest, returnTo string) error {
	if authRequest != "" && i.d.LookupAuthRequest != nil {
		if _, err := i.d.LookupAuthRequest(ctx, authRequest); err != nil {
			if errors.Is(err, ErrAuthRequestGone) {
				return ErrIdpFailed
			}
			return err
		}
	}
	if returnTo != "" {
		if _, ok := domain.SafeReturnTo(returnTo); !ok {
			return ErrIdpFailed
		}
	}
	return nil
}

// session returns the valid session of a cookie value.
func (i *Idp) session(ctx context.Context, token string) (domain.Session, error) {
	if token == "" || len(token) > domain.MaxTokenValueLength {
		return domain.Session{}, ErrIdpReauth
	}
	sess, err := i.d.Sessions.GetByTokenHash(ctx, domain.HashSecret(token))
	if errors.Is(err, sessions.ErrNotFound) {
		return domain.Session{}, ErrIdpReauth
	}
	if err != nil {
		return domain.Session{}, fmt.Errorf("get the session: %w", err)
	}
	if !sess.Valid(i.now()) {
		return domain.Session{}, ErrIdpReauth
	}
	return sess, nil
}

// --- callback ---

// CallbackIdp is the input of the callback.
type CallbackIdp struct {
	Provider string
	// State, Code, and Iss are the query values of the redirect. They are secrets.
	State string
	Code  string
	Iss   string
	// ProviderError is true when the redirect has an error parameter.
	ProviderError bool
	// Binding is the value of the cookie of the flow. SessionToken is the session
	// cookie value. Both are secrets.
	Binding      string
	SessionToken string
	// IP, UserAgent, and PreviousToken are for the session.
	IP            string
	UserAgent     string
	PreviousToken string
}

// The kinds of the result of a callback.
const (
	// IdpSession means the login made a session.
	IdpSession = "session"
	// IdpPending means the login needs a second factor.
	IdpPending = "pending"
	// IdpLinked means the flow added a link. The user goes to the account page.
	IdpLinked = "linked"
	// IdpUnlinked means the flow removed a link. The sessions with an upstream
	// login ended.
	IdpUnlinked = "unlinked"
)

// IdpResult is the result of a good callback.
type IdpResult struct {
	Kind    string
	Purpose string
	// Session is the new session, or the pending login.
	Session IssuedSession
	// AuthRequest and ReturnTo are the place to go after a login.
	AuthRequest string
	ReturnTo    string
	// SessionEnded is true when the removal of a link ended the session of the
	// request (purpose unlink).
	SessionEnded bool
}

// Callback checks the answer of the provider and continues with the purpose of
// the flow. It uses only the values of the flow record, not the request.
func (i *Idp) Callback(ctx context.Context, in CallbackIdp) (IdpResult, error) {
	if !domain.ValidProvider(in.Provider) || !i.d.Client.Enabled(in.Provider) {
		return IdpResult{}, ErrIdpProviderOff
	}
	ctx, cancel := context.WithTimeout(ctx, i.d.Timeout)
	defer cancel()
	rec, err := i.takeFlow(ctx, in)
	if err != nil {
		return IdpResult{}, err
	}
	if in.ProviderError {
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeProviderError)
		return IdpResult{}, ErrIdpFailed
	}
	id, err := i.d.Client.Exchange(ctx, in.Provider, upstreamidp.ExchangeParams{
		Code: in.Code, Verifier: rec.Verifier, Nonce: rec.Nonce, Iss: in.Iss,
	})
	switch {
	case errors.Is(err, upstreamidp.ErrToken):
		i.d.Log.InfoContext(ctx, "identity.idp.token_refused", "event", "identity.idp.token_refused", "provider", in.Provider)
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeTokenInvalid)
		return IdpResult{}, ErrIdpFailed
	case err != nil:
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeProviderError)
		return IdpResult{}, ErrIdpFailed
	}
	if rec.Fresh && !domain.UpstreamFresh(in.Provider, id.AuthTime, id.IssuedAt, i.now()) {
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeNotFresh)
		return IdpResult{}, ErrIdpFailed
	}
	if rec.NeedAuthTime && !domain.UpstreamAuthTimeFresh(id.AuthTime, i.now()) {
		// The user has no local factor, so the ID token must prove a recent login.
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeNotFresh)
		return IdpResult{}, ErrIdpFailed
	}
	switch rec.Purpose {
	case domain.FlowLink:
		return i.link(ctx, in, rec, id)
	case domain.FlowUnlink:
		return i.unlink(ctx, in, rec, id)
	case domain.FlowInvite:
		return i.invite(ctx, in, rec, id)
	}
	return i.login(ctx, in, rec, id)
}

// takeFlow reads the flow record of the state and checks the provider and the
// binding of the browser. A record is used one time.
func (i *Idp) takeFlow(ctx context.Context, in CallbackIdp) (domain.IdpFlow, error) {
	if in.State == "" || len(in.State) > domain.MaxTokenValueLength {
		i.failed(ctx, in.Provider, "", IdpOutcomeBadState)
		return domain.IdpFlow{}, ErrIdpExpired
	}
	rec, err := i.d.Flows.Take(ctx, domain.HashSecret(in.State))
	if errors.Is(err, idpflow.ErrNotFound) {
		i.failed(ctx, in.Provider, "", IdpOutcomeBadState)
		return domain.IdpFlow{}, ErrIdpExpired
	}
	if err != nil {
		i.d.Log.ErrorContext(ctx, "identity.idp.flow_unavailable", "event", "identity.idp.flow_unavailable", "error", err)
		return domain.IdpFlow{}, ErrIdpUnavailable
	}
	bound := in.Binding != "" && subtle.ConstantTimeCompare([]byte(domain.HashSecret(in.Binding)), []byte(rec.BindingHash)) == 1
	if rec.Provider != in.Provider || !bound {
		i.failed(ctx, in.Provider, rec.Purpose, IdpOutcomeBadState)
		return domain.IdpFlow{}, ErrIdpExpired
	}
	return rec, nil
}

// login is the purpose login: the upstream account must have a link.
func (i *Idp) login(ctx context.Context, in CallbackIdp, rec domain.IdpFlow, id domain.UpstreamIdentity) (IdpResult, error) {
	link, err := i.d.Links.GetBySubject(ctx, in.Provider, id.Subject)
	if errors.Is(err, identitylinks.ErrNotFound) {
		// The service does not look up the email. A match by email would let an
		// attacker with an upstream account take over a user.
		i.failed(ctx, in.Provider, domain.FlowLogin, IdpOutcomeNotLinked)
		return IdpResult{}, ErrIdpNotLinked
	}
	if err != nil {
		return IdpResult{}, fmt.Errorf("get the link: %w", err)
	}
	user, err := i.d.Users.GetByID(ctx, link.UserID)
	if errors.Is(err, users.ErrNotFound) || (err == nil && user.Status != domain.UserActive) {
		i.failed(ctx, in.Provider, domain.FlowLogin, IdpOutcomeUserInactive)
		return IdpResult{}, ErrIdpFailed
	}
	if err != nil {
		return IdpResult{}, fmt.Errorf("get the user: %w", err)
	}
	if err := i.d.Links.Touch(ctx, link.ID, id.Email, i.now()); err != nil {
		i.d.Log.WarnContext(ctx, "identity.idp.touch_failed", "event", "identity.idp.touch_failed", "error", err)
	}
	res, err := i.continueLogin(ctx, in, rec, user.ID, domain.UpstreamAuthTimeFresh(id.AuthTime, i.now()))
	if err != nil {
		return IdpResult{}, err
	}
	i.count(ctx, in.Provider, domain.FlowLogin, IdpOutcomeOK)
	i.d.Log.InfoContext(ctx, "identity.login.ok", "event", "identity.login.ok", "user_id", user.ID, "method", domain.AMRFederated)
	return res, nil
}

// continueLogin makes the session, or the pending login if the user has a local
// second factor.
func (i *Idp) continueLogin(ctx context.Context, in CallbackIdp, rec domain.IdpFlow, userID string, authTimeValid bool) (IdpResult, error) {
	needsMFA, hasFactor, err := i.mfaPolicy(ctx, userID)
	if err != nil {
		return IdpResult{}, err
	}
	res := IdpResult{Purpose: rec.Purpose, AuthRequest: rec.AuthRequest, ReturnTo: rec.ReturnTo}
	if hasFactor {
		value, hash, err := domain.NewSecret()
		if err != nil {
			return IdpResult{}, err
		}
		expires := i.now().Add(PendingLoginTTL)
		err = i.d.Pending.Put(ctx, hash, domain.PendingLogin{
			UserID: userID, Methods: domain.MethodsFederated(), Provider: in.Provider, AuthRequest: rec.AuthRequest, ReturnTo: rec.ReturnTo, ExpiresAt: expires,
		}, PendingLoginTTL)
		if err != nil {
			i.d.Log.ErrorContext(ctx, "identity.mfa.pending_failed", "event", "identity.mfa.pending_failed", "error", err)
			return IdpResult{}, ErrMFAUnavailable
		}
		res.Kind = IdpPending
		res.Session = IssuedSession{UserID: userID, PendingToken: value, PendingExpiresAt: expires}
		return res, nil
	}
	// The link is read again in the transaction that starts the session. A
	// removal of the link locks the user row, so it runs before this read or
	// after the session exists and revokes it (R2).
	var issued IssuedSession
	err = i.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		if _, err := i.d.Users.LockByID(ctx, userID); err != nil {
			return err
		}
		if _, err := i.d.Links.GetByUserProvider(ctx, userID, in.Provider); err != nil {
			if errors.Is(err, identitylinks.ErrNotFound) {
				return ErrIdpFailed
			}
			return err
		}
		var err error
		issued, err = sessionStarter{sessionIssuer{repo: i.d.Sessions, policy: i.d.Policy, now: i.d.Now}}.
			start(ctx, userID, in.PreviousToken, in.UserAgent, in.IP, domain.MethodsFederated(), withUpstreamAuth(authTimeValid))
		if err != nil {
			return err
		}
		return writeLoginSuccess(ctx, i.d.Audit, i.now(), userID, LoginMethodUpstream, "")
	}, txName("login_upstream"))
	if errors.Is(err, ErrIdpFailed) {
		i.failed(ctx, in.Provider, domain.FlowLogin, IdpOutcomeNotLinked)
		return IdpResult{}, ErrIdpFailed
	}
	if err != nil {
		return IdpResult{}, err
	}
	issued.SetupRequired = needsMFA
	res.Kind, res.Session = IdpSession, issued
	return res, nil
}

// mfaPolicy reads the MFA data of the user. A read error fails the login.
func (i *Idp) mfaPolicy(ctx context.Context, userID string) (needsMFA, hasFactor bool, err error) {
	if i.d.MFA == nil {
		return false, false, nil
	}
	state, err := i.d.MFA.State(ctx, userID)
	if err != nil {
		return false, false, fmt.Errorf("read the MFA state: %w", err)
	}
	state.PasskeysOn = i.d.PasskeysOn
	if i.d.RequireMFAForAdmins && i.d.UserRoles != nil {
		granted, err := i.d.UserRoles.GrantedPermissions(ctx, userID, domain.ImplicitUserRoles(domain.UserActive)...)
		if err != nil {
			return false, false, fmt.Errorf("get the permissions: %w", err)
		}
		needsMFA = domain.NeedsMFA(true, granted)
	}
	return needsMFA, state.Enabled(), nil
}

// link is the purpose link: the session of the start adds a link.
func (i *Idp) link(ctx context.Context, in CallbackIdp, rec domain.IdpFlow, id domain.UpstreamIdentity) (IdpResult, error) {
	sess, err := i.session(ctx, in.SessionToken)
	if err != nil {
		i.failed(ctx, in.Provider, domain.FlowLink, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpReauth
	}
	if subtle.ConstantTimeCompare([]byte(sess.TokenHash), []byte(rec.SessionHash)) != 1 {
		i.failed(ctx, in.Provider, domain.FlowLink, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpExpired
	}
	// The session of the start is checked here, so the actor of the audit entry
	// is the user of the session.
	ctx = asUser(ctx, sess.UserID)
	err = i.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		u, err := i.d.Users.LockByID(ctx, sess.UserID)
		if err != nil {
			return err
		}
		if u.Status != domain.UserActive {
			return ErrIdpFailed
		}
		return i.createLink(ctx, u.ID, id, "")
	}, txName("link_identity"))
	switch {
	case errors.Is(err, ErrIdpAlreadyLinked):
		i.failed(ctx, in.Provider, domain.FlowLink, IdpOutcomeNotLinked)
		return IdpResult{}, ErrIdpAlreadyLinked
	case errors.Is(err, ErrIdpLinkedElsewhere):
		i.failed(ctx, in.Provider, domain.FlowLink, IdpOutcomeLinkedElsewhere)
		return IdpResult{}, ErrIdpLinkedElsewhere
	case errors.Is(err, ErrIdpFailed):
		return IdpResult{}, ErrIdpFailed
	case err != nil:
		return IdpResult{}, fmt.Errorf("add the link: %w", err)
	}
	i.linked(ctx, in.Provider, domain.FlowLink, sess.UserID)
	return IdpResult{Kind: IdpLinked, Purpose: domain.FlowLink}, nil
}

// unlink is the purpose unlink: the session of the start removes a link. The
// upstream account of the login must be linked to the user of the session. The
// ID token has a valid auth_time (the callback checked it), so the removal
// passes the rule of P23 for a user with no local factor.
func (i *Idp) unlink(ctx context.Context, in CallbackIdp, rec domain.IdpFlow, id domain.UpstreamIdentity) (IdpResult, error) {
	sess, err := i.session(ctx, in.SessionToken)
	if err != nil {
		i.failed(ctx, in.Provider, domain.FlowUnlink, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpReauth
	}
	if subtle.ConstantTimeCompare([]byte(sess.TokenHash), []byte(rec.SessionHash)) != 1 {
		i.failed(ctx, in.Provider, domain.FlowUnlink, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpExpired
	}
	// The upstream account must be an account of the user. An account of the
	// attacker would give a valid auth_time and no proof about the user.
	link, err := i.d.Links.GetBySubject(ctx, in.Provider, id.Subject)
	if errors.Is(err, identitylinks.ErrNotFound) || (err == nil && link.UserID != sess.UserID) {
		i.failed(ctx, in.Provider, domain.FlowUnlink, IdpOutcomeNotLinked)
		return IdpResult{}, ErrIdpFailed
	}
	if err != nil {
		return IdpResult{}, fmt.Errorf("get the link: %w", err)
	}
	if i.d.Remover == nil {
		return IdpResult{}, ErrIdpFailed
	}
	err = i.d.Remover.Remove(asUser(ctx, sess.UserID), RemoveIdentityLink{
		UserID: sess.UserID, Provider: rec.RemoveProvider, Actor: sess.UserID, Self: true, UpstreamFresh: true,
	})
	if err != nil {
		return IdpResult{}, err
	}
	i.count(ctx, in.Provider, domain.FlowUnlink, IdpOutcomeOK)
	return IdpResult{
		Kind: IdpUnlinked, Purpose: domain.FlowUnlink, SessionEnded: slices.Contains(sess.AuthMethods, domain.AMRFederated),
	}, nil
}

// createLink adds the link of an upstream account. It runs in a transaction.
func (i *Idp) createLink(ctx context.Context, userID string, id domain.UpstreamIdentity, origin string) error {
	if _, err := i.d.Links.GetByUserProvider(ctx, userID, id.Provider); err == nil {
		return ErrIdpAlreadyLinked
	} else if !errors.Is(err, identitylinks.ErrNotFound) {
		return err
	}
	err := i.d.Links.Create(ctx, domain.IdentityLink{
		ID: newUUID(), UserID: userID, Provider: id.Provider, Subject: id.Subject, Email: id.Email, CreatedAt: i.now(),
	})
	switch {
	case errors.Is(err, identitylinks.ErrSubjectLinked):
		return ErrIdpLinkedElsewhere
	case errors.Is(err, identitylinks.ErrProviderLinked):
		return ErrIdpAlreadyLinked
	case err != nil:
		return err
	}
	return writeAudit(ctx, i.d.Audit, i.now(), ActionLinkAdd, targetUser, userID, originDetails(origin, map[string]any{"provider": id.Provider}))
}

// linked writes the log record and the notice of a new link. The audit entry is
// in the transaction of the link.
func (i *Idp) linked(ctx context.Context, provider, purpose, target string) {
	i.count(ctx, provider, purpose, IdpOutcomeOK)
	i.d.Log.InfoContext(ctx, "identity.idp.linked", "event", "identity.idp.linked", "user_id", target, "provider", provider)
	notifyLink(ctx, i.d.Events, i.d.Log, securitynotices.NoticeIdentityLinkAdded, target, i.now())
}

// invite is the purpose invite: the verified email of the upstream account must
// be the email of the invited user.
func (i *Idp) invite(ctx context.Context, in CallbackIdp, rec domain.IdpFlow, id domain.UpstreamIdentity) (IdpResult, error) {
	now := i.now()
	userID, ok, err := i.d.Tokens.FindValid(ctx, rec.InviteHash, domain.PurposeInvite, now)
	if err != nil {
		return IdpResult{}, fmt.Errorf("find the invite: %w", err)
	}
	if !ok {
		i.failed(ctx, in.Provider, domain.FlowInvite, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpExpired
	}
	invited, err := i.d.Users.GetByID(ctx, userID)
	if errors.Is(err, users.ErrNotFound) {
		return IdpResult{}, ErrIdpExpired
	}
	if err != nil {
		return IdpResult{}, fmt.Errorf("get the user: %w", err)
	}
	email, err := domain.NormalizeEmail(id.Email)
	if err != nil || !id.EmailVerified || email != invited.Email {
		// The token stays unused.
		i.failed(ctx, in.Provider, domain.FlowInvite, IdpOutcomeEmailMismatch)
		return IdpResult{}, ErrIdpMismatch
	}
	// The MFA policy is read before the commit. A failure of the read must not
	// leave a used invite with no session (R4).
	needsMFA, _, err := i.mfaPolicy(ctx, invited.ID)
	if err != nil {
		return IdpResult{}, err
	}
	var issued IssuedSession
	err = i.d.Tx.WithinTx(ctx, func(ctx context.Context) error {
		uid, ok, err := i.d.Tokens.FindValid(ctx, rec.InviteHash, domain.PurposeInvite, now)
		if err != nil {
			return err
		}
		if !ok || uid != invited.ID {
			return ErrIdpExpired
		}
		user, err := i.d.Users.LockByID(ctx, uid)
		if errors.Is(err, users.ErrNotFound) {
			return ErrIdpExpired
		}
		if err != nil {
			return err
		}
		if user.Status != domain.UserInvited {
			return ErrIdpExpired
		}
		if _, ok, err := i.d.Tokens.Use(ctx, rec.InviteHash, domain.PurposeInvite, now); err != nil {
			return err
		} else if !ok {
			return ErrIdpExpired
		}
		if err := i.createLink(ctx, user.ID, id, OriginInvite); err != nil {
			return err
		}
		if err := i.d.Users.Activate(ctx, user.ID, "", now); err != nil {
			return err
		}
		if err := writeAudit(ctx, i.d.Audit, now, ActionInviteAccept, targetUser, user.ID, originDetails(OriginInvite, nil)); err != nil {
			return err
		}
		issued, err = sessionIssuer{repo: i.d.Sessions, policy: i.d.Policy, now: i.d.Now}.
			issue(ctx, user.ID, in.UserAgent, in.IP, domain.MethodsFederated(), withUpstreamAuth(domain.UpstreamAuthTimeFresh(id.AuthTime, now)))
		return err
	}, txName("accept_invite_upstream"))
	switch {
	case errors.Is(err, ErrIdpLinkedElsewhere):
		i.failed(ctx, in.Provider, domain.FlowInvite, IdpOutcomeLinkedElsewhere)
		return IdpResult{}, ErrIdpLinkedElsewhere
	case errors.Is(err, ErrIdpExpired):
		i.failed(ctx, in.Provider, domain.FlowInvite, IdpOutcomeBadState)
		return IdpResult{}, ErrIdpExpired
	case errors.Is(err, ErrIdpAlreadyLinked):
		return IdpResult{}, ErrIdpAlreadyLinked
	case err != nil:
		return IdpResult{}, fmt.Errorf("accept the invite: %w", err)
	}
	issued.SetupRequired = needsMFA
	i.linked(ctx, in.Provider, domain.FlowInvite, invited.ID)
	i.d.Log.InfoContext(ctx, "identity.invite.accepted", "event", "identity.invite.accepted", "user_id", invited.ID)
	return IdpResult{Kind: IdpSession, Purpose: domain.FlowInvite, Session: issued}, nil
}
