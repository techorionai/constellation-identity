package commands_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/adapters/jose"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/authflow"
	"github.com/techorionai/constellation-identity/internal/ports/refreshtokens"
	"github.com/techorionai/constellation-identity/internal/ports/tokensigner"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// memCodes is an in-memory store of authorization codes.
type memCodes struct {
	codes map[string]domain.AuthCode
	used  map[string]domain.UsedCode
}

func (m *memCodes) Put(_ context.Context, h string, c domain.AuthCode, _ time.Duration) error {
	m.codes[h] = c
	return nil
}

func (m *memCodes) Peek(_ context.Context, h string) (domain.AuthCode, error) {
	c, ok := m.codes[h]
	if !ok {
		return domain.AuthCode{}, authflow.ErrNotFound
	}
	return c, nil
}

func (m *memCodes) Claim(_ context.Context, h string) (domain.AuthCode, error) {
	c, ok := m.codes[h]
	if !ok {
		return domain.AuthCode{}, authflow.ErrNotFound
	}
	delete(m.codes, h)
	return c, nil
}

func (m *memCodes) MarkUsed(_ context.Context, h string, u domain.UsedCode, _ time.Duration) error {
	m.used[h] = u
	return nil
}

func (m *memCodes) GetUsed(_ context.Context, h string) (domain.UsedCode, error) {
	u, ok := m.used[h]
	if !ok {
		return domain.UsedCode{}, authflow.ErrNotFound
	}
	return u, nil
}

// memRefresh is an in-memory refresh token repository.
type memRefresh struct {
	refreshtokens.Repository
	sessions *mock.Sessions
	families map[string]domain.RefreshFamily
	tokens   map[string]domain.RefreshToken
}

func (m *memRefresh) InsertFamilyIfSessionValid(_ context.Context, f domain.RefreshFamily, t domain.RefreshToken, _ time.Time) (bool, error) {
	m.families[f.ID] = f
	m.tokens[t.Hash] = t
	return true, nil
}

func (m *memRefresh) LockSessionOfToken(_ context.Context, h string) (string, bool, error) {
	t, ok := m.tokens[h]
	if !ok {
		return "", false, nil
	}
	return m.families[t.FamilyID].SessionID, true, nil
}

func (m *memRefresh) LockFamilyOfToken(_ context.Context, h string) (domain.RefreshFamily, bool, error) {
	t, ok := m.tokens[h]
	if !ok {
		return domain.RefreshFamily{}, false, nil
	}
	return m.families[t.FamilyID], true, nil
}

func (m *memRefresh) GetToken(_ context.Context, h string) (domain.RefreshToken, error) {
	return m.tokens[h], nil
}

func (m *memRefresh) MarkUsed(_ context.Context, h string, at time.Time) (bool, error) {
	t := m.tokens[h]
	t.UsedAt = &at
	m.tokens[h] = t
	return true, nil
}

func (m *memRefresh) InsertToken(_ context.Context, t domain.RefreshToken) error {
	m.tokens[t.Hash] = t
	return nil
}

func (m *memRefresh) RevokeFamily(_ context.Context, id string, at time.Time) error {
	f := m.families[id]
	f.RevokedAt = &at
	m.families[id] = f
	return nil
}

func (m *memRefresh) RefreshState(_ context.Context, familyID string) (refreshtokens.State, error) {
	f := m.families[familyID]
	return refreshtokens.State{UserActive: true, Session: m.sessions.Rows[f.SessionID]}, nil
}

const reviewVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ-1234567"

type oidcRig struct {
	*exchangeEnv
	oidc    *commands.OIDC
	codes   *memCodes
	refresh *memRefresh
	sess    *mock.Sessions
}

func newOIDCRig(t *testing.T) *oidcRig {
	t.Helper()
	e := newExchangeEnv(t)
	r := &oidcRig{exchangeEnv: e, sess: mock.NewSessions(), codes: &memCodes{codes: map[string]domain.AuthCode{}, used: map[string]domain.UsedCode{}}}
	r.sess.Rows["sess-1"] = domain.Session{
		ID: "sess-1", UserID: user1, CreatedAt: now, AuthTime: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}
	r.refresh = &memRefresh{sessions: r.sess, families: map[string]domain.RefreshFamily{}, tokens: map[string]domain.RefreshToken{}}
	o, err := commands.NewOIDC(commands.OIDCDeps{
		Issuer: issuer, Clients: e.clients, Users: e.users, UserRoles: e.roles, Sessions: r.sess, Refresh: r.refresh,
		Codes: r.codes, Keys: keySet{t: t, f: e.fixture, key: tokensigner.Key{KID: "sig-1", Private: e.sign}},
		Signer: jose.Signer{}, Verifier: jose.Verifier{}, Tx: mock.Tx{}, Audit: e.ev,
		Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.oidc = o
	return r
}

// putCode stores a code for the client helpdesk-ui and returns its text.
func (r *oidcRig) putCode(scopes ...string) string {
	sum := sha256.Sum256([]byte(reviewVerifier))
	code := fmt.Sprintf("code-%d", len(r.codes.codes)+len(r.codes.used))
	r.codes.codes[domain.HashSecret(code)] = domain.AuthCode{
		ClientID: "helpdesk-ui", RedirectURI: "https://ui.example/cb", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		SessionID: "sess-1", UserID: user1, Scope: []string{"mail:message:read"}, OIDCScopes: scopes, AuthTime: now,
	}
	return code
}

func (r *oidcRig) exchange(code string) commands.ExchangeCode {
	return commands.ExchangeCode{ClientID: "helpdesk-ui", Code: code, RedirectURI: "https://ui.example/cb", CodeVerifier: reviewVerifier}
}

// Issue26_R3: the authorization code path and the refresh path write one
// success entry each. The client is the actor. The entry has no token.
func TestIssue26_R3_CodeAndRefreshEntries(t *testing.T) {
	r := newOIDCRig(t)
	res, err := r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if err != nil || res.RefreshToken == "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	a := oneTokenEntry(t, r.ev, "success")
	if a.Actor != "helpdesk-ui" || a.TargetType != "user" || a.TargetUserID != user1 || a.Details["grant"] != "authorization_code" ||
		a.Details["clientId"] != "helpdesk-ui" || a.Details["audience"] != "helpdesk" || a.Details["jti"] == "" {
		t.Fatalf("code entry = %+v", a)
	}
	if strings.Contains(fmt.Sprint(a.Details), res.AccessToken) || strings.Contains(fmt.Sprint(a.Details), res.RefreshToken) {
		t.Fatal("the entry has a token")
	}
	r.ev.Audits = nil
	rr, err := r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "helpdesk-ui", RefreshToken: res.RefreshToken})
	if err != nil || rr.RefreshToken == "" {
		t.Fatalf("refresh: %+v, %v", rr, err)
	}
	b := oneTokenEntry(t, r.ev, "success")
	if b.Actor != "helpdesk-ui" || b.TargetUserID != user1 || b.Details["grant"] != "refresh_token" {
		t.Fatalf("refresh entry = %+v", b)
	}
}

// Issue26_R3: a writer error gives no token on the code path and on the
// refresh path.
func TestIssue26_R3_WriterErrorGivesNoToken(t *testing.T) {
	r := newOIDCRig(t)
	r.ev.AuditErr = errAuditDown
	res, err := r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if oauthCode(t, err) != apperrors.OAuthTemporarilyUnavailable || res.AccessToken != "" || res.RefreshToken != "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	r.ev.AuditErr = nil
	res, err = r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if err != nil {
		t.Fatal(err)
	}
	r.ev.AuditErr = errAuditDown
	rr, err := r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "helpdesk-ui", RefreshToken: res.RefreshToken})
	if oauthCode(t, err) != apperrors.OAuthTemporarilyUnavailable || rr.AccessToken != "" {
		t.Fatalf("refresh: %+v, %v", rr, err)
	}
}

// Issue26_R11: a refresh token reuse with the client_id of another public
// client writes one denied entry in the transaction of the revocation. The entry
// names the client and the user of the family, and has the IDs of the family and
// the session.
func TestIssue26_R11_ReuseEntry(t *testing.T) {
	r := newOIDCRig(t)
	res, err := r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "helpdesk-ui", RefreshToken: res.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	r.ev.Audits = nil
	_, err = r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "other-ui", RefreshToken: res.RefreshToken})
	if oauthCode(t, err) != apperrors.OAuthInvalidGrant {
		t.Fatalf("err = %v", err)
	}
	a := oneTokenEntry(t, r.ev, "denied")
	if a.TargetType != "user" || a.TargetUserID != user1 || a.Details["reason"] != commands.ReasonRefreshTokenReuse ||
		a.Details["clientId"] != "helpdesk-ui" || a.Details["familyId"] == "" || a.Details["sessionId"] != "sess-1" {
		t.Fatalf("entry = %+v", a)
	}
	if r.sess.Rows["sess-1"].RevokedAt == nil {
		t.Fatal("the session is not revoked")
	}
}

// Issue26_R11: a writer error for the entry of a reuse gives the error
// temporarily_unavailable. In a real transaction the revocation rolls back, so
// no revocation exists without an entry.
func TestIssue26_R11_ReuseWriterError(t *testing.T) {
	r := newOIDCRig(t)
	res, err := r.oidc.ExchangeCode(ctx, r.exchange(r.putCode("offline_access")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "helpdesk-ui", RefreshToken: res.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	r.ev.AuditErr = errAuditDown
	_, err = r.oidc.RefreshTokens(ctx, commands.RefreshTokens{ClientID: "other-ui", RefreshToken: res.RefreshToken})
	if oauthCode(t, err) != apperrors.OAuthTemporarilyUnavailable {
		t.Fatalf("err = %v", err)
	}
}

// Issue26_R8: a known client that fails the authentication of a token exchange
// gets its client ID in the denied entry. The actor is the service identity.
func TestIssue26_R8_ExchangeDeniedKnownClient(t *testing.T) {
	e := newExchangeEnv(t)
	in := e.in(t)
	in.Assertion = e.assertion(t, func(c map[string]any) { c["aud"] = "https://wrong.example" })
	_, err := e.cmd.Execute(ctx, in)
	if oauthCode(t, err) != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v", err)
	}
	a := oneTokenEntry(t, e.ev, "denied")
	if a.Actor != "" || a.TargetType != "client" || a.TargetUserID != "helpdesk" || a.Details["clientId"] != "helpdesk" ||
		a.Details["grant"] != "token_exchange" || a.Details["reason"] != "invalid_client" {
		t.Fatalf("entry = %+v", a)
	}
	// An unknown client has no client ID in the entry.
	e.ev.Audits = nil
	in.Assertion = e.assertion(t, func(c map[string]any) { c["sub"] = "nobody"; c["iss"] = "nobody" })
	if _, err := e.cmd.Execute(ctx, in); oauthCode(t, err) != apperrors.OAuthInvalidClient {
		t.Fatalf("err = %v", err)
	}
	if b := oneTokenEntry(t, e.ev, "denied"); b.TargetUserID != "" || b.Details["clientId"] != nil {
		t.Fatalf("unknown entry = %+v", b)
	}
}

// Issue26_R10: the unlock entry has the time of the clock of the command.
func TestIssue26_R10_UnlockEntryTime(t *testing.T) {
	e := newEnv()
	e.addUser("u", "u@example.com", domain.UserActive, "pw")
	ev := &mock.Events{}
	l := mock.NewLimiter()
	l.Emails["u@example.com"] = 6
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	cmd := commands.NewUnlockLogin(l, nil).WithAudit(e.users, mock.Tx{}, ev).WithClock(func() time.Time { return at })
	if _, err := cmd.Execute(ctx, commands.UnlockLogin{Email: "u@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(ev.Audits) != 1 || !ev.Audits[0].Time.Equal(at) {
		t.Fatalf("audits = %+v, want the time %v", ev.Audits, at)
	}
}
