package commands_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"

	adaptertotp "github.com/techorionai/constellation-identity/internal/adapters/totp"
	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/securityevents"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	userA   = "00000000-0000-4000-8000-00000000000a"
	userB   = "00000000-0000-4000-8000-00000000000b"
	adminID = "00000000-0000-4000-8000-0000000000ad"
)

// mfaEnv is the env of the login with the ports of the second factor.
type mfaEnv struct {
	*env
	mfa      *mock.MFA
	pending  *mock.Pending
	setups   *mock.Setups
	failures *mock.Failures
	events   *mock.Events
	totp     adaptertotp.Service
	cmd      *commands.MFA
	require  bool
}

func newMFAEnv(t *testing.T) *mfaEnv {
	t.Helper()
	m := &mfaEnv{
		env: newEnv(), mfa: mock.NewMFA(), pending: mock.NewPending(), setups: mock.NewSetups(),
		failures: mock.NewFailures(), events: &mock.Events{}, totp: adaptertotp.New(), require: true,
	}
	m.addUser(userA, "a@example.com", domain.UserActive, "right password 1")
	m.addUser(userB, "b@example.com", domain.UserActive, "right password 1")
	m.addUser(adminID, "admin@example.com", domain.UserActive, "right password 1")
	m.roles.Perms[domain.AdminRole] = []string{domain.AdminPermission}
	if err := m.roles.Assign(ctx, adminID, domain.AdminRole, domain.AssignmentAPI); err != nil {
		t.Fatal(err)
	}
	m.build(t)
	return m
}

func (m *mfaEnv) build(t *testing.T) {
	t.Helper()
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: m.users, UserRoles: m.roles, Sessions: m.sessions, MFA: m.mfa, TOTP: m.totp, Sealer: mock.Sealer{},
		Pending: m.pending, Setups: m.setups, Failures: m.failures, Limiter: m.limiter, Events: m.events, Tx: mock.Tx{},
		Policy: policy, RequireMFAForAdmins: m.require, Issuer: "Constellation", MaxFailures: 10, FailureWindow: 15 * time.Minute,
		Log: slog.New(slog.NewTextHandler(discard{}, nil)), Now: m.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.cmd = cmd
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// loginCmd is the login command with the second factor ports.
func (m *mfaEnv) loginCmd(t *testing.T) *commands.LoginCommand {
	t.Helper()
	c, err := commands.NewLogin(commands.LoginDeps{
		Users: m.users, Session: m.sessions, Hasher: m.hasher, Limiter: m.limiter,
		Limits: commands.LoginLimits{MaxFailuresPerEmail: 3, MaxFailuresPerIP: 50}, Policy: policy, Now: m.clock,
		MFA: m.mfa, UserRoles: m.roles, Pending: m.pending, RequireMFAForAdmins: m.require,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enable turns on TOTP for a user through the setup use cases. It returns the
// secret and the recovery codes.
func (m *mfaEnv) enable(t *testing.T, userID, email string) ([]byte, []string) {
	t.Helper()
	sessionID := "setup-session-" + userID
	info, err := m.cmd.BeginSetup(ctx, commands.BeginSetup{SessionID: sessionID, UserID: userID, Account: email})
	if err != nil {
		t.Fatal(err)
	}
	if info.Secret == "" || !strings.HasPrefix(info.URI, "otpauth://totp/") || len(info.QRPNG) == 0 {
		t.Fatalf("setup info = %+v", info)
	}
	sealed, err := m.setups.Get(ctx, domain.HashSecret(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	// R3: the store holds the secret sealed, with an identifier that is not the user ID.
	secret, err := mock.Sealer{}.Open("setup:"+userID, sealed)
	if err != nil || bytes.Equal(sealed, secret) {
		t.Fatalf("the setup secret is not sealed: %v", err)
	}
	m.sessions.Rows[sessionID] = domain.Session{ID: sessionID, UserID: userID}
	res, err := m.cmd.FinishSetup(ctx, commands.FinishSetup{SessionID: sessionID, UserID: userID, Code: m.code(secret, m.now)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RecoveryCodes) != domain.RecoveryCodeCount {
		t.Fatalf("codes = %d", len(res.RecoveryCodes))
	}
	// The code of the setup counts as used. Move to the next step for a login.
	m.now = m.now.Add(31 * time.Second)
	return secret, res.RecoveryCodes
}

// code makes the TOTP code of a secret at a time.
func (m *mfaEnv) code(secret []byte, at time.Time) string {
	c, err := pqtotp.GenerateCodeCustom(m.totp.Base32(secret), at, pqtotp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		panic(err)
	}
	return c
}

// start does the first factor and returns the pending token.
func (m *mfaEnv) start(t *testing.T, email string) commands.IssuedSession {
	t.Helper()
	got, err := m.loginCmd(t).Execute(ctx, commands.Login{Email: email, Password: "right password 1", IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// U1: the methods of a login.
func TestU1_Methods(t *testing.T) {
	cases := []struct {
		name string
		got  []string
		want string
	}{
		{"password", domain.MethodsPassword(), "pwd"},
		{"totp", domain.WithSecondFactor(domain.MethodsPassword(), domain.AMROTP), "pwd otp mfa"},
		{"recovery", domain.WithSecondFactor(domain.MethodsPassword(), domain.AMRRecovery), "pwd rec mfa"},
	}
	for _, c := range cases {
		if got := strings.Join(c.got, " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if domain.HasMFA(domain.MethodsPassword()) || !domain.HasMFA(domain.WithSecondFactor(domain.MethodsPassword(), domain.AMROTP)) || !domain.HasMFA(domain.WithSecondFactor(domain.MethodsPassword(), domain.AMRRecovery)) {
		t.Error("HasMFA is wrong")
	}
}

// U2: the forms of a recovery code give one normalized value.
func TestU2_NormalizeRecoveryCode(t *testing.T) {
	for _, in := range []string{"abcde-fghij", "ABCDE FGHIJ", "ABCDEFGHIJ"} {
		got, err := domain.NormalizeRecoveryCode(in)
		if err != nil || got != "ABCDEFGHIJ" {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ABCDE", "ABCDE-FGHI1", "ABCDE-FGHIJK", "abcde_fghij"} {
		if _, err := domain.NormalizeRecoveryCode(bad); err == nil {
			t.Errorf("%q must not be valid", bad)
		}
	}
	codes, err := domain.NewRecoveryCodes()
	if err != nil || len(codes) != domain.RecoveryCodeCount {
		t.Fatalf("codes = %v, %v", codes, err)
	}
	for _, c := range codes {
		if n, err := domain.NormalizeRecoveryCode(domain.FormatRecoveryCode(c)); err != nil || n != c {
			t.Errorf("code %q does not round trip", c)
		}
	}
}

// U4: a good password and a user with TOTP gives no session and a pending login.
func TestU4_PasswordThenPending(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	got := m.start(t, "a@example.com")
	if got.PendingToken == "" || got.Token != "" || len(m.sessions.Rows) != 1 {
		t.Fatalf("result = %+v, sessions = %d", got, len(m.sessions.Rows))
	}
	p, err := m.pending.Get(ctx, domain.HashSecret(got.PendingToken))
	if err != nil || p.UserID != userA || strings.Join(p.Methods, " ") != "pwd" {
		t.Fatalf("pending = %+v, %v", p, err)
	}
	// R8: the good password resets the password counters. The second factor has its own counters.
	if n := m.limiter.Emails["a@example.com"]; n != 0 {
		t.Fatalf("email counter = %d", n)
	}
}

// U5: a good code gives a session with the methods, removes the pending login,
// and resets the email counter.
func TestU5_GoodCode(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	res, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now), IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	row := m.sessions.Rows[res.Session.SessionID]
	if strings.Join(row.AuthMethods, " ") != "pwd otp mfa" || res.Session.Token == "" {
		t.Fatalf("session = %+v", row)
	}
	if len(m.pending.Rows) != 0 {
		t.Fatal("the pending login must be removed")
	}
	if _, ok := m.limiter.Emails["a@example.com"]; ok {
		t.Fatal("the email counter must be reset")
	}
}

// U6: the same code two times gives replay.
func TestU6_Replay(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	code := m.code(secret, m.now)
	pend := m.start(t, "a@example.com")
	if _, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: code}); err != nil {
		t.Fatal(err)
	}
	pend = m.start(t, "a@example.com")
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: code})
	if !errors.Is(err, commands.ErrMFAReplay) {
		t.Fatalf("err = %v, want replay", err)
	}
}

// U7: 5 bad codes remove the pending login.
func TestU7_FiveBadCodes(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	for i := 1; i <= commands.MaxPendingAttempts; i++ {
		_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: "000000"})
		if !errors.Is(err, commands.ErrMFABadCode) {
			t.Fatalf("try %d: err = %v", i, err)
		}
	}
	if len(m.pending.Rows) != 0 {
		t.Fatal("the pending login must be removed after the fifth bad code")
	}
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: "000000"})
	if !errors.Is(err, commands.ErrMFAPendingGone) {
		t.Fatalf("sixth try: err = %v", err)
	}
}

// U8: the failure counter over the limit gives the limit error and does not check the code.
func TestU8_FailureCounterLimit(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	m.failures.Counts[userA] = 10
	pend := m.start(t, "a@example.com")
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
	if !errors.Is(err, commands.ErrTooManyAttempts) {
		t.Fatalf("err = %v", err)
	}
	if rec, _ := m.mfa.GetTOTP(ctx, userA); rec.LastUsedAt != nil {
		t.Fatal("the code must not be checked")
	}
}

// U9: the failure counter fails, so the login fails closed with no session.
func TestU9_FailureCounterFails(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	sessions := len(m.sessions.Rows)
	m.failures.Err = errors.New("valkey is down")
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
	if !errors.Is(err, commands.ErrMFAUnavailable) || len(m.sessions.Rows) != sessions {
		t.Fatalf("err = %v, sessions = %d", err, len(m.sessions.Rows))
	}
}

// U10: a recovery code works one time.
func TestU10_RecoveryCode(t *testing.T) {
	m := newMFAEnv(t)
	_, codes := m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	res, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: strings.ToLower(codes[0]), Recovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.sessions.Rows[res.Session.SessionID].AuthMethods, " "); got != "pwd rec mfa" {
		t.Fatalf("methods = %q", got)
	}
	pend = m.start(t, "a@example.com")
	_, err = m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: codes[0], Recovery: true})
	if !errors.Is(err, commands.ErrMFABadCode) {
		t.Fatalf("second use: err = %v", err)
	}
	st, _ := m.mfa.State(ctx, userA)
	if st.CodesRemaining != domain.RecoveryCodeCount-1 {
		t.Fatalf("codes remaining = %d", st.CodesRemaining)
	}
}

// U10a: a pending login that has expired by the clock is gone.
func TestU10a_PendingExpires(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	m.now = m.now.Add(commands.PendingLoginTTL + time.Second)
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
	if !errors.Is(err, commands.ErrMFAPendingGone) {
		t.Fatalf("err = %v", err)
	}
}

// U10b: the pending login of user A does not take a code of user B.
func TestU10b_OtherUserCode(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	secretB, _ := m.enable(t, userB, "b@example.com")
	pend := m.start(t, "a@example.com")
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secretB, m.now)})
	if !errors.Is(err, commands.ErrMFABadCode) {
		t.Fatalf("err = %v", err)
	}
}

// U10c: a user with no factor, and the policy on, gets a session with a setup flag.
func TestU10c_SetupRequired(t *testing.T) {
	m := newMFAEnv(t)
	got := m.start(t, "admin@example.com")
	if got.Token == "" || !got.SetupRequired || strings.Join(got.AuthMethods, " ") != "pwd" {
		t.Fatalf("result = %+v", got)
	}
	m.require = false
	got, err := m.loginCmd(t).Execute(ctx, commands.Login{Email: "admin@example.com", Password: "right password 1", IP: "1.1.1.2"})
	if err != nil || got.SetupRequired {
		t.Fatalf("rule off: %+v, %v", got, err)
	}
}

// U19: a login of a user with a session and a second factor keeps the old
// methods and auth time until the second factor is good.
func TestU19_StepUp(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	first := m.start(t, "a@example.com")
	res, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: first.PendingToken, Code: m.code(secret, m.now)})
	if err != nil {
		t.Fatal(err)
	}
	old := m.sessions.Rows[res.Session.SessionID]
	m.now = m.now.Add(2 * time.Minute)
	pend, err := m.loginCmd(t).Execute(ctx, commands.Login{
		Email: "a@example.com", Password: "right password 1", IP: "1.1.1.1", PreviousToken: res.Session.Token,
	})
	if err != nil || pend.PendingToken == "" {
		t.Fatalf("pending = %+v, %v", pend, err)
	}
	row := m.sessions.Rows[res.Session.SessionID]
	if !row.AuthTime.Equal(old.AuthTime) || strings.Join(row.AuthMethods, " ") != "pwd otp mfa" || row.TokenHash != old.TokenHash {
		t.Fatalf("the session changed before the second factor: %+v", row)
	}
	code := m.code(secret, m.now)
	res2, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: code, PreviousToken: res.Session.Token})
	if err != nil {
		t.Fatal(err)
	}
	row = m.sessions.Rows[res.Session.SessionID]
	if res2.Session.SessionID != res.Session.SessionID || !row.AuthTime.After(old.AuthTime) || strings.Join(row.AuthMethods, " ") != "pwd otp mfa" {
		t.Fatalf("session after the second factor = %+v", row)
	}
}

// U14: the removal of TOTP for a user that needs MFA gives mfa_required.
func TestU14_RemoveRequired(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, adminID, "admin@example.com")
	err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: adminID, Actor: adminID})
	if !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("err = %v", err)
	}
	if st, _ := m.mfa.State(ctx, adminID); !st.HasTOTP {
		t.Fatal("TOTP must stay")
	}
	// A user with no TOTP gives totp_not_found before mfa_required.
	_, _ = m.mfa.RemoveAll(ctx, adminID)
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: adminID, Actor: adminID}); !errors.Is(err, commands.ErrTOTPNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// U20: a good removal writes one audit entry and one notice.
func TestU20_RemoveSecurityEvents(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: userA, Actor: userA}); err != nil {
		t.Fatal(err)
	}
	if len(m.events.Audits) != 1 || len(m.events.Notices) != 1 {
		t.Fatalf("audits = %d, notices = %d", len(m.events.Audits), len(m.events.Notices))
	}
	a, n := m.events.Audits[0], m.events.Notices[0]
	if a.Action != securityevents.ActionTotpRemove || a.TargetUserID != userA || a.Result != securityevents.ResultSuccess || a.Actor != userA {
		t.Fatalf("audit = %+v", a)
	}
	if n.Kind != securityevents.NoticeTotpRemoved || n.TargetUserID != userA {
		t.Fatalf("notice = %+v", n)
	}
	if st, _ := m.mfa.State(ctx, userA); st.Enabled() {
		t.Fatal("the factors must be removed")
	}
}

// U21: a refused removal makes no call to the port.
func TestU21_RefusedRemoveNoEvents(t *testing.T) {
	m := newMFAEnv(t)
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: userA, Actor: userA}); !errors.Is(err, commands.ErrTOTPNotFound) {
		t.Fatalf("err = %v", err)
	}
	m.enable(t, adminID, "admin@example.com")
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: adminID, Actor: adminID}); !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("err = %v", err)
	}
	if len(m.events.Audits) != 0 || len(m.events.Notices) != 0 {
		t.Fatal("a refused removal must not call the port")
	}
}

// U22: a good reset (and the CLI form) writes one audit entry and one notice,
// and revokes the sessions.
func TestU22_ResetSecurityEvents(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	pend := m.start(t, "a@example.com")
	res, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: userA, Actor: adminID}); err != nil {
		t.Fatal(err)
	}
	if m.sessions.Rows[res.Session.SessionID].RevokedAt == nil {
		t.Fatal("the session must be revoked")
	}
	if st, _ := m.mfa.State(ctx, userA); st.Enabled() {
		t.Fatal("the factors must be removed")
	}
	if len(m.events.Audits) != 1 || m.events.Audits[0].Action != securityevents.ActionMfaReset || m.events.Audits[0].Actor != adminID ||
		m.events.Audits[0].TargetUserID != userA || len(m.events.Notices) != 1 || m.events.Notices[0].Kind != securityevents.NoticeMfaReset {
		t.Fatalf("events = %+v %+v", m.events.Audits, m.events.Notices)
	}
	// The subcommand uses the actor cli, also for an admin that resets the own MFA.
	if err := m.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: adminID, Actor: securityevents.ActorCLI}); err != nil {
		t.Fatal(err)
	}
	if got := m.events.Audits[1]; got.Actor != securityevents.ActorCLI || got.TargetUserID != adminID {
		t.Fatalf("cli audit = %+v", got)
	}
}

// U23: a reset with the actor equal to the user gives mfa_required and changes nothing.
func TestU23_SelfReset(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, adminID, "admin@example.com")
	err := m.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: adminID, Actor: adminID})
	if !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("err = %v", err)
	}
	if st, _ := m.mfa.State(ctx, adminID); !st.HasTOTP {
		t.Fatal("nothing must change")
	}
	if len(m.events.Audits) != 0 || len(m.events.Notices) != 0 {
		t.Fatal("a refused reset must not call the port")
	}
	// An unknown user gives not found before the self check.
	if err := m.cmd.ResetMFA(ctx, commands.ResetMFA{UserID: "00000000-0000-4000-8000-0000000000ff", Actor: adminID}); !errors.Is(err, commands.ErrUserNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// U24: a failure of the port does not undo the removal.
func TestU24_PortFailure(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	m.events.Err = errors.New("the port is down")
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: userA, Actor: userA}); err != nil {
		t.Fatalf("err = %v, want success", err)
	}
	if st, _ := m.mfa.State(ctx, userA); st.Enabled() {
		t.Fatal("the removal must stay done")
	}
}
