package commands_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
	"github.com/techorionai/constellation-identity/internal/ports/sessions"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

// failingSessions is a session repository that fails Create.
type failingSessions struct {
	sessions.Repository
}

func (failingSessions) Create(context.Context, domain.Session) error {
	return errors.New("the database is down")
}

// R2: a session that cannot start does not use the TOTP step or the recovery code.
func TestR2_SessionFailureKeepsCode(t *testing.T) {
	m := newMFAEnv(t)
	secret, codes := m.enable(t, userA, "a@example.com")
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: m.users, UserRoles: m.roles, Sessions: failingSessions{m.sessions}, MFA: m.mfa, TOTP: m.totp, Sealer: mock.Sealer{},
		Pending: m.pending, Setups: m.setups, Failures: m.failures, Limiter: m.limiter, Events: m.events, Audit: m.events, Tx: mock.Tx{},
		Policy: policy, RequireMFAForAdmins: m.require, Issuer: "Constellation", MaxFailures: 10, FailureWindow: 15 * time.Minute,
		Log: slog.New(slog.NewTextHandler(discard{}, nil)), Now: m.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := m.mfa.GetTOTP(ctx, userA)
	pend := m.start(t, "a@example.com")
	if _, err := cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)}); err == nil {
		t.Fatal("the login must fail")
	}
	after, _ := m.mfa.GetTOTP(ctx, userA)
	if after.LastUsedStep != before.LastUsedStep {
		t.Fatal("the TOTP step must stay unused")
	}
	pend = m.start(t, "a@example.com")
	if _, err := cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: codes[0], Recovery: true}); err == nil {
		t.Fatal("the login must fail")
	}
	if st, _ := m.mfa.State(ctx, userA); st.CodesRemaining != domain.RecoveryCodeCount {
		t.Fatalf("codes remaining = %d", st.CodesRemaining)
	}
}

// R3: the store holds the setup secret sealed, and the same session gets the same secret (R10).
func TestR3_R10_SetupSecretSealedAndStable(t *testing.T) {
	m := newMFAEnv(t)
	in := commands.BeginSetup{SessionID: "s1", UserID: userA, Account: "a@example.com"}
	first, err := m.cmd.BeginSetup(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.cmd.BeginSetup(ctx, in)
	if err != nil || second.Secret != first.Secret {
		t.Fatalf("second = %+v, %v", second, err)
	}
	raw, _ := m.setups.Get(ctx, domain.HashSecret("s1"))
	if !strings.HasPrefix(string(raw), "setup:"+userA+"|") {
		t.Fatalf("the stored value is not sealed for the setup: %q", raw)
	}
	if _, err := (mock.Sealer{}).Open(userA, raw); err == nil {
		t.Fatal("the sealed setup secret must not open as the stored factor")
	}
	if ok, _ := m.setups.PutIfAbsent(ctx, domain.HashSecret("s1"), []byte("x"), time.Minute); ok {
		t.Fatal("PutIfAbsent must not replace a value")
	}
}

// R4: the removal of TOTP removes the second factor methods of the other sessions.
func TestR4_RemoveDropsMethodsOfOtherSessions(t *testing.T) {
	m := newMFAEnv(t)
	m.enable(t, userA, "a@example.com")
	m.sessions.Rows["other"] = domain.Session{ID: "other", UserID: userA, AuthMethods: domain.WithSecondFactor(domain.MethodsPassword(), domain.AMROTP)}
	m.sessions.Rows["foreign"] = domain.Session{ID: "foreign", UserID: userB, AuthMethods: domain.WithSecondFactor(domain.MethodsPassword(), domain.AMROTP)}
	if err := m.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: userA, Actor: userA}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.sessions.Rows["other"].AuthMethods, " "); got != "pwd" {
		t.Fatalf("methods = %q", got)
	}
	if got := strings.Join(m.sessions.Rows["foreign"].AuthMethods, " "); got != "pwd otp mfa" {
		t.Fatalf("the session of another user changed: %q", got)
	}
}

// R9: a code with spaces is good.
func TestR9_CodeWithSpaces(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	code := m.code(secret, m.now)
	pend := m.start(t, "a@example.com")
	if _, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: code[:3] + " " + code[3:]}); err != nil {
		t.Fatal(err)
	}
}

// R13: the first attempt over a limit sends one notice. The long counter limits too.
func TestR13_NoticeAndDailyLimit(t *testing.T) {
	m := newMFAEnv(t)
	secret, _ := m.enable(t, userA, "a@example.com")
	m.failures.Counts[userA] = 10
	for i := 0; i < 2; i++ {
		pend := m.start(t, "a@example.com")
		_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
		if !errors.Is(err, commands.ErrTooManyAttempts) {
			t.Fatalf("err = %v", err)
		}
	}
	if len(m.events.Notices) != 1 || m.events.Notices[0].Kind != securitynotices.NoticeMfaLimited || m.events.Notices[0].TargetUserID != userA {
		t.Fatalf("notices = %+v", m.events.Notices)
	}
	m.failures.Counts[userA] = 0
	m.failures.Counts["day:"+userA] = commands.DailyMaxFailures
	pend := m.start(t, "a@example.com")
	_, err := m.cmd.VerifyLogin(ctx, commands.VerifyLogin{PendingToken: pend.PendingToken, Code: m.code(secret, m.now)})
	if !errors.Is(err, commands.ErrTooManyAttempts) || len(m.events.Notices) != 2 {
		t.Fatalf("err = %v, notices = %d", err, len(m.events.Notices))
	}
}
