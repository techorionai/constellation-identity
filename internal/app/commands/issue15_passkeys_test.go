package commands_test

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/ports/securitynotices"
	"github.com/techorionai/constellation-identity/internal/ports/webauthn"
	"github.com/techorionai/constellation-identity/resources/test/mock"
)

const (
	passkeyID1 = "00000000-0000-4000-8000-0000000000e1"
	passkeyID2 = "00000000-0000-4000-8000-0000000000e2"
)

// passkeyEnv is the env of the MFA use cases with the ports of the passkeys.
type passkeyEnv struct {
	*mfaEnv
	keys       *mock.Passkeys
	ceremonies *mock.Ceremonies
	wa         *mock.WebAuthn
}

func newPasskeyEnv(t *testing.T) *passkeyEnv {
	t.Helper()
	p := &passkeyEnv{mfaEnv: newMFAEnv(t), keys: mock.NewPasskeys(), ceremonies: mock.NewCeremonies(), wa: &mock.WebAuthn{}}
	p.mfa.Passkeys = p.keys
	return p
}

// buildPasskeys makes the MFA use cases with the passkey ports.
func (p *passkeyEnv) buildPasskeys(t *testing.T, on bool) {
	t.Helper()
	cmd, err := commands.NewMFA(commands.MFADeps{
		Users: p.users, UserRoles: p.roles, Sessions: p.sessions, MFA: p.mfa, TOTP: p.totp, Sealer: mock.Sealer{},
		Passkeys: p.keys, WebAuthn: p.wa, Ceremonies: p.ceremonies, PasskeysOn: on,
		Pending: p.pending, Setups: p.setups, Failures: p.failures, Limiter: p.limiter, Events: p.events, Audit: p.events, Tx: mock.Tx{},
		Policy: policy, RequireMFAForAdmins: p.require, Issuer: "Constellation", MaxFailures: 10, FailureWindow: 15 * time.Minute,
		Log: slog.New(slog.NewTextHandler(discard{}, nil)), Now: p.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	p.cmd = cmd
}

func (p *passkeyEnv) addPasskey(userID, id, name string) {
	p.keys.Add(domain.PasskeyCredential{
		Passkey:      domain.Passkey{ID: id, UserID: userID, Name: name, CreatedAt: p.now},
		CredentialID: []byte("cred-" + id), PublicKey: []byte("key"),
	})
}

// U6: the rule "last second factor" when the policy needs MFA for the user.
func TestIssue15_U6_LastSecondFactor(t *testing.T) {
	t.Run("TOTP and one passkey, remove the passkey", func(t *testing.T) {
		p := newPasskeyEnv(t)
		p.enable(t, adminID, "admin@example.com")
		p.addPasskey(adminID, passkeyID1, "key")
		p.buildPasskeys(t, true)
		if err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	t.Run("one passkey only, remove it", func(t *testing.T) {
		p := newPasskeyEnv(t)
		p.addPasskey(adminID, passkeyID1, "key")
		p.buildPasskeys(t, true)
		err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID})
		if !errors.Is(err, commands.ErrMFARequired) {
			t.Fatalf("remove: %v, want mfa_required", err)
		}
		if n, _ := p.keys.Count(ctx, adminID); n != 1 {
			t.Fatalf("the passkey must stay, count = %d", n)
		}
	})
	t.Run("two passkeys only, remove one", func(t *testing.T) {
		p := newPasskeyEnv(t)
		p.addPasskey(adminID, passkeyID1, "one")
		p.addPasskey(adminID, passkeyID2, "two")
		p.buildPasskeys(t, true)
		if err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID}); err != nil {
			t.Fatalf("remove: %v", err)
		}
	})
	t.Run("TOTP and one passkey, remove TOTP", func(t *testing.T) {
		p := newPasskeyEnv(t)
		p.enable(t, adminID, "admin@example.com")
		p.addPasskey(adminID, passkeyID1, "key")
		p.buildPasskeys(t, true)
		if err := p.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: adminID, Actor: adminID}); err != nil {
			t.Fatalf("remove TOTP: %v", err)
		}
		if n, _ := p.keys.Count(ctx, adminID); n != 1 {
			t.Fatalf("the passkey must stay, count = %d", n)
		}
	})
	t.Run("TOTP and one passkey with passkeys off, remove TOTP", func(t *testing.T) {
		p := newPasskeyEnv(t)
		p.enable(t, adminID, "admin@example.com")
		p.addPasskey(adminID, passkeyID1, "key")
		p.buildPasskeys(t, false)
		err := p.cmd.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: adminID, Actor: adminID})
		if !errors.Is(err, commands.ErrMFARequired) {
			t.Fatalf("remove TOTP: %v, want mfa_required", err)
		}
	})
}

// U12: the registration writes one audit entry and one notice. A refusal writes none.
func TestIssue15_U12_Registration(t *testing.T) {
	p := newPasskeyEnv(t)
	p.buildPasskeys(t, true)
	const sessionID = "session-reg"
	p.sessions.Rows[sessionID] = domain.Session{
		ID: sessionID, UserID: userA, AuthMethods: []string{"pwd"},
		IdleExpiresAt: p.clock().Add(time.Hour), ExpiresAt: p.clock().Add(time.Hour),
	}
	if _, err := p.cmd.BeginPasskeyRegistration(ctx, commands.BeginPasskey{SessionID: sessionID, UserID: userA, Name: "My key"}); err != nil {
		t.Fatal(err)
	}
	p.wa.Registered = webauthn.Credential{ID: []byte("new-credential"), PublicKey: []byte("pk"), BackupEligible: true, BackupState: true}
	added, err := p.cmd.FinishPasskeyRegistration(ctx, commands.FinishPasskey{
		SessionID: sessionID, UserID: userA, SessionMethods: []string{"pwd"}, Body: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if added.Passkey.Name != "My key" || !added.Passkey.BackupState {
		t.Fatalf("passkey = %+v", added.Passkey)
	}
	if len(p.events.Audits) != 1 || p.events.Audits[0].Action != commands.ActionPasskeyAdd || p.events.Audits[0].TargetUserID != userA {
		t.Fatalf("audits = %+v", p.events.Audits)
	}
	if len(p.events.Notices) != 1 || p.events.Notices[0].Kind != securitynotices.NoticePasskeyAdded {
		t.Fatalf("notices = %+v", p.events.Notices)
	}
	// A session with no second factor gets the methods of a passkey.
	if got := p.sessions.Rows[sessionID].AuthMethods; len(got) != 4 || !domain.HasMFA(got) {
		t.Fatalf("session methods = %v", got)
	}

	// A refusal writes nothing.
	p.events.Audits, p.events.Notices = nil, nil
	if _, err := p.cmd.BeginPasskeyRegistration(ctx, commands.BeginPasskey{SessionID: sessionID, UserID: userA, Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	p.wa.Err = webauthn.ErrBadOrigin
	_, err = p.cmd.FinishPasskeyRegistration(ctx, commands.FinishPasskey{SessionID: sessionID, UserID: userA, Body: []byte("{}")})
	if !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("refusal = %v", err)
	}
	if len(p.events.Audits) != 0 || len(p.events.Notices) != 0 {
		t.Fatalf("a refusal wrote events: %+v %+v", p.events.Audits, p.events.Notices)
	}
}

// U13: the removal writes one audit entry and one notice. A refusal writes none.
func TestIssue15_U13_Removal(t *testing.T) {
	p := newPasskeyEnv(t)
	p.enable(t, adminID, "admin@example.com")
	p.addPasskey(adminID, passkeyID1, "one")
	p.buildPasskeys(t, true)
	p.events.Audits, p.events.Notices = nil, nil
	if err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID}); err != nil {
		t.Fatal(err)
	}
	if len(p.events.Audits) != 1 || p.events.Audits[0].Action != commands.ActionPasskeyRemove {
		t.Fatalf("audits = %+v", p.events.Audits)
	}
	if len(p.events.Notices) != 1 || p.events.Notices[0].Kind != securitynotices.NoticePasskeyRemoved {
		t.Fatalf("notices = %+v", p.events.Notices)
	}

	p.events.Audits, p.events.Notices = nil, nil
	if err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID}); !errors.Is(err, commands.ErrPasskeyNotFound) {
		t.Fatalf("unknown passkey: %v", err)
	}
	if err := p.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: "abc", Actor: adminID}); !errors.Is(err, commands.ErrPasskeyNotFound) {
		t.Fatalf("id that is not a UUID: %v", err)
	}
	// The last factor of an admin on a user with no TOTP.
	p2 := newPasskeyEnv(t)
	p2.addPasskey(adminID, passkeyID1, "one")
	p2.buildPasskeys(t, true)
	if err := p2.cmd.RemovePasskey(ctx, commands.RemovePasskey{UserID: adminID, PasskeyID: passkeyID1, Actor: adminID}); !errors.Is(err, commands.ErrMFARequired) {
		t.Fatalf("last factor: %v", err)
	}
	if len(p.events.Audits)+len(p.events.Notices)+len(p2.events.Audits)+len(p2.events.Notices) != 0 {
		t.Fatal("a refusal wrote events")
	}
}

// U16: the rename writes one audit entry with the old name and the new name. A
// refusal writes none. The check of the ID comes before the check of the name.
func TestIssue15_U16_Rename(t *testing.T) {
	p := newPasskeyEnv(t)
	p.addPasskey(userA, passkeyID1, "Old name")
	p.buildPasskeys(t, true)
	pk, err := p.cmd.RenamePasskey(asUser(userA), commands.RenamePasskey{UserID: userA, PasskeyID: passkeyID1, Name: "New name", Actor: userA})
	if err != nil || pk.Name != "New name" {
		t.Fatalf("rename: %+v, %v", pk, err)
	}
	if len(p.events.Audits) != 1 {
		t.Fatalf("audits = %+v", p.events.Audits)
	}
	a := p.events.Audits[0]
	if a.Action != commands.ActionPasskeyRename || a.Details["oldName"] != "Old name" || a.Details["newName"] != "New name" || a.Actor != userA || a.TargetUserID != userA {
		t.Fatalf("audit = %+v", a)
	}
	if len(p.events.Notices) != 0 {
		t.Fatalf("a rename sends no notice: %+v", p.events.Notices)
	}
	p.events.Audits = nil
	if _, err := p.cmd.RenamePasskey(ctx, commands.RenamePasskey{UserID: userA, PasskeyID: passkeyID2, Name: "x", Actor: userA}); !errors.Is(err, commands.ErrPasskeyNotFound) {
		t.Fatalf("unknown passkey: %v", err)
	}
	if _, err := p.cmd.RenamePasskey(ctx, commands.RenamePasskey{UserID: userA, PasskeyID: passkeyID2, Name: " bad", Actor: userA}); !errors.Is(err, commands.ErrPasskeyNotFound) {
		t.Fatalf("unknown passkey with a bad name must give not found: %v", err)
	}
	if _, err := p.cmd.RenamePasskey(ctx, commands.RenamePasskey{UserID: userB, PasskeyID: passkeyID1, Name: "x", Actor: userB}); !errors.Is(err, commands.ErrPasskeyNotFound) {
		t.Fatalf("passkey of another user: %v", err)
	}
	if _, err := p.cmd.RenamePasskey(ctx, commands.RenamePasskey{UserID: userA, PasskeyID: passkeyID1, Name: " bad", Actor: userA}); !errors.Is(err, domain.ErrInvalidPasskeyName) {
		t.Fatalf("bad name: %v", err)
	}
	if len(p.events.Audits) != 0 {
		t.Fatalf("a refusal wrote an audit entry: %+v", p.events.Audits)
	}
}

// The passkey login: a good response makes a session with the methods of a
// passkey. A response with a count that is not larger is refused (U4 at the
// level of the command). The credential of a disabled user is refused.
func TestIssue15_PasskeyLoginCommand(t *testing.T) {
	p := newPasskeyEnv(t)
	p.buildPasskeys(t, true)
	handle := []byte("handle-of-user-a-0123456789abcdef")
	p.keys.Handles[userA] = handle
	p.keys.Add(domain.PasskeyCredential{
		Passkey: domain.Passkey{ID: passkeyID1, UserID: userA, Name: "key", CreatedAt: p.now}, CredentialID: []byte("cid"), SignCount: 7,
	})
	p.wa.Asserted = webauthn.Asserted{CredentialID: []byte("cid"), SignCount: 8, UserVerified: true}
	login := func() (commands.VerifiedLogin, error) {
		out, err := p.cmd.BeginPasskeyLogin(ctx, commands.BeginPasskeyLogin{})
		if err != nil {
			t.Fatal(err)
		}
		return p.cmd.FinishPasskeyLogin(ctx, commands.PasskeyLogin{Token: out.Token, Body: handle, IP: "1.1.1.1"})
	}
	got, err := login()
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if row := p.sessions.Rows[got.Session.SessionID]; len(row.AuthMethods) != 3 || row.AuthMethods[0] != "hwk" {
		t.Fatalf("session = %+v", row)
	}
	if got := p.keys.Rows[passkeyID1].SignCount; got != 8 {
		t.Fatalf("sign count = %d", got)
	}
	// The same count again: a clone warning, no session.
	if _, err := login(); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("repeated count: %v", err)
	}
	// The user handle of another user.
	p.wa.Asserted.SignCount = 9
	out, _ := p.cmd.BeginPasskeyLogin(ctx, commands.BeginPasskeyLogin{})
	if _, err := p.cmd.FinishPasskeyLogin(ctx, commands.PasskeyLogin{Token: out.Token, Body: []byte("another handle"), IP: "1.1.1.1"}); !errors.Is(err, commands.ErrPasskeyInvalid) {
		t.Fatalf("other handle: %v", err)
	}
	// A token that was used is gone.
	if _, err := p.cmd.FinishPasskeyLogin(ctx, commands.PasskeyLogin{Token: out.Token, Body: handle}); !errors.Is(err, commands.ErrCeremonyGone) {
		t.Fatalf("used token: %v", err)
	}
}

// R11: a registration that finishes after the reset of the MFA finds its session
// revoked in the insert transaction. The passkey is not stored.
func TestIssue15_R11_RegistrationAfterReset(t *testing.T) {
	p := newPasskeyEnv(t)
	p.buildPasskeys(t, true)
	const sessionID = "session-r11"
	p.sessions.Rows[sessionID] = domain.Session{
		ID: sessionID, UserID: userA, AuthMethods: []string{"pwd"},
		IdleExpiresAt: p.clock().Add(time.Hour), ExpiresAt: p.clock().Add(time.Hour),
	}
	if _, err := p.cmd.BeginPasskeyRegistration(ctx, commands.BeginPasskey{SessionID: sessionID, UserID: userA, Name: "Late"}); err != nil {
		t.Fatal(err)
	}
	p.wa.Registered = webauthn.Credential{ID: []byte("late-credential"), PublicKey: []byte("pk")}
	revoked := p.clock()
	row := p.sessions.Rows[sessionID]
	row.RevokedAt = &revoked
	p.sessions.Rows[sessionID] = row
	_, err := p.cmd.FinishPasskeyRegistration(ctx, commands.FinishPasskey{
		SessionID: sessionID, UserID: userA, SessionMethods: []string{"pwd"}, Body: []byte("{}"),
	})
	if !errors.Is(err, commands.ErrCeremonyGone) {
		t.Fatalf("finish = %v, want ErrCeremonyGone", err)
	}
	if n, _ := p.keys.Count(ctx, userA); n != 0 {
		t.Fatalf("no passkey may be stored, count = %d", n)
	}
}
