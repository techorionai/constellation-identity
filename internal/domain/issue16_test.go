package domain_test

import (
	"slices"
	"testing"
	"time"

	"github.com/techorionai/constellation-identity/internal/domain"
)

const (
	tenantA = "11111111-aaaa-4aaa-8aaa-111111111111"
	tenantB = "22222222-bbbb-4bbb-8bbb-222222222222"
	msBase  = "https://login.microsoftonline.com"
)

// U2: the subject key of a Microsoft account.
func TestIssue16_U2_MicrosoftSubject(t *testing.T) {
	got, err := domain.MicrosoftSubject(tenantA, "oid-1")
	if err != nil || got != tenantA+":oid-1" {
		t.Fatalf("subject = %q, %v", got, err)
	}
	for _, c := range []struct{ tid, oid string }{{"not-a-guid", "o"}, {tenantA, ""}, {tenantA, "a:b"}} {
		if _, err := domain.MicrosoftSubject(c.tid, c.oid); err == nil {
			t.Errorf("tid %q oid %q must fail", c.tid, c.oid)
		}
	}
}

// U3: the issuer rule of the tenant organizations.
func TestIssue16_U3_MicrosoftIssuer(t *testing.T) {
	cases := []struct {
		name, iss, tid string
		ok             bool
	}{
		{"issuer of the tid", msBase + "/" + tenantA + "/v2.0", tenantA, true},
		{"issuer of another tenant", msBase + "/" + tenantB + "/v2.0", tenantA, false},
		{"tid is not a GUID", msBase + "/not-a-guid/v2.0", "not-a-guid", false},
		{"template", msBase + "/{tenantid}/v2.0", tenantA, false},
		{"other host", "https://evil.example.com/" + tenantA + "/v2.0", tenantA, false},
		{"v1 issuer", msBase + "/" + tenantA + "/", tenantA, false},
	}
	for _, c := range cases {
		err := domain.CheckMicrosoftIssuer(msBase, c.iss, c.tid)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// U4: the Google hosted domain rule.
func TestIssue16_U4_GoogleHD(t *testing.T) {
	list := []string{"example.com"}
	for _, c := range []struct {
		list []string
		hd   string
		ok   bool
	}{{list, "example.com", true}, {list, "Example.com", true}, {list, "other.com", false}, {list, "", false}, {nil, "", true}, {nil, "x.com", true}} {
		if got := domain.GoogleHDAllowed(c.list, c.hd); got != c.ok {
			t.Errorf("list %v hd %q = %v, want %v", c.list, c.hd, got, c.ok)
		}
	}
}

// U5, U11: the verified email rules. Google: the boolean true and the string
// "true". Anything else is not verified.
func TestIssue16_U5_U11_VerifiedEmail(t *testing.T) {
	for _, c := range []struct {
		v    any
		want bool
	}{{true, true}, {"true", true}, {false, false}, {"false", false}, {nil, false}, {1.0, false}, {"True", false}} {
		if got := domain.VerifiedFlag(c.v); got != c.want {
			t.Errorf("VerifiedFlag(%#v) = %v, want %v", c.v, got, c.want)
		}
	}
}

// U5, U12: the Microsoft rule needs the email claim and xms_edov true.
func TestIssue16_U12_MicrosoftVerified(t *testing.T) {
	for _, c := range []struct {
		email string
		edov  any
		want  bool
	}{{"a@example.com", true, true}, {"a@example.com", false, false}, {"a@example.com", nil, false}, {"", true, false}} {
		if got := domain.MicrosoftEmailVerified(c.email, c.edov); got != c.want {
			t.Errorf("MicrosoftEmailVerified(%q, %#v) = %v, want %v", c.email, c.edov, got, c.want)
		}
	}
}

// U14: the builders of the methods.
func TestIssue16_U14_WithSecondFactor(t *testing.T) {
	fed, pwd := domain.MethodsFederated(), domain.MethodsPassword()
	for _, c := range []struct {
		name  string
		first []string
		f     []string
		want  []string
	}{
		{"fed totp", fed, []string{domain.AMROTP}, []string{"fed", "otp", "mfa"}},
		{"fed recovery", fed, []string{domain.AMRRecovery}, []string{"fed", "rec", "mfa"}},
		{"fed passkey", fed, domain.PasskeyFactor(false), []string{"fed", "hwk", "mfa"}},
		{"fed passkey verified", fed, domain.PasskeyFactor(true), []string{"fed", "hwk", "user", "mfa"}},
		{"pwd totp", pwd, []string{domain.AMROTP}, []string{"pwd", "otp", "mfa"}},
		{"pwd recovery", pwd, []string{domain.AMRRecovery}, []string{"pwd", "rec", "mfa"}},
		{"pwd passkey", pwd, domain.PasskeyFactor(false), []string{"pwd", "hwk", "mfa"}},
		{"pwd passkey verified", pwd, domain.PasskeyFactor(true), []string{"pwd", "hwk", "user", "mfa"}},
	} {
		if got := domain.WithSecondFactor(c.first, c.f...); !slices.Equal(got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	if got := domain.FirstFactor([]string{"fed", "hwk", "mfa"}); !slices.Equal(got, fed) {
		t.Errorf("first factor = %v", got)
	}
	if got := domain.FirstFactor(nil); !slices.Equal(got, pwd) {
		t.Errorf("first factor of no methods = %v", got)
	}
	// The builder does not change its input.
	in := []string{"fed"}
	_ = domain.WithSecondFactor(in, "otp")
	if len(in) != 1 {
		t.Fatal("the input changed")
	}
}

// U15: the one definition of the rule "last login method", and U6, the enable rule.
func TestIssue16_U15_HasLoginMethod(t *testing.T) {
	googleOn := func(p string) bool { return p == domain.ProviderGoogle }
	for _, c := range []struct {
		name string
		s    domain.MethodsState
		want bool
	}{
		{"password only", domain.MethodsState{HasPassword: true}, true},
		{"passkey, passkeys on", domain.MethodsState{Passkeys: 1, PasskeysOn: true}, true},
		{"passkey, passkeys off", domain.MethodsState{Passkeys: 1}, false},
		{"link, provider on", domain.MethodsState{Links: []string{"google"}, On: googleOn}, true},
		{"link, provider off", domain.MethodsState{Links: []string{"microsoft"}, On: googleOn}, false},
		{"link with no provider setting", domain.MethodsState{Links: []string{"google"}}, false},
		{"passkey and link", domain.MethodsState{Passkeys: 1, PasskeysOn: true, Links: []string{"google"}, On: googleOn}, true},
		{"nothing", domain.MethodsState{}, false},
	} {
		if got := domain.HasLoginMethod(c.s); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	// U6: the status of a user that an admin enables.
	if got := domain.EnableStatus(domain.MethodsState{Links: []string{"google"}, On: googleOn}); got != domain.UserActive {
		t.Errorf("link on = %s", got)
	}
	if got := domain.EnableStatus(domain.MethodsState{}); got != domain.UserInvited {
		t.Errorf("nothing = %s", got)
	}
	if got := domain.EnableStatus(domain.MethodsState{Links: []string{"microsoft"}, On: googleOn}); got != domain.UserInvited {
		t.Errorf("link off = %s", got)
	}
}

// U16: the audience rules.
func TestIssue16_U16_Audience(t *testing.T) {
	for _, c := range []struct {
		name string
		aud  []string
		azp  string
		ok   bool
	}{
		{"one audience", []string{"c"}, "", true},
		{"two audiences", []string{"c", "d"}, "", false},
		{"azp is the client", []string{"c"}, "c", true},
		{"azp of another client", []string{"c"}, "other", false},
		{"audience of another client", []string{"other"}, "", false},
		{"no audience", nil, "", false},
	} {
		if err := domain.CheckAudience(c.aud, c.azp, "c"); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// U17: the iss parameter.
func TestIssue16_U17_IssParam(t *testing.T) {
	for _, c := range []struct {
		provider, got string
		ok            bool
	}{
		{domain.ProviderGoogle, domain.GoogleIssuer, true},
		{domain.ProviderGoogle, "https://evil.example.com", false},
		{domain.ProviderGoogle, "", false},
		{domain.ProviderMicrosoft, "https://evil.example.com", true},
		{domain.ProviderMicrosoft, "", true},
	} {
		if got := domain.IssParamOK(c.provider, c.got, domain.GoogleIssuer); got != c.ok {
			t.Errorf("%s %q = %v, want %v", c.provider, c.got, got, c.ok)
		}
	}
}

// U18: the signing key rules of Microsoft.
func TestIssue16_U18_MicrosoftKeyIssuer(t *testing.T) {
	issA := msBase + "/" + tenantA + "/v2.0"
	issB := msBase + "/" + tenantB + "/v2.0"
	for _, c := range []struct {
		name, keyIssuer, iss, tid string
		ok                        bool
	}{
		{"GUID equal to iss", issA, issA, tenantA, true},
		{"key of tenant B, token of tenant A", issB, issA, tenantA, false},
		{"template with the tid", msBase + "/{tenantid}/v2.0", issA, tenantA, true},
		{"template, token of another tenant than its tid", msBase + "/{tenantid}/v2.0", issB, tenantA, false},
		{"no issuer property", "", issA, tenantA, true},
	} {
		if err := domain.CheckMicrosoftKeyIssuer(c.keyIssuer, c.iss, c.tid); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
	}
	// A key with no property needs rules 1 and 3 of the issuer check.
	if err := domain.CheckMicrosoftIssuer(msBase, issA, tenantA); err != nil {
		t.Errorf("rule 1 and 3: %v", err)
	}
}

// U20: the provider name rule.
func TestIssue16_U20_ProviderName(t *testing.T) {
	for _, c := range []struct {
		s  string
		ok bool
	}{{"google", true}, {"microsoft", true}, {"Google", false}, {"okta", false}, {"", false}, {"google ", false}} {
		if got := domain.ValidProvider(c.s); got != c.ok {
			t.Errorf("ValidProvider(%q) = %v, want %v", c.s, got, c.ok)
		}
	}
}

// U21: the freshness of an upstream token.
func TestIssue16_U21_UpstreamFresh(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name     string
		provider string
		auth, at time.Time
		want     bool
	}{
		{"microsoft auth_time 1 minute old", domain.ProviderMicrosoft, now.Add(-time.Minute), now.Add(-time.Hour), true},
		{"microsoft iat 10 minutes old, no auth_time", domain.ProviderMicrosoft, time.Time{}, now.Add(-10 * time.Minute), false},
		{"microsoft iat 1 minute old, no auth_time", domain.ProviderMicrosoft, time.Time{}, now.Add(-time.Minute), true},
		{"google auth_time 10 minutes old", domain.ProviderGoogle, now.Add(-10 * time.Minute), now, false},
		{"google no auth_time", domain.ProviderGoogle, time.Time{}, now.Add(-time.Hour), true},
		{"microsoft with no time", domain.ProviderMicrosoft, time.Time{}, time.Time{}, false},
		{"auth_time far in the future", domain.ProviderMicrosoft, now.Add(time.Hour), now, false},
		{"auth_time a little in the future", domain.ProviderMicrosoft, now.Add(30 * time.Second), now, true},
	} {
		if got := domain.UpstreamFresh(c.provider, c.auth, c.at, now); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

// U23: the Sec-Fetch-Site rule of the start.
func TestIssue16_U23_SecFetchSite(t *testing.T) {
	headers := []string{"cross-site", "same-site", "same-origin", "none", ""}
	strict := []bool{false, false, true, false, true}
	for _, purpose := range []string{domain.FlowLink, domain.FlowInvite} {
		for i, h := range headers {
			if got := domain.SecFetchSiteAllowed(purpose, h); got != strict[i] {
				t.Errorf("%s %q = %v, want %v", purpose, h, got, strict[i])
			}
		}
	}
	for _, h := range headers {
		if !domain.SecFetchSiteAllowed(domain.FlowLogin, h) {
			t.Errorf("login %q must be allowed", h)
		}
	}
}

// The tenant setting: a GUID or organizations. U1 tests the config. This tests
// the rule.
func TestIssue16_TenantRule(t *testing.T) {
	for _, c := range []struct {
		s  string
		ok bool
	}{{"organizations", true}, {tenantA, true}, {"common", false}, {"consumers", false}, {"", false}} {
		if got := domain.ValidMicrosoftTenant(c.s); got != c.ok {
			t.Errorf("ValidMicrosoftTenant(%q) = %v, want %v", c.s, got, c.ok)
		}
	}
}
