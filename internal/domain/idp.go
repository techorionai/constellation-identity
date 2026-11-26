package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The upstream identity providers.
const (
	ProviderGoogle    = "google"
	ProviderMicrosoft = "microsoft"
)

// GoogleIssuer is the issuer of the Google discovery document. The ID token of
// Google has this value or the same text with no scheme.
const GoogleIssuer = "https://accounts.google.com"

// MicrosoftLoginBase is the base URL of the Microsoft login service.
const MicrosoftLoginBase = "https://login.microsoftonline.com"

// MicrosoftOrganizations is the tenant value that allows all work and school
// accounts.
const MicrosoftOrganizations = "organizations"

// TenantTemplate is the text that the Microsoft documents use for the tenant ID.
const TenantTemplate = "{tenantid}"

// ValidProvider reports whether s is exactly the name of a supported provider.
// A value of another case, an unknown provider, and an empty value are not
// valid.
func ValidProvider(s string) bool { return s == ProviderGoogle || s == ProviderMicrosoft }

// Errors of the upstream identity rules.
var (
	// ErrUpstreamToken means an ID token breaks a rule of the service.
	ErrUpstreamToken = errors.New("the upstream ID token is not valid")
	// ErrNotFresh means an upstream login is older than the fresh login rule allows.
	ErrNotFresh = errors.New("the upstream login is not fresh")
)

// UpstreamIdentity is the identity that an upstream provider proved. The
// subject is the key of the link. It is internal and never shown.
type UpstreamIdentity struct {
	Provider string
	// Subject is the subject key: sub for Google, and "<tid>:<oid>" for Microsoft.
	Subject string
	// Email is the email claim. It is not a key and the service never uses it
	// to find a user.
	Email string
	// EmailVerified is true when the provider says that the email is verified.
	EmailVerified bool
	// AuthTime is the auth_time claim, or the zero time.
	AuthTime time.Time
	// IssuedAt is the iat claim.
	IssuedAt time.Time
}

// IdentityLink is the link between a user and an account at a provider.
type IdentityLink struct {
	ID         string
	UserID     string
	Provider   string
	Subject    string
	Email      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// The purposes of an upstream flow.
const (
	FlowLogin  = "login"
	FlowLink   = "link"
	FlowInvite = "invite"
	// FlowUnlink is the removal of a link by a user with no local factor. The
	// upstream login must have a valid auth_time (P23).
	FlowUnlink = "unlink"
)

// ValidFlowPurpose reports whether s is a purpose of an upstream flow.
func ValidFlowPurpose(s string) bool {
	return s == FlowLogin || s == FlowLink || s == FlowInvite || s == FlowUnlink
}

// IdpFlow is the record of an upstream flow between the start and the callback.
// The store keeps it for a short time, under the hash of the state.
type IdpFlow struct {
	Provider string `json:"provider"`
	Purpose  string `json:"purpose"`
	// Nonce and Verifier are secrets of the flow.
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	// BindingHash is the hash of the value of the cookie of the browser.
	BindingHash string `json:"binding_hash"`
	// Fresh is true when the flow needs a fresh login at the provider.
	Fresh bool `json:"fresh"`
	// AuthRequest and ReturnTo are the place to go after a login. The start
	// checked them.
	AuthRequest string `json:"auth_request,omitempty"`
	ReturnTo    string `json:"return_to,omitempty"`
	// SessionHash is the hash of the session cookie value (purpose link).
	SessionHash string `json:"session_hash,omitempty"`
	// InviteHash is the hash of the invite token (purpose invite).
	InviteHash string `json:"invite_hash,omitempty"`
	// NeedAuthTime is true when the callback must refuse an ID token with no
	// valid auth_time. The start sets it for a link of a user that has no local
	// factor (P23).
	NeedAuthTime bool `json:"need_auth_time,omitempty"`
	// RemoveProvider is the provider of the link that the flow removes (purpose
	// unlink).
	RemoveProvider string `json:"remove_provider,omitempty"`
}

// FlowID returns the short ID of a flow. It is the start of the hash of the
// state, so it tells nothing about the state. The name of the binding cookie of
// the flow has it, so two flows of one browser have two cookies (R8).
func FlowID(state string) string { return HashSecret(state)[:16] }

// FlowConfirm is the purpose of the record that a local factor check leaves. It
// is not the purpose of an upstream flow. The record has the provider and the
// hash of the session, and the start of the purpose link takes it one time.
const FlowConfirm = "confirm"

var guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidGUID reports whether s has the form of a GUID.
func ValidGUID(s string) bool { return guidPattern.MatchString(s) }

// ValidMicrosoftTenant reports whether the tenant setting is allowed: a tenant
// GUID or "organizations". The values "common" and "consumers" allow personal
// accounts, so they are not allowed.
func ValidMicrosoftTenant(s string) bool { return s == MicrosoftOrganizations || ValidGUID(s) }

// MicrosoftSubject makes the subject key of a Microsoft account from the tenant
// ID and the object ID.
func MicrosoftSubject(tid, oid string) (string, error) {
	if !ValidGUID(tid) || oid == "" || strings.ContainsAny(oid, ": \t\r\n") {
		return "", ErrUpstreamToken
	}
	return tid + ":" + oid, nil
}

// CheckMicrosoftIssuer checks the issuer of a token of the tenant "organizations".
// The tid must be a GUID. The iss must be exactly base/<tid>/v2.0 with the tid of
// the same token, and the first path segment after the base must be the tid.
func CheckMicrosoftIssuer(base, iss, tid string) error {
	if !ValidGUID(tid) || iss != base+"/"+tid+"/v2.0" {
		return ErrUpstreamToken
	}
	rest := strings.TrimPrefix(iss, base+"/")
	first, _, _ := strings.Cut(rest, "/")
	if first != tid {
		return ErrUpstreamToken
	}
	return nil
}

// CheckMicrosoftKeyIssuer checks the issuer property of a signing key. A key
// with no property has no further rule. A key with a GUID issuer is good only
// for the same iss. A key with the template is good for the iss that has the tid
// of the token in place of the template.
func CheckMicrosoftKeyIssuer(keyIssuer, iss, tid string) error {
	if keyIssuer == "" {
		return nil
	}
	want := strings.ReplaceAll(keyIssuer, TenantTemplate, tid)
	if want != iss {
		return ErrUpstreamToken
	}
	return nil
}

// GoogleHDAllowed is the rule of the Google hosted domain. An empty list allows
// all accounts. Else the hd claim must be in the list.
func GoogleHDAllowed(allowed []string, hd string) bool {
	if len(allowed) == 0 {
		return true
	}
	hd = strings.ToLower(strings.TrimSpace(hd))
	if hd == "" {
		return false
	}
	return slices.ContainsFunc(allowed, func(a string) bool { return strings.ToLower(strings.TrimSpace(a)) == hd })
}

// VerifiedFlag reads the claim that tells that an email is verified. The
// documents give the type of the value in two ways, so the rule accepts the
// boolean true and the string "true". Any other value, and a missing value,
// mean "not verified".
func VerifiedFlag(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

// MicrosoftEmailVerified is the rule of the Microsoft email. The email counts
// as verified only when the token has the email claim and xms_edov is true.
func MicrosoftEmailVerified(email string, xmsEdov any) bool {
	return email != "" && VerifiedFlag(xmsEdov)
}

// CheckAudience checks the audience of an ID token. The token must have one
// audience, and it must be the client ID. An azp claim, if present, must be the
// client ID.
func CheckAudience(aud []string, azp, clientID string) error {
	if len(aud) != 1 || aud[0] != clientID {
		return ErrUpstreamToken
	}
	if azp != "" && azp != clientID {
		return ErrUpstreamToken
	}
	return nil
}

// IssParamOK checks the iss parameter of the response of the authorization
// endpoint (RFC 9207). A provider that sets
// authorization_response_iss_parameter_supported (Google) must send it, and it
// must be the issuer of the discovery document. The service ignores the value
// of other providers.
func IssParamOK(provider, got, issuer string) bool {
	if provider != ProviderGoogle {
		return true
	}
	return got != "" && got == issuer
}

// clockSkew is the tolerance for a time claim in the future.
const clockSkew = 60 * time.Second

// UpstreamFresh is the freshness rule of an upstream login for a flow that needs
// a fresh login. For Microsoft, auth_time is used if present, else iat. For
// Google, auth_time is used if present, and a token with no auth_time passes
// (the documents give no way to force a login). The time must be at most
// MaxFreshAge old, with a tolerance for the clock of the provider.
func UpstreamFresh(provider string, authTime, issuedAt, now time.Time) bool {
	t := authTime
	if t.IsZero() {
		if provider == ProviderGoogle {
			return true
		}
		t = issuedAt
	}
	if t.IsZero() {
		return false
	}
	return t.Before(now.Add(clockSkew)) && now.Sub(t) <= MaxFreshAge
}

// UpstreamAuthTimeFresh is the strict freshness rule of P23. The ID token must
// have an auth_time, and it must be at most MaxFreshAge old. A token with no
// auth_time does not pass, for any provider. The rule has the same tolerance
// for the clock of the provider as UpstreamFresh.
func UpstreamAuthTimeFresh(authTime, now time.Time) bool {
	if authTime.IsZero() {
		return false
	}
	return authTime.Before(now.Add(clockSkew)) && now.Sub(authTime) <= MaxFreshAge
}

// HasLocalFactor reports whether a user has a local factor: a password, a TOTP
// factor, or a passkey that the service accepts (P23). A login method at a
// provider is not a local factor.
func HasLocalFactor(hasPassword bool, s MFAState) bool {
	return hasPassword || s.HasTOTP || s.AcceptedPasskeys() > 0
}

// LocalFactorMethod reports whether an amr value is the proof of a local factor.
func LocalFactorMethod(m string) bool {
	return m == AMRPassword || m == AMROTP || m == AMRRecovery || m == AMRHardwareKey
}

// SecFetchSiteAllowed is the rule of the start of an upstream flow. The purposes
// link and invite need a request from our own page: the header Sec-Fetch-Site
// must be same-origin, or absent. The purpose login has no rule, because the
// flow is bound to the cookie of the browser.
func SecFetchSiteAllowed(purpose, header string) bool {
	if purpose == FlowLogin {
		return true
	}
	return header == "" || header == "same-origin"
}

// ProviderOn tells if the operator turned a provider on.
type ProviderOn func(provider string) bool

// MethodsState is the data that the rule "last login method" needs.
type MethodsState struct {
	// HasPassword is true when the user has a password.
	HasPassword bool
	// Passkeys is the number of stored passkeys, and PasskeysOn is true when the
	// service accepts them.
	Passkeys   int
	PasskeysOn bool
	// Links are the providers of the links of the user.
	Links []string
	// On tells if a provider is on. A nil value means that all are off.
	On ProviderOn
}

// HasLoginMethod is the one definition of the rule "last login method". A
// password counts. A passkey counts when passkeys are on. A link counts when
// its provider is on.
func HasLoginMethod(s MethodsState) bool {
	if s.HasPassword {
		return true
	}
	if s.PasskeysOn && s.Passkeys > 0 {
		return true
	}
	if s.On == nil {
		return false
	}
	return slices.ContainsFunc(s.Links, s.On)
}

// EnableStatus is the status of a disabled user that an admin enables: active
// if the user has a login method, else invited.
func EnableStatus(s MethodsState) UserStatus {
	if HasLoginMethod(s) {
		return UserActive
	}
	return UserInvited
}
