package pages

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// IdpCookieName is the start of the name of the cookie that binds an upstream
// flow to the browser. The name ends with the ID of the flow, so a second flow
// in another tab does not replace the cookie of the first flow (R8). The
// cookie has the rules of the other cookies. The value is a secret.
const IdpCookieName = "__Host-constellation_idp"

// IdpCookieNameFor returns the name of the cookie of a flow. The state is the
// state parameter of the callback.
func IdpCookieNameFor(state string) string {
	return IdpCookieName + "_" + domain.FlowID(state)
}

// Texts of the pages of the upstream flows.
const (
	idpFailedText   = "The login did not complete."
	idpExpiredText  = "The login expired. Try again."
	idpNotLinked    = "This account is not linked. Log in and link it on the account page."
	idpLinkedOther  = "This account is linked to another user."
	idpMismatchText = "This account does not match the invitation."
	// The texts of the check of a local factor (P23).
	factorWrongText   = "The password or the code is not right."
	factorMissingText = "Set a password or an authenticator app first. Then you can link and remove accounts."
)

// providerNames gives the name of a provider on a page.
var providerNames = map[string]string{domain.ProviderGoogle: "Google", domain.ProviderMicrosoft: "Microsoft"}

// providerLink is a link to the start of an upstream flow.
type providerLink struct {
	Provider string
	Name     string
	URL      string
}

// idpEnabled reports whether the routes of the upstream flows are on.
func (h *Handler) idpEnabled() bool { return h.d.Idp != nil && len(h.d.Providers) > 0 }

// idpLinks returns the links of the providers that are on. The values are
// added to the URL of the start.
func (h *Handler) idpLinks(purpose string, values url.Values) []providerLink {
	var out []providerLink
	if !h.idpEnabled() {
		return nil
	}
	for _, p := range h.d.Providers {
		q := url.Values{"purpose": {purpose}}
		for k, v := range values {
			for _, x := range v {
				if x != "" {
					q.Add(k, x)
				}
			}
		}
		out = append(out, providerLink{Provider: p, Name: providerNames[p], URL: "/login/oidc/" + p + "?" + q.Encode()})
	}
	return out
}

func (h *Handler) setIdpCookie(w http.ResponseWriter, flow, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: IdpCookieName + "_" + flow, Value: value, Path: "/", MaxAge: int(commands.IdpFlowTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearIdpCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func idpCookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// idpStart starts an upstream flow. The page links to this route with a link,
// not with a form, because a form that redirects to another host breaks the CSP
// rule form-action.
func (h *Handler) idpStart(w http.ResponseWriter, r *http.Request) {
	if !h.idpEnabled() {
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	q := r.URL.Query()
	purpose := q.Get("purpose")
	if purpose == "" {
		purpose = domain.FlowLogin
	}
	in := commands.StartIdp{
		Provider: r.PathValue("provider"), Purpose: purpose, AuthRequest: q.Get("authRequest"), ReturnTo: q.Get("return_to"),
		InviteToken: TokenFromRequest(r), Fresh: q.Get("prompt") == "login", SecFetchSite: r.Header.Get("Sec-Fetch-Site"),
	}
	if purpose == domain.FlowLink || purpose == domain.FlowUnlink {
		in.RemoveProvider = q.Get("remove")
		// The use case reads the session one time (R17). It needs a fresh session
		// and the proof of a local factor (P23). The error ErrIdpReauth sends a
		// session that is too old to the login page.
		in.SessionToken, in.Confirm = cookieValue(r), q.Get("confirm")
	}
	started, err := h.d.Idp.Start(r.Context(), in)
	if err != nil {
		h.idpStartError(w, r, err)
		return
	}
	h.setIdpCookie(w, started.Flow, started.Binding)
	// The location is the authorization URL of a provider that the operator set.
	http.Redirect(w, r, started.Location, http.StatusFound) //nolint:gosec // G710: see the line above.
}

func (h *Handler) idpStartError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, commands.ErrIdpProviderOff):
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
	case errors.Is(err, commands.ErrIdpFailed):
		h.message(w, r, http.StatusBadRequest, "Cannot log in", idpFailedText)
	case errors.Is(err, commands.ErrIdpProviderDown):
		h.log.WarnContext(r.Context(), "identity.idp.start_failed", "event", "identity.idp.start_failed", "error", err)
		h.message(w, r, http.StatusBadGateway, "Cannot log in", idpFailedText)
	case errors.Is(err, commands.ErrIdpReauth):
		h.loginRedirect(w, r, "/account/security")
	case errors.Is(err, commands.ErrIdpConfirm):
		http.Redirect(w, r, "/account/identity-links/"+url.PathEscape(r.PathValue("provider"))+"/link", http.StatusSeeOther)
	case errors.Is(err, commands.ErrIdpUnavailable):
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	default:
		h.serverError(w, r, err)
	}
}

// idpCallback finishes an upstream flow. The response mode is query, so the
// callback is a top-level GET that http.CrossOriginProtection does not block.
func (h *Handler) idpCallback(w http.ResponseWriter, r *http.Request) {
	if !h.idpEnabled() {
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	q := r.URL.Query()
	provider := r.PathValue("provider")
	cookieName := IdpCookieNameFor(q.Get("state"))
	res, err := h.d.Idp.Callback(r.Context(), commands.CallbackIdp{
		Provider: provider, State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss"), ProviderError: q.Has("error"),
		Binding: idpCookieValue(r, cookieName), SessionToken: cookieValue(r),
		IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	// The flow is over, with a good result or not. A callback with a state that
	// the service does not know, or with the cookie of another flow, does not
	// clear the cookie: a request of another site must not end the flow of the user.
	if !errors.Is(err, commands.ErrIdpExpired) {
		clearIdpCookie(w, cookieName)
	}
	if err != nil {
		h.idpCallbackError(w, r, provider, err)
		return
	}
	switch res.Kind {
	case commands.IdpPending:
		h.setMFACookie(w, res.Session)
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
	case commands.IdpLinked:
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	case commands.IdpUnlinked:
		if res.SessionEnded {
			clearCookie(w)
			http.Redirect(w, r, "/login?removed=1", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	default:
		h.setCookie(w, res.Session)
		target := afterLogin(res.AuthRequest, res.ReturnTo)
		if res.Purpose == domain.FlowInvite {
			target = h.setupTarget(r, res.Session.UserID, "/login/done")
		} else if res.Session.SetupRequired {
			target = setupPath(res.AuthRequest, res.ReturnTo)
		}
		// target is a fixed path, or a path that domain.SafeReturnTo accepted.
		http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: see the line above.
	}
}

func (h *Handler) idpCallbackError(w http.ResponseWriter, r *http.Request, provider string, err error) {
	switch {
	case errors.Is(err, commands.ErrIdpProviderOff):
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
	case errors.Is(err, commands.ErrIdpExpired):
		h.message(w, r, http.StatusBadRequest, "Login expired", idpExpiredText)
	case errors.Is(err, commands.ErrIdpNotLinked):
		h.message(w, r, http.StatusForbidden, "Account not linked", idpNotLinked)
	case errors.Is(err, commands.ErrIdpLinkedElsewhere):
		h.message(w, r, http.StatusConflict, "Account linked", idpLinkedOther)
	case errors.Is(err, commands.ErrIdpAlreadyLinked):
		h.message(w, r, http.StatusConflict, "Account already linked",
			"You already linked a "+strings.ToLower(providerNames[provider])+" account. Remove it first.")
	case errors.Is(err, commands.ErrIdpMismatch):
		h.message(w, r, http.StatusForbidden, "Invitation", idpMismatchText)
	case errors.Is(err, commands.ErrIdpFailed):
		h.message(w, r, http.StatusBadRequest, "Cannot log in", idpFailedText)
	case errors.Is(err, commands.ErrIdpReauth):
		h.loginRedirect(w, r, "/account/security")
	case errors.Is(err, commands.ErrIdentityLinkNotFound):
		h.message(w, r, http.StatusNotFound, "Link not found", "You have no link for this provider.")
	case errors.Is(err, commands.ErrLastLoginMethod):
		h.message(w, r, http.StatusConflict, "Last login method", "You cannot remove your last login method.")
	case errors.Is(err, commands.ErrLocalFactorMissing):
		h.message(w, r, http.StatusConflict, "Check not passed", factorMissingText)
	case errors.Is(err, commands.ErrIdpUnavailable), errors.Is(err, commands.ErrMFAUnavailable):
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	default:
		h.serverError(w, r, err)
	}
}

// --- links on the account page ---

// linkRemove removes an upstream link. The session needs a fresh login. The
// sessions that the upstream login made end, so a user that logged in with the
// link goes to the login page.
func (h *Handler) linkRemove(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	res, ok := h.accountSession(w, r, "/account/security", true, false)
	if !ok {
		return
	}
	// The user proves a local factor, a password or a code, before the removal
	// (P23). A user that has no password and no code cannot remove a link.
	err := h.d.MFA.VerifyLocalFactor(r.Context(), commands.LocalFactor{
		UserID: res.User.ID, Password: r.PostForm.Get("password"), Code: r.PostForm.Get("code"),
	})
	if err == nil {
		err = h.d.IdentityLinks.Remove(r.Context(), commands.RemoveIdentityLink{
			UserID: res.User.ID, Provider: r.PathValue("provider"), Actor: res.User.ID, Self: true, FactorVerified: true,
		})
	}
	switch {
	case errors.Is(err, commands.ErrLocalFactorRequired):
		h.message(w, r, http.StatusUnauthorized, "Check not passed", factorWrongText)
	case errors.Is(err, commands.ErrLocalFactorMissing):
		h.message(w, r, http.StatusConflict, "Password necessary", factorMissingText)
	case errors.Is(err, commands.ErrTooManyAttempts):
		h.message(w, r, http.StatusTooManyRequests, "Too many attempts", "Too many attempts. Try again later.")
	case err == nil:
		for _, m := range res.Session.AuthMethods {
			if m == domain.AMRFederated {
				clearCookie(w)
				http.Redirect(w, r, "/login?removed=1", http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	case errors.Is(err, commands.ErrUserNotFound):
		// The user does not exist any more (R7). The session is not valid.
		clearCookie(w)
		h.loginRedirect(w, r, "/account/security")
	case errors.Is(err, commands.ErrIdentityLinkNotFound):
		h.message(w, r, http.StatusNotFound, "Link not found", "You have no link for this provider.")
	case errors.Is(err, commands.ErrLastLoginMethod):
		h.message(w, r, http.StatusConflict, "Last login method", "You cannot remove your last login method.")
	default:
		h.serverError(w, r, err)
	}
}

// passwordForm shows the form that sets a first password.
func (h *Handler) passwordForm(w http.ResponseWriter, r *http.Request) {
	res, ok := h.accountSession(w, r, "/account/password", true, false)
	if !ok {
		return
	}
	if res.User.PasswordHash != "" {
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
		return
	}
	h.render(w, r, http.StatusOK, "account_password", view{Title: "Set a password"})
}

// passwordSet sets the first password of a user that has none.
func (h *Handler) passwordSet(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	res, ok := h.accountSession(w, r, "/account/password", true, false)
	if !ok {
		return
	}
	v := view{Title: "Set a password"}
	if r.PostForm.Get("password") != r.PostForm.Get("password2") {
		v.Error = mismatchText
		h.render(w, r, http.StatusBadRequest, "account_password", v)
		return
	}
	err := h.d.SetPassword.Execute(r.Context(), commands.SetPassword{UserID: res.User.ID, Password: r.PostForm.Get("password"), Actor: res.User.ID})
	switch {
	case err == nil, errors.Is(err, commands.ErrPasswordSet):
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	default:
		if text, status, ok := formError(err); ok {
			v.Error = text
			h.render(w, r, status, "account_password", v)
			return
		}
		h.serverError(w, r, err)
	}
}

// --- the check of a local factor before a link (P23) ---

// linkConfirmView makes the view of the page of a link. The user has a local
// factor if the page needs a password or a code.
func (h *Handler) linkConfirmView(r *http.Request, userID, provider string, hasPassword bool) (view, error) {
	st, err := h.d.MFA.Status(r.Context(), userID)
	if err != nil {
		return view{}, err
	}
	v := view{
		Title: "Link " + providerNames[provider], ProviderName: providerNames[provider], Provider: provider,
		HasPassword: hasPassword, TOTPOn: st.State.HasTOTP || st.State.CodesRemaining > 0,
		FactorOn: domain.HasLocalFactor(hasPassword, st.State),
	}
	v.StartURL = "/login/oidc/" + provider + "?purpose=link"
	v.PasskeyConfirm = h.passkeysOn() && st.State.AcceptedPasskeys() > 0
	return v, nil
}

func (h *Handler) providerOn(provider string) bool {
	return h.idpEnabled() && slices.Contains(h.d.Providers, provider)
}

// linkConfirmForm shows the page that asks for a local factor before a link. A
// user that has none sees the link to the start. The callback then needs an ID
// token with a valid auth_time.
func (h *Handler) linkConfirmForm(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !h.providerOn(provider) {
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	res, ok := h.accountSession(w, r, "/account/security", true, false)
	if !ok {
		return
	}
	v, err := h.linkConfirmView(r, res.User.ID, provider, res.User.PasswordHash != "")
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	h.renderLink(w, r, http.StatusOK, v)
}

// linkConfirm checks the local factor and shows the link to the start of the
// flow. The page has a link and no redirect, because a redirect after a form
// to another host breaks the CSP rule form-action.
func (h *Handler) linkConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	provider := r.PathValue("provider")
	if !h.providerOn(provider) {
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	res, ok := h.accountSession(w, r, "/account/security", true, false)
	if !ok {
		return
	}
	confirm, err := h.d.Idp.ConfirmLink(r.Context(), commands.ConfirmLink{
		Provider: provider, SessionToken: cookieValue(r),
		Password: r.PostForm.Get("password"), Code: r.PostForm.Get("code"),
	})
	if err != nil {
		h.linkConfirmError(w, r, res, provider, err)
		return
	}
	v, err := h.linkConfirmView(r, res.User.ID, provider, res.User.PasswordHash != "")
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if confirm != "" {
		v.StartURL += "&confirm=" + url.QueryEscape(confirm)
	}
	v.Done = true
	h.renderLink(w, r, http.StatusOK, v)
}

func (h *Handler) linkConfirmError(w http.ResponseWriter, r *http.Request, res queries.SessionResult, provider string, err error) {
	show := func(status int, text string) {
		v, verr := h.linkConfirmView(r, res.User.ID, provider, res.User.PasswordHash != "")
		if verr != nil {
			h.serverError(w, r, verr)
			return
		}
		v.Error = text
		h.renderLink(w, r, status, v)
	}
	switch {
	case errors.Is(err, commands.ErrLocalFactorRequired):
		show(http.StatusUnauthorized, factorWrongText)
	case errors.Is(err, commands.ErrLocalFactorMissing):
		show(http.StatusConflict, factorMissingText)
	case errors.Is(err, commands.ErrTooManyAttempts):
		show(http.StatusTooManyRequests, "Too many attempts. Try again later.")
	case errors.Is(err, commands.ErrIdpReauth), errors.Is(err, commands.ErrUserNotFound):
		h.loginRedirect(w, r, "/account/security")
	case errors.Is(err, commands.ErrIdpProviderOff):
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
	case errors.Is(err, commands.ErrIdpUnavailable):
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	default:
		h.serverError(w, r, err)
	}
}

// renderLink shows the page of a link. It has the script of the passkeys if the
// user can use a passkey as the local factor.
func (h *Handler) renderLink(w http.ResponseWriter, r *http.Request, status int, v view) {
	if v.PasskeyConfirm {
		v.Script = true
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicyWithScript(""))
	}
	h.render(w, r, status, "account_link", v)
}
