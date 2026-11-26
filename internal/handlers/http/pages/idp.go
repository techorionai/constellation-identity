package pages

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// IdpCookieName is the name of the cookie that binds an upstream flow to the
// browser. It has the rules of the other cookies. The value is a secret.
const IdpCookieName = "__Host-constellation_idp"

// Texts of the pages of the upstream flows.
const (
	idpFailedText   = "The login did not complete."
	idpExpiredText  = "The login expired. Try again."
	idpNotLinked    = "This account is not linked. Log in and link it on the account page."
	idpLinkedOther  = "This account is linked to another user."
	idpMismatchText = "This account does not match the invitation."
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

func (h *Handler) setIdpCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: IdpCookieName, Value: value, Path: "/", MaxAge: int(commands.IdpFlowTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearIdpCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: IdpCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func idpCookieValue(r *http.Request) string {
	c, err := r.Cookie(IdpCookieName)
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
	if purpose == domain.FlowLink {
		// The link needs a fresh session. A session that is too old goes to the
		// login page and comes back to the account page.
		if _, ok := h.accountSession(w, r, "/account/security", true, false); !ok {
			return
		}
		in.SessionToken = cookieValue(r)
	}
	started, err := h.d.Idp.Start(r.Context(), in)
	if err != nil {
		h.idpStartError(w, r, err)
		return
	}
	h.setIdpCookie(w, started.Binding)
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
	res, err := h.d.Idp.Callback(r.Context(), commands.CallbackIdp{
		Provider: provider, State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss"), ProviderError: q.Has("error"),
		Binding: idpCookieValue(r), SessionToken: cookieValue(r),
		IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	// The flow is over, with a good result or not. A callback with a state that
	// the service does not know, or with the cookie of another flow, does not
	// clear the cookie: a request of another site must not end the flow of the user.
	if !errors.Is(err, commands.ErrIdpExpired) {
		clearIdpCookie(w)
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
	res, ok := h.accountSession(w, r, "/account/security", true, false)
	if !ok {
		return
	}
	err := h.d.IdentityLinks.Remove(r.Context(), commands.RemoveIdentityLink{
		UserID: res.User.ID, Provider: r.PathValue("provider"), Actor: res.User.ID,
	})
	switch {
	case err == nil:
		for _, m := range res.Session.AuthMethods {
			if m == domain.AMRFederated {
				clearCookie(w)
				http.Redirect(w, r, "/login?removed=1", http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
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
	err := h.d.SetPassword.Execute(r.Context(), commands.SetPassword{UserID: res.User.ID, Password: r.PostForm.Get("password")})
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
