package pages

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// MFACookieName is the name of the cookie of the pending login. It has the same
// rules as the session cookie.
const MFACookieName = "__Host-constellation_mfa"

// setupBase is the TOTP setup page. A user that needs MFA and has no second
// factor goes there.
const setupBase = "/account/totp?required=1"

// maxAuthRequestLength is the longest auth request ID that a page accepts.
const maxAuthRequestLength = 128

// setupPath returns the setup page with the place to go after the setup. The
// values are optional (R6).
func setupPath(authRequest, returnTo string) string {
	p := setupBase
	if authRequest != "" {
		p += "&authRequest=" + url.QueryEscape(authRequest)
	}
	if returnTo != "" {
		p += "&return_to=" + url.QueryEscape(returnTo)
	}
	return p
}

// setupNext reads the place to go after the setup from the values of a request.
func setupNext(authRequest, returnTo string) (string, string) {
	if len(authRequest) > maxAuthRequestLength {
		authRequest = ""
	}
	rt, _ := domain.SafeReturnTo(returnTo)
	return authRequest, rt
}

func (h *Handler) setMFACookie(w http.ResponseWriter, s commands.IssuedSession) {
	maxAge := int(s.PendingExpiresAt.Sub(h.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: MFACookieName, Value: s.PendingToken, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: MFACookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func mfaCookieValue(r *http.Request) string {
	c, err := r.Cookie(MFACookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// afterLogin returns the place to go after a good login.
func afterLogin(authRequest, returnTo string) string {
	switch {
	case authRequest != "":
		return "/oauth/authorize/continue?authRequest=" + url.QueryEscape(authRequest)
	case returnTo != "":
		return returnTo
	}
	return "/login/done"
}

// --- second factor of the login ---

// mfaForm shows the form of the second factor. A user without a pending login
// goes to the login page.
func (h *Handler) mfaForm(w http.ResponseWriter, r *http.Request) {
	v := view{Title: "Second factor", Recovery: r.URL.Query().Get("recovery") == "1"}
	if !h.mfaView(w, r, &v) {
		return
	}
	h.render(w, r, http.StatusOK, "mfa", v)
}

// mfaView checks the pending login and sets the CSP form-action of the page.
// It returns false after it wrote the response.
func (h *Handler) mfaView(w http.ResponseWriter, r *http.Request, v *view) bool {
	info, err := h.d.MFA.CheckPending(r.Context(), mfaCookieValue(r))
	if errors.Is(err, commands.ErrMFAPendingGone) {
		clearMFACookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	if errors.Is(err, commands.ErrMFAUnavailable) {
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
		return false
	}
	if err != nil {
		h.serverError(w, r, err)
		return false
	}
	if info.AuthRequest != "" {
		// The redirect after the form goes to the redirect URI of the client. The
		// CSP form-action must have its origin. The auth request can end before
		// the pending login. Then the page shows with no extra origin, and the
		// continue step gives the error page after the login (R7).
		origin, err := h.d.LookupAuthRequest.Execute(r.Context(), info.AuthRequest)
		switch {
		case err == nil:
			w.Header().Set("Content-Security-Policy", ContentSecurityPolicyWithFormAction(origin.FormActionOrigin))
		case errors.Is(err, commands.ErrAuthRequestGone):
		default:
			h.serverError(w, r, err)
			return false
		}
	}
	return true
}

func (h *Handler) mfaVerify(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	recovery := r.PostForm.Get("recovery") == "1"
	verified, err := h.d.MFA.VerifyLogin(r.Context(), commands.VerifyLogin{
		PendingToken: mfaCookieValue(r), Code: r.PostForm.Get("code"), Recovery: recovery,
		IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	if err == nil {
		h.setCookie(w, verified.Session)
		clearMFACookie(w)
		// The target is a fixed path, or a path that domain.SafeReturnTo accepted.
		http.Redirect(w, r, afterLogin(verified.AuthRequest, verified.ReturnTo), http.StatusSeeOther) //nolint:gosec // G710: see the line above.
		return
	}
	v := view{Title: "Second factor", Recovery: recovery}
	switch {
	case errors.Is(err, commands.ErrMFAPendingGone):
		clearMFACookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.Is(err, commands.ErrMFABadCode):
		v.Error = "The code is not correct."
		h.renderMFA(w, r, http.StatusUnauthorized, v)
	case errors.Is(err, commands.ErrMFAReplay):
		v.Error = "This code was used already. Wait for the next code."
		h.renderMFA(w, r, http.StatusUnauthorized, v)
	case errors.Is(err, commands.ErrTooManyAttempts):
		v.Error = "Too many attempts. Try again later."
		h.renderMFA(w, r, http.StatusTooManyRequests, v)
	case errors.Is(err, commands.ErrMFAUnavailable):
		v.Error = "The service is not available. Try again later."
		h.renderMFA(w, r, http.StatusServiceUnavailable, v)
	default:
		h.serverError(w, r, err)
	}
}

func (h *Handler) renderMFA(w http.ResponseWriter, r *http.Request, status int, v view) {
	if !h.mfaView(w, r, &v) {
		return
	}
	h.render(w, r, status, "mfa", v)
}

// --- account pages ---

// loginRedirect sends the user to the login page and back to the page after a
// good login. The login asks for all factors again.
func (h *Handler) loginRedirect(w http.ResponseWriter, r *http.Request, returnTo string) {
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo)+"&prompt=login", http.StatusSeeOther)
}

// accountSession returns the session of the request. fresh needs an auth time
// of at most 5 minutes. needMFA also needs the method mfa in the session. If
// the session does not fit, the handler redirects to the login page and the
// function returns false.
func (h *Handler) accountSession(w http.ResponseWriter, r *http.Request, returnTo string, fresh, needMFA bool) (queries.SessionResult, bool) {
	res, err := h.d.Session.Execute(r.Context(), queries.SessionFromCookie{Token: cookieValue(r)})
	if errors.Is(err, queries.ErrNoSession) {
		h.loginRedirect(w, r, returnTo)
		return queries.SessionResult{}, false
	}
	if err != nil {
		h.serverError(w, r, err)
		return queries.SessionResult{}, false
	}
	if fresh && !domain.FreshLogin(res.Session.AuthTime, h.now().UTC()) {
		h.loginRedirect(w, r, returnTo)
		return queries.SessionResult{}, false
	}
	if needMFA && !domain.HasMFA(res.Session.AuthMethods) {
		h.loginRedirect(w, r, returnTo)
		return queries.SessionResult{}, false
	}
	return res, true
}

func (h *Handler) securityPage(w http.ResponseWriter, r *http.Request) {
	res, ok := h.accountSession(w, r, "/account/security", false, false)
	if !ok {
		return
	}
	st, err := h.d.MFA.Status(r.Context(), res.User.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	h.render(w, r, http.StatusOK, "account_security", view{
		Title: "Account security", UserName: res.User.Name, TOTPOn: st.State.HasTOTP,
		CodesLeft: st.State.CodesRemaining, MFARequired: st.Required,
	})
}

func (h *Handler) totpSetupForm(w http.ResponseWriter, r *http.Request) {
	res, ok := h.accountSession(w, r, "/account/totp", true, false)
	if !ok {
		return
	}
	ar, rt := setupNext(r.URL.Query().Get("authRequest"), r.URL.Query().Get("return_to"))
	h.renderSetup(w, r, http.StatusOK, res, view{
		Title: "Set up TOTP", Required: r.URL.Query().Get("required") == "1", AuthRequest: ar, ReturnTo: rt,
	})
}

// renderSetup shows the setup page with the secret and the QR code.
func (h *Handler) renderSetup(w http.ResponseWriter, r *http.Request, status int, res queries.SessionResult, v view) {
	info, err := h.d.MFA.BeginSetup(r.Context(), commands.BeginSetup{
		SessionID: res.Session.ID, UserID: res.User.ID, Account: res.User.Email,
	})
	if errors.Is(err, commands.ErrTOTPEnabled) {
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
		return
	}
	if errors.Is(err, commands.ErrMFAUnavailable) {
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
		return
	}
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	v.Secret, v.URI = info.Secret, info.URI
	// The QR code is a PNG in a data URI. The value is not from a user.
	v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(info.QRPNG)) //nolint:gosec // G203: the PNG comes from the service.
	w.Header().Set("Content-Security-Policy", contentSecurityPolicyWithImages)
	h.render(w, r, status, "account_totp", v)
}

func (h *Handler) totpSetup(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	res, ok := h.accountSession(w, r, "/account/totp", true, false)
	if !ok {
		return
	}
	out, err := h.d.MFA.FinishSetup(r.Context(), commands.FinishSetup{
		SessionID: res.Session.ID, UserID: res.User.ID, Code: r.PostForm.Get("code"),
	})
	ar, rt := setupNext(r.PostForm.Get("authRequest"), r.PostForm.Get("return_to"))
	v := view{Title: "Set up TOTP", AuthRequest: ar, ReturnTo: rt}
	switch {
	case err == nil:
		next := ""
		if ar != "" || rt != "" {
			next = afterLogin(ar, rt)
		}
		h.render(w, r, http.StatusOK, "account_codes", view{Title: "Recovery codes", Codes: out.RecoveryCodes, Done: true, Next: next})
	case errors.Is(err, commands.ErrMFABadCode):
		v.Error = "The code is not correct."
		h.renderSetup(w, r, http.StatusBadRequest, res, v)
	case errors.Is(err, commands.ErrSetupExpired):
		http.Redirect(w, r, setupPath(ar, rt), http.StatusSeeOther) //nolint:gosec // G710: a fixed path with escaped query values.
	case errors.Is(err, commands.ErrTOTPEnabled):
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	case errors.Is(err, commands.ErrTooManyAttempts):
		v.Error = "Too many attempts. Try again later."
		h.renderSetup(w, r, http.StatusTooManyRequests, res, v)
	case errors.Is(err, commands.ErrMFAUnavailable):
		h.message(w, r, http.StatusServiceUnavailable, "Service not available", "The service is not available. Try again later.")
	default:
		h.serverError(w, r, err)
	}
}

func (h *Handler) totpRemove(w http.ResponseWriter, r *http.Request) {
	res, ok := h.accountSession(w, r, "/account/security", true, true)
	if !ok {
		return
	}
	err := h.d.MFA.RemoveTOTP(r.Context(), commands.RemoveTOTP{UserID: res.User.ID, Actor: res.User.ID})
	switch {
	case err == nil:
		http.Redirect(w, r, "/account/security", http.StatusSeeOther)
	case errors.Is(err, commands.ErrTOTPNotFound):
		h.message(w, r, http.StatusNotFound, "TOTP is not on", "Your account has no TOTP factor.")
	case errors.Is(err, commands.ErrMFARequired):
		h.message(w, r, http.StatusConflict, "MFA is required", "Your account must have MFA. You cannot remove TOTP.")
	default:
		h.serverError(w, r, err)
	}
}

func (h *Handler) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	res, ok := h.accountSession(w, r, "/account/security", true, true)
	if !ok {
		return
	}
	codes, err := h.d.MFA.RegenerateRecoveryCodes(r.Context(), res.User.ID)
	switch {
	case err == nil:
		h.render(w, r, http.StatusOK, "account_codes", view{Title: "Recovery codes", Codes: codes})
	case errors.Is(err, commands.ErrTOTPNotFound):
		h.message(w, r, http.StatusNotFound, "TOTP is not on", "Your account has no TOTP factor.")
	default:
		h.serverError(w, r, err)
	}
}

// setupTarget returns the TOTP setup page when the policy needs MFA for the
// user and the user has no second factor. Else it returns the default.
func (h *Handler) setupTarget(r *http.Request, userID, fallback string) string {
	if h.d.MFA == nil || userID == "" {
		return fallback
	}
	st, err := h.d.MFA.Status(r.Context(), userID)
	if err != nil {
		h.log.WarnContext(r.Context(), "read the MFA status", "error", err)
		return fallback
	}
	if st.Required && !st.State.Enabled() {
		return setupBase
	}
	return fallback
}
