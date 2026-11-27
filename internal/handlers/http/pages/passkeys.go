package pages

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// WebAuthnCookieName is the name of the cookie that binds a login ceremony with
// no password to the browser. It has the rules of the other cookies, with the
// attribute SameSite=Strict, because the ceremony is a same-origin call.
const WebAuthnCookieName = "__Host-constellation_webauthn"

// maxJSONBytes is the largest body of a JSON route of the passkeys.
const maxJSONBytes = 64 << 10

// passkeyPath is the page of the passkeys of the user.
const passkeyPath = "/account/passkeys"

// Texts that the pages and the script show.
const (
	invalidNameText  = "The name must have 1 to 64 characters, with no space at the start or the end, and no control characters"
	passkeyLimitText = "You have the maximum number of passkeys"
	passkeyBadText   = "The passkey is not valid"
)

// passkeysOn reports whether the hosted passkey routes are on.
func (h *Handler) passkeysOn() bool { return h.d.PasskeysOn && h.d.MFA != nil }

// writeJSON writes a JSON body.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonError writes the error body of a JSON route.
func (h *Handler) jsonError(w http.ResponseWriter, status int, code string) {
	h.writeJSON(w, status, map[string]string{"error": code})
}

// jsonLogin tells the script to go to the login page. The login comes back to
// the passkey page.
func (h *Handler) jsonLogin(w http.ResponseWriter, returnTo string) {
	h.writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "login_required", "redirect": "/login?return_to=" + url.QueryEscape(returnTo) + "&prompt=login",
	})
}

// jsonBody reads the body of a JSON route. It needs the content type
// application/json and at most 64 KiB. It returns false after it wrote the
// error. With wantJSON true it also checks the content type.
func (h *Handler) jsonBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		h.jsonError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.jsonError(w, http.StatusRequestEntityTooLarge, "body_too_large")
			return nil, false
		}
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return body, true
}

// passkeyRoute is the start of each JSON route and form route of the passkeys.
// It returns false after it wrote the 404 response, when passkeys are off.
func (h *Handler) passkeyRoute(w http.ResponseWriter, r *http.Request, jsonRoute bool) bool {
	if h.passkeysOn() {
		return true
	}
	if jsonRoute {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return false
	}
	h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
	return false
}

// jsonSession returns the fresh session of a JSON route. A session that is not
// fresh gets the answer "login_required".
func (h *Handler) jsonSession(w http.ResponseWriter, r *http.Request) (queries.SessionResult, bool) {
	return h.jsonSessionAt(w, r, passkeyPath)
}

// jsonSessionAt is jsonSession with the page that the login comes back to.
func (h *Handler) jsonSessionAt(w http.ResponseWriter, r *http.Request, returnTo string) (queries.SessionResult, bool) {
	res, err := h.d.Session.Execute(r.Context(), queries.SessionFromCookie{Token: cookieValue(r)})
	if errors.Is(err, queries.ErrNoSession) {
		h.jsonLogin(w, returnTo)
		return queries.SessionResult{}, false
	}
	if err != nil {
		h.log.ErrorContext(r.Context(), "a page failed", "path", r.URL.Path, "error", err)
		h.jsonError(w, http.StatusInternalServerError, "server_error")
		return queries.SessionResult{}, false
	}
	if !domain.FreshLogin(res.Session.AuthTime, h.now().UTC()) {
		h.jsonLogin(w, returnTo)
		return queries.SessionResult{}, false
	}
	return res, true
}

// ceremonyError writes the error of a ceremony step as JSON. It returns false
// for an error that it does not know.
func (h *Handler) ceremonyError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, commands.ErrPasskeysOff):
		h.jsonError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, domain.ErrInvalidPasskeyName):
		h.jsonError(w, http.StatusBadRequest, "invalid_name")
	case errors.Is(err, commands.ErrPasskeyLimit):
		h.jsonError(w, http.StatusConflict, "passkey_limit")
	case errors.Is(err, commands.ErrCeremonyGone):
		h.jsonError(w, http.StatusBadRequest, "expired")
	case errors.Is(err, commands.ErrPasskeyInvalid):
		h.jsonError(w, http.StatusUnauthorized, "invalid_passkey")
	case errors.Is(err, commands.ErrTooManyAttempts):
		w.Header().Set("Retry-After", "60")
		h.jsonError(w, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, commands.ErrMFAUnavailable):
		h.jsonError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		return false
	}
	return true
}

func (h *Handler) ceremonyFailed(w http.ResponseWriter, r *http.Request, err error) {
	if h.ceremonyError(w, err) {
		return
	}
	h.log.ErrorContext(r.Context(), "a passkey route failed", "path", r.URL.Path, "error", err)
	h.jsonError(w, http.StatusInternalServerError, "server_error")
}

func (h *Handler) writeOptions(w http.ResponseWriter, options []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(options) //nolint:gosec // G705: The body is JSON from the WebAuthn adapter with the type application/json.
}

// --- script ---

// passkeyScript serves the one script of the service.
func (h *Handler) passkeyScript(w http.ResponseWriter, r *http.Request) {
	if !h.passkeysOn() {
		h.message(w, r, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(h.js)
}

// --- the page of the passkeys ---

// passkeyRow is one row of the page of the passkeys.
type passkeyRow struct {
	ID        string
	Name      string
	CreatedAt string
	LastUsed  string
	Synced    bool
}

const timeText = "2006-01-02 15:04 UTC"

func (h *Handler) passkeyRows(r *http.Request, userID string) ([]passkeyRow, error) {
	var rows []passkeyRow
	token := ""
	for {
		page, err := h.d.MFA.ListPasskeys(r.Context(), userID, commands.ListPage{Token: token}, false)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Items {
			row := passkeyRow{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt.UTC().Format(timeText), Synced: p.BackupState}
			if p.LastUsedAt != nil {
				row.LastUsed = p.LastUsedAt.UTC().Format(timeText)
			}
			rows = append(rows, row)
		}
		if page.Next == "" {
			return rows, nil
		}
		token = page.Next
	}
}

func (h *Handler) passkeysForm(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, false) {
		return
	}
	res, ok := h.accountSession(w, r, passkeyPath, true, false)
	if !ok {
		return
	}
	ar, rt := setupNext(r.URL.Query().Get("authRequest"), r.URL.Query().Get("return_to"))
	h.renderPasskeys(w, r, http.StatusOK, res, view{
		Title: "Passkeys", Required: r.URL.Query().Get("required") == "1", AuthRequest: ar, ReturnTo: rt,
	})
}

func (h *Handler) renderPasskeys(w http.ResponseWriter, r *http.Request, status int, res queries.SessionResult, v view) {
	rows, err := h.passkeyRows(r, res.User.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	v.Passkeys, v.PasskeyOn, v.Script = rows, true, true
	w.Header().Set("Content-Security-Policy", ContentSecurityPolicyWithScript(""))
	h.render(w, r, status, "account_passkeys", v)
}

// passkeyOptionsRequest is the body of the options step of a registration.
type passkeyOptionsRequest struct {
	Name        string `json:"name"`
	AuthRequest string `json:"authRequest"`
	ReturnTo    string `json:"return_to"`
}

func (h *Handler) passkeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	var req passkeyOptionsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	res, ok := h.jsonSession(w, r)
	if !ok {
		return
	}
	ar, rt := setupNext(req.AuthRequest, req.ReturnTo)
	options, err := h.d.MFA.BeginPasskeyRegistration(r.Context(), commands.BeginPasskey{
		SessionID: res.Session.ID, UserID: res.User.ID, Name: req.Name, AuthRequest: ar, ReturnTo: rt,
	})
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.writeOptions(w, options)
}

func (h *Handler) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	res, ok := h.jsonSession(w, r)
	if !ok {
		return
	}
	added, err := h.d.MFA.FinishPasskeyRegistration(sessionContext(r, res.User.ID), commands.FinishPasskey{
		SessionID: res.Session.ID, UserID: res.User.ID, SessionMethods: res.Session.AuthMethods, Body: body,
	})
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	target := passkeyPath
	if added.AuthRequest != "" || added.ReturnTo != "" {
		target = afterLogin(added.AuthRequest, added.ReturnTo)
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"redirect": target})
}

// passkeyRename renames a passkey. The form has no script. The session needs a
// fresh MFA login, as the removal of TOTP.
func (h *Handler) passkeyRename(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, false) {
		return
	}
	if !h.parseForm(w, r) {
		return
	}
	res, ok := h.accountSession(w, r, passkeyPath, true, true)
	if !ok {
		return
	}
	_, err := h.d.MFA.RenamePasskey(sessionContext(r, res.User.ID), commands.RenamePasskey{
		UserID: res.User.ID, PasskeyID: r.PathValue("id"), Name: r.PostForm.Get("name"), Actor: res.User.ID,
	})
	switch {
	case err == nil:
		http.Redirect(w, r, passkeyPath, http.StatusSeeOther)
	case errors.Is(err, commands.ErrPasskeyNotFound):
		h.message(w, r, http.StatusNotFound, "Passkey not found", "The passkey does not exist.")
	case errors.Is(err, domain.ErrInvalidPasskeyName):
		h.renderPasskeys(w, r, http.StatusBadRequest, res, view{Title: "Passkeys", Error: invalidNameText})
	default:
		h.serverError(w, r, err)
	}
}

// passkeyRemove removes a passkey. The form has no script. The session needs a
// fresh MFA login. The sessions with a passkey end, so the page goes to the login.
func (h *Handler) passkeyRemove(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, false) {
		return
	}
	res, ok := h.accountSession(w, r, passkeyPath, true, true)
	if !ok {
		return
	}
	err := h.d.MFA.RemovePasskey(sessionContext(r, res.User.ID), commands.RemovePasskey{
		UserID: res.User.ID, PasskeyID: r.PathValue("id"), Actor: res.User.ID,
	})
	switch {
	case err == nil:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.Is(err, commands.ErrPasskeyNotFound):
		h.message(w, r, http.StatusNotFound, "Passkey not found", "The passkey does not exist.")
	case errors.Is(err, commands.ErrMFARequired):
		h.message(w, r, http.StatusConflict, "MFA is required", "Your account must have MFA. You cannot remove the last second factor.")
	default:
		h.serverError(w, r, err)
	}
}

// --- login with no password ---

func (h *Handler) setWebAuthnCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: WebAuthnCookieName, Value: token, Path: "/", MaxAge: int(commands.CeremonyTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearWebAuthnCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: WebAuthnCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func webAuthnCookieValue(r *http.Request) string {
	c, err := r.Cookie(WebAuthnCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (h *Handler) passkeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	var req passkeyOptionsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// The values are checked as POST /login checks them.
	ar, rt := setupNext(req.AuthRequest, req.ReturnTo)
	out, err := h.d.MFA.BeginPasskeyLogin(r.Context(), commands.BeginPasskeyLogin{AuthRequest: ar, ReturnTo: rt})
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.setWebAuthnCookie(w, out.Token)
	h.writeOptions(w, out.JSON)
}

func (h *Handler) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	verified, err := h.d.MFA.FinishPasskeyLogin(r.Context(), commands.PasskeyLogin{
		Token: webAuthnCookieValue(r), Body: body, IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	// The challenge is single use, so the cookie goes away with each answer.
	clearWebAuthnCookie(w)
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.setCookie(w, verified.Session)
	h.writeJSON(w, http.StatusOK, map[string]string{"redirect": afterLogin(verified.AuthRequest, verified.ReturnTo)})
}

// --- second factor ---

func (h *Handler) mfaPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	if _, ok := h.jsonBody(w, r); !ok {
		return
	}
	options, err := h.d.MFA.BeginPasskeySecondFactor(r.Context(), mfaCookieValue(r))
	if errors.Is(err, commands.ErrMFAPendingGone) {
		clearMFACookie(w)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "redirect": "/login"})
		return
	}
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.writeOptions(w, options)
}

func (h *Handler) mfaPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	verified, err := h.d.MFA.FinishPasskeySecondFactor(r.Context(), commands.PasskeySecondFactor{
		PendingToken: mfaCookieValue(r), Body: body, IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	if errors.Is(err, commands.ErrMFAPendingGone) {
		clearMFACookie(w)
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "redirect": "/login"})
		return
	}
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.setCookie(w, verified.Session)
	clearMFACookie(w)
	h.writeJSON(w, http.StatusOK, map[string]string{"redirect": afterLogin(verified.AuthRequest, verified.ReturnTo)})
}

// --- rate limit bodies ---

// jsonRoutes are the paths with a JSON answer. The rate limit answers with JSON
// on these paths.
var jsonRoutes = map[string]bool{
	"/login/passkey/options": true, "/login/passkey/finish": true,
	"/login/mfa/passkey/options": true, "/login/mfa/passkey/finish": true,
	"/account/passkeys/options": true, "/account/passkeys/finish": true,
	// The passkey check before a link and before a link removal (P23).
	"/account/identity-links/passkey/options": true, "/account/identity-links/passkey/link": true,
	"/account/identity-links/passkey/remove": true,
}

// jsonRateLimited writes the 429 answer of a JSON route.
func (h *Handler) jsonRateLimited(w http.ResponseWriter, re *apperrors.RateLimitedError) {
	w.Header().Set("Retry-After", strconv.Itoa(max(apperrors.RetryAfterSeconds(re.RetryAfter), 1)))
	h.jsonError(w, http.StatusTooManyRequests, "rate_limited")
}
