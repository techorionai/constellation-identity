// Package pages holds the HTML pages of the identity service: login, logout,
// first-admin setup, and invite accept. The pages are server-side HTML with no
// JavaScript. They are primary adapters and call internal/app only.
package pages

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/techorionai/constellation-platform-go/executor"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/app/queries"
	"github.com/techorionai/constellation-identity/internal/domain"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets/pages.css
var assetFS embed.FS

// CookieName is the name of the session cookie. The prefix __Host- makes the
// browser accept the cookie only with Secure, Path=/, and no Domain.
const CookieName = "__Host-constellation_session"

// maxFormBytes is the largest request body of a page.
const maxFormBytes = 64 << 10

// Paths are the URL patterns that the handler of the pages serves. Register
// them on the router of the public server.
var Paths = []string{"/login", "/login/done", "/logout", "/setup", "/invite", "/assets/pages.css"}

// Deps are the use cases and the settings of the pages.
type Deps struct {
	Setup      executor.ExecutorWithReturn[commands.CompleteSetup, commands.IssuedSession]
	Invite     executor.ExecutorWithReturn[commands.AcceptInvite, commands.IssuedSession]
	Login      executor.ExecutorWithReturn[commands.Login, commands.IssuedSession]
	Logout     executor.Executor[commands.Logout]
	Session    executor.ExecutorWithReturn[queries.SessionFromCookie, queries.SessionResult]
	Touch      executor.Executor[commands.TouchSession]
	CheckToken executor.ExecutorWithReturn[queries.CheckOneTimeToken, bool]
	// TrustedProxies are the ranges whose X-Forwarded-For header the pages use.
	TrustedProxies []netip.Prefix
	Log            *slog.Logger
	// Now is the clock for the cookie. The default is time.Now.
	Now func() time.Time
}

// Handler serves the pages.
type Handler struct {
	d    Deps
	log  *slog.Logger
	tmpl *template.Template
	css  []byte
	now  func() time.Time
}

// New makes the handler.
func New(d Deps) (*Handler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	css, err := fs.ReadFile(assetFS, "assets/pages.css")
	if err != nil {
		return nil, err
	}
	h := &Handler{d: d, log: d.Log, tmpl: tmpl, css: css, now: d.Now}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

// Routes returns the router of the pages. A POST page is behind the cross
// origin check of the standard library. All pages get the security headers.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.loginForm)
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("GET /login/done", h.loginDone)
	mux.HandleFunc("POST /logout", h.logout)
	mux.HandleFunc("GET /setup", h.setupForm)
	mux.HandleFunc("POST /setup", h.setup)
	mux.HandleFunc("GET /invite", h.inviteForm)
	mux.HandleFunc("POST /invite", h.invite)
	mux.HandleFunc("GET /assets/pages.css", h.stylesheet)
	return SecurityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

// view is the data of a template.
type view struct {
	Title    string
	Error    string
	Token    string
	Email    string
	Name     string
	ReturnTo string
	UserName string
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, name string, v view) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, v); err != nil {
		h.log.ErrorContext(r.Context(), "render a page", "page", name, "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) stylesheet(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(h.css)
}

// message renders a page with a title and an error text.
func (h *Handler) message(w http.ResponseWriter, r *http.Request, status int, title, text string) {
	h.render(w, r, status, "message", view{Title: title, Error: text})
}

func (h *Handler) invalidLink(w http.ResponseWriter, r *http.Request) {
	h.message(w, r, http.StatusBadRequest, "Link not valid", "This link is not valid or it has expired.")
}

func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.log.ErrorContext(r.Context(), "a page failed", "path", r.URL.Path, "error", err)
	h.message(w, r, http.StatusInternalServerError, "Error", "Something went wrong. Try again later.")
}

// parseForm reads the form of a POST request. It returns false after it wrote
// the error page.
func (h *Handler) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.message(w, r, http.StatusBadRequest, "Request not valid", "The request is not valid.")
		return false
	}
	return true
}

func (h *Handler) clientIP(r *http.Request) string {
	return ClientIP(r.RemoteAddr, r.Header.Values("X-Forwarded-For"), h.d.TrustedProxies)
}

// setCookie sets the session cookie.
func (h *Handler) setCookie(w http.ResponseWriter, s commands.IssuedSession) {
	maxAge := int(s.ExpiresAt.Sub(h.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: s.Token, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func cookieValue(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// formError maps the error of a password or account form to a text and a
// status. ok is false for an error that the form does not show.
func formError(err error) (text string, status int, ok bool) {
	switch {
	case errors.Is(err, domain.ErrPasswordTooShort), errors.Is(err, domain.ErrPasswordTooLong):
		return "The password must have 12 to 128 characters.", http.StatusBadRequest, true
	case errors.Is(err, domain.ErrInvalidEmail):
		return "Enter a valid email address.", http.StatusBadRequest, true
	case errors.Is(err, domain.ErrInvalidName):
		return "Enter a name of 1 to 200 characters.", http.StatusBadRequest, true
	case errors.Is(err, commands.ErrEmailTaken):
		return "This email is in use", http.StatusConflict, true
	case errors.Is(err, commands.ErrBusy):
		return "The service is busy. Try again.", http.StatusServiceUnavailable, true
	}
	return "", 0, false
}

const mismatchText = "The passwords are not the same."

// --- login ---

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	rt, _ := domain.SafeReturnTo(r.URL.Query().Get("return_to"))
	h.render(w, r, http.StatusOK, "login", view{Title: "Log in", ReturnTo: rt})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	rt, _ := domain.SafeReturnTo(r.PostForm.Get("return_to"))
	email := r.PostForm.Get("email")
	issued, err := h.d.Login.Execute(r.Context(), commands.Login{
		Email: email, Password: r.PostForm.Get("password"),
		IP: h.clientIP(r), UserAgent: r.UserAgent(), PreviousToken: cookieValue(r),
	})
	v := view{Title: "Log in", Email: email, ReturnTo: rt}
	switch {
	case err == nil:
		h.setCookie(w, issued)
		target := "/login/done"
		if rt != "" {
			target = rt
		}
		// target is /login/done or a path that domain.SafeReturnTo accepted.
		http.Redirect(w, r, target, http.StatusSeeOther) //nolint:gosec // G710: see the line above.
	case errors.Is(err, commands.ErrBadCredentials):
		v.Error = "Email or password is not correct"
		h.render(w, r, http.StatusUnauthorized, "login", v)
	case errors.Is(err, commands.ErrTooManyAttempts):
		v.Error = "Too many attempts. Try again later."
		h.render(w, r, http.StatusTooManyRequests, "login", v)
	case errors.Is(err, commands.ErrBusy):
		v.Error = "The service is busy. Try again."
		h.render(w, r, http.StatusServiceUnavailable, "login", v)
	case errors.Is(err, commands.ErrLimiterUnavailable):
		v.Error = "The service is not available. Try again later."
		h.render(w, r, http.StatusServiceUnavailable, "login", v)
	default:
		h.serverError(w, r, err)
	}
}

func (h *Handler) loginDone(w http.ResponseWriter, r *http.Request) {
	res, err := h.d.Session.Execute(r.Context(), queries.SessionFromCookie{Token: cookieValue(r)})
	if errors.Is(err, queries.ErrNoSession) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if err := h.d.Touch.Execute(r.Context(), commands.TouchSession{Session: res.Session}); err != nil {
		h.log.WarnContext(r.Context(), "touch the session", "error", err)
	}
	h.render(w, r, http.StatusOK, "done", view{Title: "Logged in", UserName: res.User.Name})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token := cookieValue(r)
	if err := h.d.Logout.Execute(r.Context(), commands.Logout{Token: token}); err != nil {
		h.serverError(w, r, err)
		return
	}
	clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- setup ---

func (h *Handler) setupForm(w http.ResponseWriter, r *http.Request) {
	h.tokenForm(w, r, domain.PurposeSetup, "setup", "First-admin setup")
}

func (h *Handler) inviteForm(w http.ResponseWriter, r *http.Request) {
	h.tokenForm(w, r, domain.PurposeInvite, "invite", "Accept your invite")
}

// tokenForm shows the form if the token can be used, and the error page if not.
func (h *Handler) tokenForm(w http.ResponseWriter, r *http.Request, purpose domain.TokenPurpose, page, title string) {
	token := TokenFromRequest(r)
	ok, err := h.d.CheckToken.Execute(r.Context(), queries.CheckOneTimeToken{Token: token, Purpose: purpose})
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if !ok {
		h.invalidLink(w, r)
		return
	}
	h.render(w, r, http.StatusOK, page, view{Title: title, Token: token})
}

func (h *Handler) setup(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	token := r.PostForm.Get("token")
	v := view{Title: "First-admin setup", Token: token, Email: r.PostForm.Get("email"), Name: r.PostForm.Get("name")}
	if r.PostForm.Get("password") != r.PostForm.Get("password2") {
		v.Error = mismatchText
		h.render(w, r, http.StatusBadRequest, "setup", v)
		return
	}
	issued, err := h.d.Setup.Execute(r.Context(), commands.CompleteSetup{
		Token: token, Email: v.Email, Name: v.Name, Password: r.PostForm.Get("password"),
		UserAgent: r.UserAgent(), IP: h.clientIP(r),
	})
	h.finishToken(w, r, "setup", v, issued, err)
}

func (h *Handler) invite(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	token := r.PostForm.Get("token")
	v := view{Title: "Accept your invite", Token: token}
	if r.PostForm.Get("password") != r.PostForm.Get("password2") {
		v.Error = mismatchText
		h.render(w, r, http.StatusBadRequest, "invite", v)
		return
	}
	issued, err := h.d.Invite.Execute(r.Context(), commands.AcceptInvite{
		Token: token, Password: r.PostForm.Get("password"), UserAgent: r.UserAgent(), IP: h.clientIP(r),
	})
	h.finishToken(w, r, "invite", v, issued, err)
}

// finishToken sets the cookie and redirects after a setup or an invite, or it
// shows the error.
func (h *Handler) finishToken(w http.ResponseWriter, r *http.Request, page string, v view, issued commands.IssuedSession, err error) {
	if err == nil {
		h.setCookie(w, issued)
		http.Redirect(w, r, "/login/done", http.StatusSeeOther)
		return
	}
	if errors.Is(err, commands.ErrTokenInvalid) {
		h.invalidLink(w, r)
		return
	}
	if text, status, ok := formError(err); ok {
		v.Error = text
		h.render(w, r, status, page, v)
		return
	}
	h.serverError(w, r, err)
}
