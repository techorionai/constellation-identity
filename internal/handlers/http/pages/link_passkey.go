package pages

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	"github.com/techorionai/constellation-identity/internal/domain"
)

// securityPath is the page that the passkey check of a link comes from.
const securityPath = "/account/security"

// linkPasskeyOptions makes the options of the passkey check that a link and a
// link removal need (P23). The session must be fresh. The state of the ceremony
// is bound to the session.
func (h *Handler) linkPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) || !h.idpEnabled() {
		return
	}
	if _, ok := h.jsonBody(w, r); !ok {
		return
	}
	options, err := h.d.Idp.BeginPasskeyConfirm(r.Context(), cookieValue(r))
	if errors.Is(err, commands.ErrIdpReauth) || errors.Is(err, commands.ErrUserNotFound) {
		h.jsonLogin(w, securityPath)
		return
	}
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	h.writeOptions(w, options)
}

// linkPasskeyFinish checks the passkey and returns the address of the start of
// the link flow, with the value of the check. The address is a local path.
func (h *Handler) linkPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) || !h.idpEnabled() {
		return
	}
	provider := r.URL.Query().Get("provider")
	if !domain.ValidProvider(provider) || !h.providerOn(provider) {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	confirm, err := h.d.Idp.ConfirmLink(r.Context(), commands.ConfirmLink{
		Provider: provider, SessionToken: cookieValue(r), PasskeyBody: body,
	})
	if errors.Is(err, commands.ErrIdpReauth) || errors.Is(err, commands.ErrUserNotFound) {
		h.jsonLogin(w, securityPath)
		return
	}
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	target := "/login/oidc/" + provider + "?purpose=" + domain.FlowLink
	if confirm != "" {
		target += "&confirm=" + url.QueryEscape(confirm)
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"redirect": target})
}

// linkRemovePasskey checks the passkey and removes the link. The answer has the
// address of the next page.
func (h *Handler) linkRemovePasskey(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyRoute(w, r, true) || h.d.IdentityLinks == nil {
		return
	}
	body, ok := h.jsonBody(w, r)
	if !ok {
		return
	}
	res, ok := h.jsonSessionAt(w, r, securityPath)
	if !ok {
		return
	}
	err := h.d.MFA.FinishPasskeyConfirm(r.Context(), commands.PasskeyConfirm{
		UserID: res.User.ID, SessionHash: res.Session.TokenHash, Body: body,
	})
	if err != nil {
		h.ceremonyFailed(w, r, err)
		return
	}
	err = h.d.IdentityLinks.Remove(r.Context(), commands.RemoveIdentityLink{
		UserID: res.User.ID, Provider: r.URL.Query().Get("provider"), Actor: res.User.ID, Self: true, FactorVerified: true,
	})
	switch {
	case err == nil:
		target := securityPath
		for _, m := range res.Session.AuthMethods {
			if m == domain.AMRFederated {
				clearCookie(w)
				target = "/login?removed=1"
				break
			}
		}
		h.writeJSON(w, http.StatusOK, map[string]string{"redirect": target})
	case errors.Is(err, commands.ErrIdentityLinkNotFound):
		h.jsonError(w, http.StatusNotFound, "link_not_found")
	case errors.Is(err, commands.ErrLastLoginMethod):
		h.jsonError(w, http.StatusConflict, "last_login_method")
	case errors.Is(err, commands.ErrUserNotFound):
		clearCookie(w)
		h.jsonLogin(w, securityPath)
	default:
		h.ceremonyFailed(w, r, err)
	}
}
