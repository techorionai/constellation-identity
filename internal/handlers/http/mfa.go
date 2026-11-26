package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/techorionai/constellation-platform-go/auth"

	"github.com/techorionai/constellation-identity/internal/app/commands"
	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

// mfaMaxAge is the longest age of the auth_time of a token that changes the MFA
// settings of a user.
const mfaMaxAge = 5 * time.Minute

// errReauthRequired makes the 401 refusal of the step-up (RFC 9470).
var errReauthRequired = errors.New("reauthentication required")

// writeReauthRequired writes the 401 refusal: the header WWW-Authenticate with
// the challenge of platform-go, and a problem body with the code
// reauthentication_required. The body is the body of all other problems.
func (s *Server) writeReauthRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", auth.MFAChallenge(mfaMaxAge))
	s.writeProblem(w, r, http.StatusUnauthorized, "reauthentication_required", "Reauthentication required", "A fresh MFA login is necessary.")
}

// checkMFA runs the check of the step-up after the scope check and the check
// user_token_required. It uses the clock of the service.
func (s *Server) checkMFA(ctx context.Context) error {
	p, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return errReauthRequired
	}
	if err := auth.CheckMFA(p, mfaMaxAge, s.now()); err != nil {
		return errReauthRequired
	}
	return nil
}

func (s *Server) now() time.Time {
	if s.d.Now != nil {
		return s.d.Now()
	}
	return time.Now()
}

func userNotFound() error {
	return apperrors.NewProblem(http.StatusNotFound, "user_not_found", "The user does not exist.")
}

func genMfaStatus(st commands.MFAStatus) gen.MfaStatus {
	out := gen.MfaStatus{
		Enabled:                st.State.Enabled(),
		Required:               st.Required,
		RecoveryCodesRemaining: int32(st.State.CodesRemaining), //nolint:gosec // The count is 0 to 10.
	}
	if st.State.HasTOTP {
		out.Totp = &gen.TotpStatus{CreatedAt: st.State.TOTPAt.UTC(), LastUsedAt: st.State.LastUsedAt}
	}
	return out
}

// MeMfaGet returns the MFA state of the user of the token.
func (s *Server) MeMfaGet(ctx context.Context, _ gen.MeMfaGetRequestObject) (gen.MeMfaGetResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	st, err := s.d.MFA.Status(ctx, p.ID)
	if errors.Is(err, commands.ErrUserNotFound) {
		return nil, userNotFound()
	}
	if err != nil {
		return nil, err
	}
	return gen.MeMfaGet200JSONResponse(genMfaStatus(st)), nil
}

// MeTotpRemove removes the TOTP factor and the recovery codes of the user of
// the token. The order of the checks is the order of the contract.
func (s *Server) MeTotpRemove(ctx context.Context, _ gen.MeTotpRemoveRequestObject) (gen.MeTotpRemoveResponseObject, error) {
	p, err := userPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.checkMFA(ctx); err != nil {
		return nil, err
	}
	err = s.d.MFA.RemoveTOTP(ctx, commands.RemoveTOTP{UserID: p.ID, Actor: p.ID})
	switch {
	case errors.Is(err, commands.ErrTOTPNotFound):
		return nil, apperrors.NewProblem(http.StatusNotFound, "totp_not_found", "The user has no TOTP factor.")
	case errors.Is(err, commands.ErrMFARequired):
		return nil, apperrors.NewConflictCode("mfa_required", "The policy requires MFA for the user. TOTP is the last second factor.")
	case err != nil:
		return nil, err
	}
	return gen.MeTotpRemove204Response{}, nil
}

// UserMfaGet returns the MFA state of any user.
func (s *Server) UserMfaGet(ctx context.Context, r gen.UserMfaGetRequestObject) (gen.UserMfaGetResponseObject, error) {
	st, err := s.d.MFA.Status(ctx, r.UserId)
	if errors.Is(err, commands.ErrUserNotFound) {
		return nil, userNotFound()
	}
	if err != nil {
		return nil, err
	}
	return gen.UserMfaGet200JSONResponse(genMfaStatus(st)), nil
}

// UserMfaReset removes the second factors of any user and revokes the sessions
// of the user. The token needs a fresh MFA login. The order of the checks is
// the order of the contract.
func (s *Server) UserMfaReset(ctx context.Context, r gen.UserMfaResetRequestObject) (gen.UserMfaResetResponseObject, error) {
	if err := s.checkMFA(ctx); err != nil {
		return nil, err
	}
	err := s.d.MFA.ResetMFA(ctx, commands.ResetMFA{UserID: r.UserId, Actor: actorID(ctx)})
	switch {
	case errors.Is(err, commands.ErrUserNotFound):
		return nil, userNotFound()
	case errors.Is(err, commands.ErrMFARequired):
		return nil, apperrors.NewConflictCode("mfa_required", "An administrator cannot reset the own MFA with this operation. Use the subcommand reset-mfa.")
	case err != nil:
		return nil, err
	}
	return gen.UserMfaReset204Response{}, nil
}
