package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"

	"github.com/techorionai/constellation-identity/internal/domain"
)

// The error codes of the token endpoint (RFC 6749 section 5.2 and RFC 8707).
const (
	OAuthInvalidRequest         = "invalid_request"
	OAuthInvalidClient          = "invalid_client"
	OAuthUnauthorizedClient     = "unauthorized_client"
	OAuthUnsupportedGrantType   = "unsupported_grant_type"
	OAuthInvalidScope           = "invalid_scope"
	OAuthInvalidTarget          = "invalid_target"
	OAuthServerError            = "server_error"
	OAuthTemporarilyUnavailable = "temporarily_unavailable"
)

// OAuthError is an error of the token endpoint. The description is safe to
// show to a client. The cause is for the logs only.
type OAuthError struct {
	Code        string
	Description string
	cause       error
}

// NewOAuthError makes an OAuthError.
func NewOAuthError(code, description string, cause error) *OAuthError {
	return &OAuthError{Code: code, Description: description, cause: cause}
}

// Error returns the code, the description, and the cause.
func (e *OAuthError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Description, e.cause)
	}
	return e.Code + ": " + e.Description
}

// Unwrap returns the cause.
func (e *OAuthError) Unwrap() error { return e.cause }

// Status returns the HTTP status of the error. It is 400, except for
// invalid_client (401), server_error (500), and temporarily_unavailable (503).
func (e *OAuthError) Status() int {
	switch e.Code {
	case OAuthInvalidClient:
		return http.StatusUnauthorized
	case OAuthServerError:
		return http.StatusInternalServerError
	case OAuthTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// ValidationError means a request is well formed, but its content has
// problems. Code is the code of the first problem.
type ValidationError struct {
	Code   string
	Fields []domain.FieldError
}

// NewValidationError makes a ValidationError from the problems. The code is
// the code of the first problem.
func NewValidationError(fields []domain.FieldError) *ValidationError {
	e := &ValidationError{Fields: fields}
	if len(fields) > 0 {
		e.Code = fields[0].Code
	}
	return e
}

// Error returns the code and the number of problems.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed: %s (%d problems)", e.Code, len(e.Fields))
}

// AsOAuthError returns the OAuthError in the chain.
func AsOAuthError(err error) (*OAuthError, bool) {
	var oe *OAuthError
	if stderrors.As(err, &oe) {
		return oe, true
	}
	return nil, false
}

// AsValidationError returns the ValidationError in the chain.
func AsValidationError(err error) (*ValidationError, bool) {
	var ve *ValidationError
	if stderrors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
