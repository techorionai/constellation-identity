package errors

import (
	stderrors "errors"
	"net/http"
	"time"
)

// ProblemError is an error that a handler shows as a Problem with a status and
// a code of the contract, for example 409 last_admin.
type ProblemError struct {
	Status int
	Code   string
	Detail string
	// RetryAfter is the wait time for the header Retry-After. It is 0 if the
	// error has no header.
	RetryAfter time.Duration
}

// Error returns the code and the detail.
func (e *ProblemError) Error() string { return e.Code + ": " + e.Detail }

// NewProblem makes a ProblemError.
func NewProblem(status int, code, detail string) *ProblemError {
	return &ProblemError{Status: status, Code: code, Detail: detail}
}

// NewConflictCode makes a 409 ProblemError with the code.
func NewConflictCode(code, detail string) *ProblemError {
	return NewProblem(http.StatusConflict, code, detail)
}

// NewUnprocessable makes a 422 ProblemError with the code.
func NewUnprocessable(code, detail string) *ProblemError {
	return NewProblem(http.StatusUnprocessableEntity, code, detail)
}

// AsProblem returns the ProblemError in the chain.
func AsProblem(err error) (*ProblemError, bool) {
	var pe *ProblemError
	if stderrors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
