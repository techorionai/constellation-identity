// Package errors holds the application error type. A use case returns an
// AppError, and a handler maps the code to a transport status.
package errors

import (
	stderrors "errors"
	"fmt"
)

// ErrorCode is the kind of an application error.
type ErrorCode int

// The codes of an application error.
const (
	Internal ErrorCode = iota
	InvalidInput
	NotFound
	Conflict
	Unauthorized
	Forbidden
	Timeout
	Unavailable
)

// AppError is an error with a code. The message is safe to show to a client.
// The original error is for the logs only.
type AppError struct {
	original error
	code     ErrorCode
	message  string
}

// Error returns the message and the original error.
func (e *AppError) Error() string {
	if e.original != nil {
		return fmt.Sprintf("%s: %v", e.message, e.original)
	}
	return e.message
}

// Unwrap returns the original error.
func (e *AppError) Unwrap() error { return e.original }

// Code returns the code of the error.
func (e *AppError) Code() ErrorCode { return e.code }

// Message returns the message that is safe to show to a client.
func (e *AppError) Message() string { return e.message }

// NewNotFound makes a NotFound error.
func NewNotFound(msg string) error { return &AppError{code: NotFound, message: msg} }

// NewInvalidInput makes an InvalidInput error.
func NewInvalidInput(msg string) error { return &AppError{code: InvalidInput, message: msg} }

// NewConflict makes a Conflict error.
func NewConflict(msg string) error { return &AppError{code: Conflict, message: msg} }

// NewForbidden makes a Forbidden error.
func NewForbidden(msg string) error { return &AppError{code: Forbidden, message: msg} }

// WrapInternal wraps an unexpected error as an Internal error.
func WrapInternal(err error, msg string) error {
	return &AppError{original: err, code: Internal, message: msg}
}

// CodeOf returns the code of the first AppError in the chain. An error that
// is not an AppError has the code Internal.
func CodeOf(err error) ErrorCode {
	var ae *AppError
	if stderrors.As(err, &ae) {
		return ae.code
	}
	return Internal
}
