package queries

import (
	"encoding/base64"

	apperrors "github.com/techorionai/constellation-identity/internal/common/errors"
)

// The page sizes of the contract.
const (
	// DefaultPageSize is the size of a page when the request has no pageSize.
	DefaultPageSize = 50
	maxPageSize     = 200
	maxTokenLength  = 1024
)

// pageSize checks the size of a page. A value outside 1 to 200, also 0, is an
// invalid input. The caller applies DefaultPageSize when the request has no
// pageSize.
func pageSize(n int) (int, error) {
	switch {
	case n < 1 || n > maxPageSize:
		return 0, apperrors.NewInvalidInput("pageSize must be from 1 to 200")
	}
	return n, nil
}

func encodePageToken(cursor string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursor))
}

// decodePageToken returns the cursor of a page token. An empty token gives an
// empty cursor.
func decodePageToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if len(token) > maxTokenLength {
		return "", apperrors.NewInvalidInput("pageToken is not valid")
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", apperrors.NewInvalidInput("pageToken is not valid")
	}
	return string(b), nil
}
