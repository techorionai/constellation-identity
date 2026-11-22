package httpapi

import (
	"context"

	"github.com/techorionai/constellation-identity/internal/handlers/http/gen"
)

// unimplemented gives the two operations that the pages router serves. The
// router of the public server sends GET /oauth/authorize and GET
// /oauth/end_session to the pages (package pages), because they need the raw
// query, the cookie, and HTML pages. These methods keep the generated
// interface complete. They answer 501 if a request ever reaches them.
type unimplemented struct{}

func (unimplemented) OAuthAuthorize(context.Context, gen.OAuthAuthorizeRequestObject) (gen.OAuthAuthorizeResponseObject, error) {
	return nil, errNotImplemented
}

func (unimplemented) OAuthEndSession(context.Context, gen.OAuthEndSessionRequestObject) (gen.OAuthEndSessionResponseObject, error) {
	return nil, errNotImplemented
}
