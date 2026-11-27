package commands_test

import (
	"context"

	"github.com/techorionai/constellation-platform-go/auth"
)

// asUser returns a context with the user as the authenticated principal. The
// mock audit writer records its ID as the actor.
func asUser(id string) context.Context {
	return auth.ContextWithPrincipal(context.Background(), auth.Principal{ID: id, Type: auth.PrincipalUser})
}
