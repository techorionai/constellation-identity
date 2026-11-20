// Package migrations holds the embedded SQL migrations of the service.
package migrations

import "embed"

// Files holds the migration files at its root.
//
//go:embed *.sql
var Files embed.FS
