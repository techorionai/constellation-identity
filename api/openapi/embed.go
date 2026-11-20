// Package openapi holds the copies of the files of constellation-contracts
// that the service reads at run time: the OpenAPI file, for the
// x-required-scopes values of the operations, and the permission manifest of
// the identity service.
package openapi

import "embed"

// Spec is the OpenAPI file of constellation-contracts.
//
//go:embed Constellation.Identity.openapi.yaml
var Spec []byte

// Files holds the permission manifest of the identity service as
// identity-manifest.json.
//
//go:embed identity-manifest.json
var Files embed.FS

// IdentityManifestPath is the path of the manifest in Files.
const IdentityManifestPath = "identity-manifest.json"
