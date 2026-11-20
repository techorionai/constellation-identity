// Package gen holds the server code that oapi-codegen makes from the
// Constellation identity contract.
package gen

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../../../api/openapi/Constellation.Identity.openapi.yaml
