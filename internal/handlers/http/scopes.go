package httpapi

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// publicScopeOperation is the only /v1 operation with an empty scope list. A
// caller needs a valid token, but no scope.
const publicScopeOperation = "Me_get"

// ScopeTable gives the scopes that a /v1 operation needs. The key is the
// route pattern of the router, for example "GET /v1/roles". The token must
// have all scopes of the list.
type ScopeTable map[string][]string

var specMethods = map[string]bool{"get": true, "put": true, "post": true, "patch": true, "delete": true}

// NewScopeTable reads the x-required-scopes value of each /v1 operation of the
// OpenAPI file. It fails closed: an operation with no x-required-scopes, or
// with an empty list that is not for Me_get, is an error that names the
// operation.
func NewScopeTable(spec []byte) (ScopeTable, error) {
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("scope table: read the OpenAPI file: %w", err)
	}
	table := ScopeTable{}
	var errs []error
	paths := make([]string, 0, len(doc.Paths))
	for path := range doc.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		for method, raw := range doc.Paths[path] {
			if !specMethods[method] {
				continue
			}
			op, _ := raw.(map[string]any)
			id, _ := op["operationId"].(string)
			if id == "" {
				id = strings.ToUpper(method) + " " + path
			}
			list, present := op["x-required-scopes"]
			items, isList := list.([]any)
			switch {
			case !present || !isList:
				errs = append(errs, fmt.Errorf("scope table: operation %s has no x-required-scopes", id))
				continue
			case len(items) == 0 && id != publicScopeOperation:
				errs = append(errs, fmt.Errorf("scope table: operation %s has an empty x-required-scopes", id))
				continue
			}
			scopes := make([]string, 0, len(items))
			for _, item := range items {
				s, ok := item.(string)
				if !ok || s == "" {
					errs = append(errs, fmt.Errorf("scope table: operation %s has a scope that is not a string", id))
					continue
				}
				scopes = append(scopes, s)
			}
			table[strings.ToUpper(method)+" "+path] = scopes
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return table, nil
}
