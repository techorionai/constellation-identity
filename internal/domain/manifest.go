package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The codes of the manifest checks. They are the codes of the contract.
const (
	CodeManifestAppMismatch   = "manifest_app_mismatch"
	CodePermissionAppMismatch = "permission_app_mismatch"
	CodeRolePermissionUnknown = "role_permission_unknown"
	CodeDuplicateKey          = "duplicate_key"
	CodeInvalidKey            = "invalid_key"
)

// AdminPermission is the permission of full administration. It has two
// segments. Only the role admin holds it.
const AdminPermission = "identity:admin"

const (
	maxRoleKeyLen       = 64
	maxPermissionKeyLen = 128
)

var (
	permissionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`)
	roleKeyPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// ValidPermissionKey reports whether s is a permission key: three segments, or
// the key identity:admin.
func ValidPermissionKey(s string) bool {
	if len(s) > maxPermissionKeyLen {
		return false
	}
	return s == AdminPermission || permissionKeyPattern.MatchString(s)
}

// ValidRoleKey reports whether s is a role key.
func ValidRoleKey(s string) bool {
	return len(s) <= maxRoleKeyLen && roleKeyPattern.MatchString(s)
}

// PermissionDef is one permission that an app defines.
type PermissionDef struct {
	Key         string
	Description string
}

// RoleDef is a default role of an app.
type RoleDef struct {
	Key         string
	Name        string
	Description string
	Permissions []string
}

// Manifest holds the permissions and the default roles of one app.
type Manifest struct {
	App         string
	Permissions []PermissionDef
	Roles       []RoleDef
}

// PublishedManifest is a stored manifest.
type PublishedManifest struct {
	Manifest    Manifest
	Version     int
	Hash        string
	PublishedAt time.Time
	PublishedBy string
}

// FieldError is one incorrect field. Field is a JSON Pointer into the
// manifest as the API shows it.
type FieldError struct {
	Code    string
	Field   string
	Message string
}

// CheckManifestApp checks who may publish. The path app must not be identity.
// The caller app, the path app, and the manifest app must be equal.
func CheckManifestApp(pathApp, callerApp string, m Manifest) *FieldError {
	switch {
	case pathApp == IdentityApp:
		return &FieldError{Code: CodeManifestAppMismatch, Field: "/app", Message: "The app identity is reserved."}
	case m.App != pathApp:
		return &FieldError{Code: CodeManifestAppMismatch, Field: "/app", Message: "The app of the manifest is not the app of the path."}
	case callerApp != pathApp:
		return &FieldError{Code: CodeManifestAppMismatch, Field: "/app", Message: "The caller is not a service client of this app."}
	}
	return nil
}

// CheckManifest checks the keys of a manifest and returns all problems.
func CheckManifest(m Manifest) []FieldError {
	var errs []FieldError
	add := func(code, field, format string, args ...any) {
		errs = append(errs, FieldError{Code: code, Field: field, Message: fmt.Sprintf(format, args...)})
	}
	if !ValidAppKey(m.App) {
		add(CodeInvalidKey, "/app", "The app key is not valid.")
	}
	defined := make(map[string]bool, len(m.Permissions))
	for i, p := range m.Permissions {
		field := fmt.Sprintf("/permissions/%d/key", i)
		switch {
		case !ValidPermissionKey(p.Key):
			add(CodeInvalidKey, field, "The permission key is not valid.")
		case !strings.HasPrefix(p.Key, m.App+":"):
			add(CodePermissionAppMismatch, field, "The permission key must start with %s:.", m.App)
		}
		if defined[p.Key] {
			add(CodeDuplicateKey, field, "The permission key is used two times.")
		}
		defined[p.Key] = true
	}
	roles := make(map[string]bool, len(m.Roles))
	for i, r := range m.Roles {
		field := fmt.Sprintf("/defaultRoles/%d/key", i)
		if !ValidRoleKey(r.Key) {
			add(CodeInvalidKey, field, "The role key is not valid.")
		}
		if roles[r.Key] {
			add(CodeDuplicateKey, field, "The role key is used two times.")
		}
		roles[r.Key] = true
		seen := make(map[string]bool, len(r.Permissions))
		for j, key := range r.Permissions {
			pf := fmt.Sprintf("/defaultRoles/%d/permissions/%d", i, j)
			if !defined[key] {
				add(CodeRolePermissionUnknown, pf, "The permission is not in the manifest.")
			}
			if seen[key] {
				add(CodeDuplicateKey, pf, "The permission is used two times in the role.")
			}
			seen[key] = true
		}
	}
	return errs
}

// The canonical form. The fields are in alphabetical order, so encoding/json
// writes them in the order that the hash needs.
type canonicalPermission struct {
	Description string `json:"description"`
	Key         string `json:"key"`
}

type canonicalRole struct {
	Description string   `json:"description"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type canonicalManifest struct {
	App          string                `json:"app"`
	DefaultRoles []canonicalRole       `json:"defaultRoles"`
	Permissions  []canonicalPermission `json:"permissions"`
}

// Hash returns the SHA-256 of the canonical form, in hex. In the canonical
// form the permissions and the roles are in key order, the permissions of
// each role are in order, the object keys are sorted, and the JSON has no
// white space.
func (m Manifest) Hash() string {
	c := canonicalManifest{
		App:          m.App,
		DefaultRoles: make([]canonicalRole, 0, len(m.Roles)),
		Permissions:  make([]canonicalPermission, 0, len(m.Permissions)),
	}
	for _, p := range m.Permissions {
		c.Permissions = append(c.Permissions, canonicalPermission{Description: p.Description, Key: p.Key})
	}
	slices.SortFunc(c.Permissions, func(a, b canonicalPermission) int { return strings.Compare(a.Key, b.Key) })
	for _, r := range m.Roles {
		perms := slices.Clone(r.Permissions)
		if perms == nil {
			perms = []string{}
		}
		slices.Sort(perms)
		c.DefaultRoles = append(c.DefaultRoles, canonicalRole{Description: r.Description, Key: r.Key, Name: r.Name, Permissions: perms})
	}
	slices.SortFunc(c.DefaultRoles, func(a, b canonicalRole) int { return strings.Compare(a.Key, b.Key) })
	// Marshaling a struct of strings cannot fail.
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Role is a role of a stored manifest, with its permissions.
type Role struct {
	Ref         RoleRef
	Name        string
	Description string
	Permissions []string
}
