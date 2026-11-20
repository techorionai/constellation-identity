// Package lint tests the depguard rules of .golangci.yml.
package lint_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	err := os.WriteFile(path, []byte(content), 0o600) //nolint:gosec // A test.
	if err != nil {
		t.Fatal(err)
	}
}

// golangciVersion is the version of golangci-lint that the lint job of
// constellation-ci uses. The test runs the same version when the tool is not
// on the path. The unit and integration jobs of the CI do not install the tool.
const golangciVersion = "v2.15.0"

// linter returns the command that runs golangci-lint. It uses the tool on the
// path. If the tool is not on the path, it builds the pinned version with
// "go run", so that the test also runs in the CI. The test never skips.
func linter(t *testing.T) []string {
	t.Helper()
	if bin, err := exec.LookPath("golangci-lint"); err == nil {
		return []string{bin}
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("golangci-lint and go are not on the path: %v", err)
	}
	return []string{goBin, "run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + golangciVersion}
}

func lint(t *testing.T, dir string) (string, error) {
	t.Helper()
	args := append(linter(t), "run", "./...")
	cmd := exec.CommandContext(context.Background(), args[0], args[1:]...) //nolint:gosec // A test.
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// U13: the depguard rules pass for a clean layout, and fail when an adapter
// imports the application layer.
func TestU13_DepguardRules(t *testing.T) {
	config, err := os.ReadFile("../../../.golangci.yml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".golangci.yml"), string(config))
	write(t, filepath.Join(dir, "go.mod"), "module github.com/techorionai/constellation-identity\n\ngo 1.27.4\n")
	write(t, filepath.Join(dir, "internal/app/x/x.go"), "package x\n\n// A is a constant.\nconst A = 1\n")
	clean := "package postgres\n\n// B is a constant.\nconst B = 1\n"
	write(t, filepath.Join(dir, "internal/adapters/postgres/p.go"), clean)

	if out, err := lint(t, dir); err != nil {
		t.Fatalf("a clean layout must pass: %v\n%s", err, out)
	}

	bad := "package postgres\n\nimport \"github.com/techorionai/constellation-identity/internal/app/x\"\n\n// B is a constant.\nconst B = x.A\n"
	write(t, filepath.Join(dir, "internal/adapters/postgres/p.go"), bad)
	out, err := lint(t, dir)
	if err == nil {
		t.Fatalf("an adapter that imports internal/app must fail the lint\n%s", out)
	}
	if !strings.Contains(out, "depguard") {
		t.Fatalf("the failure must come from depguard\n%s", out)
	}
}
