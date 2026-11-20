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
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lint(t *testing.T, dir string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("golangci-lint")
	if err != nil {
		t.Skip("golangci-lint is not installed")
	}
	cmd := exec.CommandContext(context.Background(), bin, "run", "./...")
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
