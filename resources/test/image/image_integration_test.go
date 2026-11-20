//go:build integration

// Package image tests the container image of the service.
package image_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcvalkey "github.com/testcontainers/testcontainers-go/modules/valkey"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// buildImage builds the Dockerfile with the docker CLI. The Dockerfile uses
// --platform=$BUILDPLATFORM, which the legacy builder of the testcontainers
// library does not support. It returns the image tag.
func buildImage(ctx context.Context, t *testing.T, root string) string {
	t.Helper()
	tag := "identity-test:" + strings.ToLower(rand.Text())
	out, err := exec.CommandContext(ctx, "docker", "build", "-t", tag, root).CombinedOutput() //nolint:gosec // A test.
	if err != nil {
		t.Fatalf("docker build: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.CommandContext(context.Background(), "docker", "rmi", "-f", tag).Run() //nolint:gosec // A test.
	})
	return tag
}

// I7: build the Dockerfile, run the image with no argument and with the
// healthcheck command.
func TestI7_Image(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	root := repoRoot(t)

	net, err := network.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = net.Remove(context.Background()) })

	pg, err := tcpostgres.Run(ctx, testserver.PostgresImage,
		tcpostgres.WithDatabase("identity"), tcpostgres.WithUsername("identity"), tcpostgres.WithPassword("pgpass"),
		tcpostgres.BasicWaitStrategies(), network.WithNetwork([]string{"pg"}, net))
	if pg != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(pg) })
	}
	if err != nil {
		t.Fatal(err)
	}
	vk, err := tcvalkey.Run(ctx, testserver.ValkeyImage,
		testcontainers.WithCmdArgs("--requirepass", "vkpass"), network.WithNetwork([]string{"vk"}, net))
	if vk != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(vk) })
	}
	if err != nil {
		t.Fatal(err)
	}

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatal(err)
	}

	image := buildImage(ctx, t, root)

	// With no argument, the server starts.
	app, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"8080/tcp", "9090/tcp"},
			Networks:     []string{net.Name},
			Env: map[string]string{ //nolint:gosec // Throwaway passwords of test containers.
				"IDENTITY_ISSUER":                 "http://localhost:8080",
				"IDENTITY_DATABASE__URL":          "postgres://identity:pgpass@pg:5432/identity?sslmode=disable",
				"IDENTITY_DATABASE__NAME":         "identity",
				"IDENTITY_VALKEY__ADDRESS":        "vk:6379",
				"IDENTITY_VALKEY__PASSWORD":       "vkpass",
				"IDENTITY_VALKEY__KEY_PREFIX":     "identity",
				"IDENTITY_SECRETS__MASTER_KEY":    base64.StdEncoding.EncodeToString(masterKey),
				"IDENTITY_SECRETS__MASTER_KEY_ID": "test",
			},
			WaitingFor: wait.ForHTTP("/readyz").WithPort("9090/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if app != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(app) })
	}
	if err != nil {
		t.Fatalf("build and start the image: %v", err)
	}

	info, err := app.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if user := info.Config.User; user != "65532" && user != "65532:65532" && user != "nonroot" {
		t.Fatalf("image user = %q, want UID 65532", user)
	}
	if len(info.Config.Entrypoint) != 1 || info.Config.Entrypoint[0] != "/identity" {
		t.Fatalf("entrypoint = %v", info.Config.Entrypoint)
	}

	// docker exec <container> /identity healthcheck exits with 0 when ready.
	code, _, err := app.Exec(ctx, []string{"/identity", "healthcheck"})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("healthcheck exit code = %d, want 0", code)
	}

	// The healthcheck command in a container with no server exits with 1.
	probe, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Cmd:        []string{"healthcheck"},
			WaitingFor: wait.ForExit().WithExitTimeout(time.Minute),
		},
		Started: true,
	})
	if probe != nil {
		t.Cleanup(func() { _ = testcontainers.TerminateContainer(probe) })
	}
	if err != nil {
		t.Fatalf("run the healthcheck command: %v", err)
	}
	state, err := probe.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.ExitCode != 1 {
		t.Fatalf("healthcheck with no server: exit code = %d, want 1", state.ExitCode)
	}
}
