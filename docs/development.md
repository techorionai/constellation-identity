# Development

## Commands

| Task | Command |
| ---- | ------- |
| Lint | `test -z "$(gofmt -l .)" && go vet ./... && golangci-lint run` |
| Unit tests | `go test -race ./...` |
| Integration tests | `go test -race -tags=integration ./...` |
| Generate | `go generate ./...` |

The integration tests need Docker. They start PostgreSQL and Valkey with testcontainers and use the same images as `constellation-deploy`. The image test (`resources/test/image`) builds the `Dockerfile` with the `docker` CLI. The `-race` flag needs a C compiler. Without one, run the tests without `-race`. If containers time out, add `-p 1`.

`resources/test/testserver` starts the service in the test process. Its options set short key periods and short loop intervals with `services.WithKeyPolicy` and `services.WithKeyIntervals`. These options do not go through the config checks. Production code does not use them.

## Generated code

`internal/handlers/http/gen/identity.gen.go` comes from the OpenAPI file in `api/openapi/`. The CI runs `go generate ./... && test -z "$(git status --porcelain)"`. The check also finds a new file that the generator made and the author did not commit. Commit the generated file after each change of the contract copy.

`oapi-codegen` is a `tool` directive in `go.mod`. `go generate` runs `go tool oapi-codegen`. To update the tool, run `go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@<version>`.

## Update the contract copy

1. Get the file from a release tag of `constellation-contracts`:

   ```sh
   git -C ../constellation-contracts show vX.Y.Z:generated/openapi/Constellation.Identity.openapi.yaml > api/openapi/Constellation.Identity.openapi.yaml
   ```

2. Write the version in `api/openapi/CONTRACTS_VERSION`.
3. Run `go generate ./...`. Implement the new operations or the new fields.

## Rotation test values

The rotation test (`I5`) uses `ROTATION_PERIOD=4s`, `PUBLISH_DELAY=1s`, and `RETIRE_AFTER=2s`. With a rotation period that is equal to the retire time, the next rotation starts when the retired key ends, and the JWKS never goes back to one key.

## Dockerfile

The build stage uses `--platform=$BUILDPLATFORM` and `GOARCH=$TARGETARCH`, so QEMU runs only the final stage. The base images are pinned by digest. To update them, pull the new tag and write the new digest in the `Dockerfile`.
