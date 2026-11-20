# Architecture

The service follows the hexagonal architecture guide of the planner repository. It uses HTTP, pgx, and `slog` through `constellation-platform-go`.

## Layout

```txt
cmd/identity/main.go            Starts the service. Subcommands "healthcheck" and "rotate-signing-keys".
api/openapi/                    Constellation.Identity.openapi.yaml, CONTRACTS_VERSION
internal/domain/                Pure types and rules (signing key states, client rules)
internal/ports/<port>/          Interfaces
internal/adapters/postgres/     Repositories
internal/adapters/secrets/      Adapter of the port "privatekeys" on platform-go secrets
internal/adapters/jose/         Adapter of the port "tokensigner" with go-jose
internal/app/{commands,queries} Use cases with platform-go executors and decorators
internal/app/keys/              Key manager and in-memory key cache
internal/handlers/http/         Generated server (gen/), handlers
internal/common/errors/         AppError
internal/config/                Config struct and the clients file parser
internal/services/              Composition root
migrations/                     SQL files, embedded
resources/test/                 mock, testserver, lint and image tests
```

The `.golangci.yml` file has `depguard` rules for the import table of the guide. A handler calls `internal/app/` only. An adapter implements a port and does not import `internal/app/` or another adapter.

## Ports

| Port | Package | Implementation |
| ---- | ------- | -------------- |
| Signing key repository | `internal/ports/signingkeys` | `internal/adapters/postgres` |
| Private key store | `internal/ports/privatekeys` | `internal/adapters/secrets` on `secrets.Service` |
| Token signer | `internal/ports/tokensigner` | `internal/adapters/jose` |
| Client repository | `internal/ports/clients` | `internal/adapters/postgres` |

## Routes

`oapi-codegen` makes the `std-http-server` and `strict-server` code for all operations of the contract. One generated router serves OAuth, discovery, and `/v1`. The service uses no OIDC provider library. The `go-jose` library signs JWTs.

The middleware chain is `otelhttp`, then `requestid`, then the router.

| Route | State |
| ----- | ----- |
| `GET /.well-known/jwks.json` | Implemented. `Cache-Control: public, max-age=300`. |
| `GET /.well-known/openid-configuration` | Implemented. `Cache-Control: public, max-age=3600`. |
| `POST /oauth/token` | 400 `unsupported_grant_type` until the grants come. |
| All other operations | 501 `Problem` with the code `not_implemented`. |

## Startup order

1. Load the clients file (an error stops the start).
2. Connect to PostgreSQL and Valkey.
3. Start the admin server. `/livez` is 200 and `/readyz` is 503.
4. Run the migrations of `secrets/postgres`, then the migrations of the service.
5. Load the key cache. A key that does not decrypt stops the start. Then run the key manager one time and load the cache again. The first load comes before the manager, so the manager never makes a key after a master key change.
6. Start the key manager loop (10 minutes) and the cache reload loop (1 minute).
7. Sync the clients file.
8. Start the public server and mark the service ready.

The readiness checks are `postgres`, `valkey`, `migrations`, and `signing_key` (an active key is in the cache).

## Key lifecycle

The key manager runs under a PostgreSQL advisory lock, so one instance changes the keys at a time.

1. No `active` or `pending` key: make a key and activate it at once.
2. The active key is older than `ROTATION_PERIOD` and no key is `pending`: make a `pending` key with `activates_at = now + PUBLISH_DELAY`.
3. A `pending` key has `activates_at <= now`: make it `active` and set the old key to `retired`. Both changes are one database transaction.
4. A `retired` key has `retired_at + RETIRE_AFTER <= now`: delete the row. A `retired` key has no private key, so there is no secret to delete.
5. Delete each secret under `identity/signing-keys/` that has no row, or whose row is `retired`. This deletes the private key of the old key in the pass that retires it.

The `kid` is the first 32 lowercase hex characters of the RFC 7638 SHA-256 thumbprint of the public key. The secret name is `identity/signing-keys/<kid>`.

Write order:

- A new key: put the secret first, then insert the row. A failure after the put leaves a secret with no row. Rule 5 deletes it.
- A key that becomes `retired`: change the states in one transaction, then delete the secret. A failure after the transaction leaves a secret with a `retired` row. Rule 5 deletes it on the next run.
- Thus a `pending` or `active` row never points to a missing secret. A `retired` row has no secret, or a secret that rule 5 deletes.

The cache serves a row only if the row is valid. The RFC 7638 thumbprint of the public key must be the `kid`. The members `kty`, `crv`, `alg`, and `use` must be `EC`, `P-256`, `ES256`, and `sig`. The `private_key_name` must be `identity/signing-keys/<kid>`. The database has a unique index for one `active` row, and a check that a `retired` row has `retired_at`.

The JWKS has the `pending`, `active`, and `retired` public keys. Only the `active` key signs. Each instance keeps the keys in memory and reloads them every minute.

## The clients file

The environment-only rule of `constellation-platform-go` says "no config files". The clients file holds data (clients and their public keys), not settings. A list of keys does not fit in environment variables. An environment variable gives its path. See [configuration.md](configuration.md).

## Telemetry

The service name is `identity`. Metrics: `identity.signing_keys` (gauge, attribute `state`) and `identity.key_rotation` (counter, attribute `outcome` with `ok` or `error`). Each key state change writes one `info` log record with `kid`, `old_state`, and `new_state`. No log record has a private key.
