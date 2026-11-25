# Architecture

The service follows the hexagonal architecture guide of the planner repository. It uses HTTP, pgx, and `slog` through `constellation-platform-go`.

## Layout

```txt
cmd/identity/main.go            Starts the service. Subcommands "healthcheck", "rotate-signing-keys", "setup-link", and "unlock-login".
api/openapi/                    Constellation.Identity.openapi.yaml, identity-manifest.json, CONTRACTS_VERSION
internal/domain/                Pure types and rules (signing keys, clients, manifests, roles, assertions, scopes)
internal/ports/<port>/          Interfaces
internal/adapters/postgres/     Repositories and the "jtistore" adapter
internal/adapters/secrets/      Adapter of the port "privatekeys" on platform-go secrets
internal/adapters/jose/         Adapters of the ports "tokensigner", "tokenverifier", and "assertion" with go-jose
internal/adapters/argon2/       Adapter of the port "passwordhasher" (argon2id, NFC, hash slots)
internal/adapters/valkey/       Adapters of the ports "loginlimiter" (login failure counters), "ratelimit" (request counters), and "authflow" (auth requests, codes, used-code markers)
internal/app/{commands,queries} Use cases with platform-go executors and decorators
internal/app/keys/              Key manager and in-memory key cache
internal/handlers/http/         Generated server (gen/), handlers
internal/handlers/http/pages/   HTML pages: login, logout, setup, invite (templates, CSS, headers)
internal/handlers/http/clientip/   Client IP and the rate limit key of a client (IPv6 /64 and /48)
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
| Manifest and role repository | `internal/ports/manifests` | `internal/adapters/postgres` |
| Client role repository | `internal/ports/clientroles` | `internal/adapters/postgres` |
| Assertion parser | `internal/ports/assertion` | `internal/adapters/jose` |
| Replay store (`jti`) | `internal/ports/jtistore` | `internal/adapters/postgres` |
| User repository | `internal/ports/users` | `internal/adapters/postgres` |
| User role repository | `internal/ports/userroles` | `internal/adapters/postgres` |
| One-time token repository (setup, invite) | `internal/ports/onetimetokens` | `internal/adapters/postgres` |
| Session repository | `internal/ports/sessions` | `internal/adapters/postgres` |
| Password hasher | `internal/ports/passwordhasher` | `internal/adapters/argon2` |
| Login failure limiter | `internal/ports/loginlimiter` | `internal/adapters/valkey` |
| Rate limiter | `internal/ports/ratelimit` | `internal/adapters/valkey` (`MULTI`, `INCR`, `PEXPIRE NX`, `PTTL`, `EXEC`) |
| Auth request store and code store | `internal/ports/authflow` | `internal/adapters/valkey` (`SET`, `GET`, `GETDEL`) |
| Refresh token families and tokens | `internal/ports/refreshtokens` | `internal/adapters/postgres` |
| Token verifier (own tokens) | `internal/ports/tokenverifier` | `internal/adapters/jose` |
| Personal API tokens (table `api_tokens`) | `internal/ports/apitokens` | `internal/adapters/postgres` |
| Agents (table `agents`) and agent roles (table `agent_roles`) | `internal/ports/agents`, `internal/ports/agentroles` | `internal/adapters/postgres` |
| Admin change lock | `internal/ports/adminlock` | `internal/adapters/postgres` (`pg_advisory_xact_lock`) |

The ports of the sessions, users, user roles, clients, and client roles have the methods that the code flow and the admin API need: the session `Reauthenticate` and `RevokeCascade`, the lists with a cursor, the role `Page`, and the client create, update, and key methods.

## Routes

`oapi-codegen` makes the `std-http-server` and `strict-server` code for all operations of the contract. One generated router serves OAuth, discovery, and `/v1`. The service uses no OIDC provider library. The `go-jose` library signs JWTs.

The middleware chain is `otelhttp`, then `requestid`, then a body limit of 1 MiB, then the router. Each `/v1` route adds `auth.Middleware` and `auth.RequireScopes` with the `x-required-scopes` list of the operation. The route pattern of the router gives the list. See [tokens.md](tokens.md).

The service reads the lists from the embedded OpenAPI file at start (`NewScopeTable`). A `/v1` operation with no list stops the start. A request for a `/v1` route with no entry fails with a 500 (fail closed).

The token endpoint is the use case `IssueServiceToken` in `internal/app/commands/`. It uses the ports `clients`, `clientroles`, `manifests`, `jtistore`, `assertion`, and `tokensigner`, and the key cache. The `/v1` routes use `auth/jwt` of `constellation-platform-go` as an in-process verifier. Its JWKS comes from the key cache through a round tripper, not from the network.

| Route | State |
| ----- | ----- |
| `GET /.well-known/jwks.json` | Implemented. `Cache-Control: public, max-age=300`. |
| `GET /.well-known/openid-configuration` | Implemented. `Cache-Control: public, max-age=3600`. |
| `POST /oauth/token` | The grants `client_credentials`, `authorization_code`, `refresh_token`, and `urn:ietf:params:oauth:grant-type:token-exchange`. Another grant gives 400 `unsupported_grant_type`. |
| `GET /oauth/authorize`, `GET /oauth/end_session` | HTML pages on the pages router, because they need the raw query, the cookie, and pages. The generated operations answer 501 if a request ever reaches them. |
| `GET /oauth/authorize/continue`, `POST /oauth/end_session` | Page routes that are not in the OpenAPI file. |
| `GET /oauth/userinfo`, `POST /oauth/revoke` | Implemented. CORS for registered origins. |
| `POST /oauth/introspect` | Implemented. The use case `Introspect` checks the caller with `AuthenticateService` and reads the table `api_tokens`. See [tokens.md](tokens.md). |
| All `/v1` operations | Implemented. See [admin-api.md](admin-api.md). |
| `PUT /v1/permission-manifests/{app}`, `GET /v1/permission-manifests`, `GET /v1/permission-manifests/{app}`, `GET /v1/roles`, `GET /v1/roles/{role}` | Implemented. |
| `GET /login`, `POST /login`, `GET /login/done`, `POST /logout`, `GET /setup`, `POST /setup`, `GET /invite`, `POST /invite`, `GET /assets/pages.css` | HTML pages. They are not in the OpenAPI file. See [security.md](security.md). |

The pages are on a router in front of the generated router. The chain is `RedactToken`, then `otelhttp`, then `requestid`, then `RestoreQuery`, then the router of the pages or the generated router. `RedactToken` replaces the values of `token`, `code`, `code_verifier`, `refresh_token`, `id_token_hint`, `authRequest`, `state`, and `nonce` with `REDACTED` in the URL, so no span and no log record holds a secret. It keeps the real query in the request context, and `RestoreQuery` puts it back for the handlers. The pages use `html/template` with embedded templates, one embedded CSS file, and no JavaScript.

The use cases of the users are in `internal/app/commands/` (`EnsureSetupToken`, `ReplaceSetupToken`, `CompleteSetup`, `CreateUser`, `CreateInvite`, `AcceptInvite`, `Login`, `Logout`, `TouchSession`) and `internal/app/queries/` (`SessionFromCookie`, `CheckOneTimeToken`). The code flow is in `internal/app/commands/oidc.go` (`OIDC`: `StartAuthorization`, `CompleteAuthorization`, `ExchangeCode`, `RefreshTokens`, `RevokeToken`, `StartEndSession`, `ConfirmEndSession`, `GetUserInfo`). The admin API is in `internal/app/commands/admin.go` (`Admin`) and calls `CreateUser` and `CreateInvite`. The CORS origin query is in `internal/app/queries/cors.go`. The `Login` command keeps the session at a re-login of the same user.

### Lock order

The table `agents` has the columns `id`, `name` (unique), `client_id` (foreign key to `clients`), `enabled`, `created_at`, and `updated_at`. The table `agent_roles` has the key (`agent_id`, `app`, `role`) and `source`. It has no foreign key to `roles`, so a role that leaves a manifest stays as a pending assignment. The migration `0011` only adds tables. The token exchange is the use case `TokenExchange` in `internal/app/commands/token_exchange.go`. See [tokens.md](tokens.md).

The create of an API token locks the user row (`SELECT ... FOR UPDATE`) in its own transaction, checks the status and the two limits, and inserts the row into the table `api_tokens`. The disable of a user holds the user row lock too, so a create and a disable cannot both pass. The disable revokes the API tokens in the same transaction as the sessions.

All paths that touch a session and its refresh token families lock in one order: the advisory lock of the admin change (only for admin changes that can remove the last admin), then the session row, then the family rows in ascending ID order. The paths are: rotation, reuse revoke, logout, end session, session revoke, user disable, client disable, and the revoke endpoint.

## Startup order

1. Load the clients file (an error stops the start).
2. Connect to PostgreSQL and Valkey.
3. Start the admin server. `/livez` is 200 and `/readyz` is 503.
4. Run the migrations of `secrets/postgres`, then the migrations of the service. Then publish the own manifest of the service (the roles `identity:admin`, `identity:service`, and `identity:user`). Then, under a PostgreSQL advisory lock, make the first-admin setup token if no active user has the role `identity:admin` and no valid setup token exists, and write one log record with the expiry (the record has no link). See [first-start.md](first-start.md).
5. Load the key cache. A key that does not decrypt stops the start. Then run the key manager one time and load the cache again. The first load comes before the manager, so the manager never makes a key after a master key change.
6. Start the key manager loop (10 minutes) and the cache reload loop (1 minute).
7. Sync the clients file.
8. Start the retention jobs and the gauge of active sessions.
9. Start the public server and mark the service ready.

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

The service name is `identity`. Metrics: `identity.signing_keys` (gauge, attribute `state`) and `identity.key_rotation` (counter, attribute `outcome` with `ok` or `error`). Token metrics: `identity.tokens.issued` (counter, attributes `grant_type` and `principal_type`), `identity.token.errors` (counter, attribute `error`), `identity.code.reuse`, and `identity.refresh_token.reuse`. See [tokens.md](tokens.md) for the log rule. Each key state change writes one `info` log record with `kid`, `old_state`, and `new_state`. No log record has a private key.
