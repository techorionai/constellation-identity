# Architecture

The service follows the hexagonal architecture guide of the planner repository. It uses HTTP, pgx, and `slog` through `constellation-platform-go`.

## Layout

```txt
cmd/identity/main.go            Starts the service. Subcommands "healthcheck", "rotate-signing-keys", "setup-link", "unlock-login", "reset-mfa", and "set-idp-secret".
api/openapi/                    Constellation.Identity.openapi.yaml, identity-manifest.json, CONTRACTS_VERSION
internal/domain/                Pure types and rules (signing keys, clients, manifests, roles, assertions, scopes)
internal/ports/<port>/          Interfaces
internal/adapters/postgres/     Repositories and the "jtistore" adapter
internal/adapters/secrets/      Adapter of the port "privatekeys" on platform-go secrets
internal/adapters/jose/         Adapters of the ports "tokensigner", "tokenverifier", and "assertion" with go-jose
internal/adapters/argon2/       Adapter of the port "passwordhasher" (argon2id, NFC, hash slots)
internal/adapters/valkey/       Adapters of the ports "loginlimiter" (login failure counters), "ratelimit" (request counters), "authflow" (auth requests, codes, used-code markers), and "idpflow" (upstream flow records)
internal/adapters/oidc/         Adapter of the port "upstreamidp" (go-oidc and x/oauth2)
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

## Signing key audit entries

Each key change writes an audit entry in the same transaction as the row change. `createKey` stores the secret first. Then one transaction inserts the row and writes `identity:signing_key:create`. The activation writes `identity:signing_key:retire` for each old active key and `identity:signing_key:activate`, in the transaction of `Activate`. The delete of a retired row writes `identity:signing_key:delete`. The secret store call stays outside the transaction. The manager does not change a key if it has no audit writer.

The forced rotation (`rotate-signing-keys --force`) does these steps in this order:

1. It stores the new secret.
2. One transaction writes the delete entries (with `forced` `true`), the create entry, and the `force_rotate` entry with the new `kid`. It deletes all rows and inserts the new active row.
3. After the commit, it deletes the old secrets.

If the transaction fails, the old keys stay, and the next pass deletes the new secret that has no row. If the delete of a secret fails after the commit, the next pass deletes the secrets that have no row.

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
| TOTP codes (RFC 6238) | `internal/ports/totp` | `internal/adapters/totp` (`github.com/pquerna/otp`) |
| TOTP factors and recovery codes (tables `user_totp`, `recovery_codes`) | `internal/ports/mfa` | `internal/adapters/postgres` |
| Sealed TOTP secret | `internal/ports/secretbox` | `internal/adapters/secrets` (`platform-go` `secrets` key ring) |
| Pending login, setup secret, failure counter of the second factor, state of the WebAuthn ceremonies | `internal/ports/mfaflow` | `internal/adapters/valkey` (`SET`, `GET`, `GETDEL`, `DEL`, `MULTI`, `INCR`, `EXPIRE NX`) |
| Passkeys and WebAuthn user handles (table `webauthn_credentials`, column `users.webauthn_user_handle`) | `internal/ports/passkeys` | `internal/adapters/postgres` |
| WebAuthn ceremonies | `internal/ports/webauthn` | `internal/adapters/webauthn` (`github.com/go-webauthn/webauthn`) |
| Security notices | `internal/ports/securitynotices` | `internal/adapters/securitynotices` (log only) |
| Audit entries | `audit.Writer` of `platform-go` (`audit/postgres`) | Table `platform_audit_outbox`, relay `audit`, Valkey stream `audit.stream:identity` |
| Links to upstream accounts (table `identity_links`) | `internal/ports/identitylinks` | `internal/adapters/postgres` |
| Upstream `auth_time` flag (columns `sessions.upstream_auth_valid` and `refresh_token_families.upstream_auth_valid`, table `upstream_auth_tokens`, migration `0015`) | `internal/ports/sessions` | `internal/adapters/postgres` |
| Upstream providers (Google, Microsoft) | `internal/ports/upstreamidp` | `internal/adapters/oidc` (`go-oidc`, `x/oauth2`, and a key set for the Microsoft tenant `organizations`) |
| Records of the upstream flows | `internal/ports/idpflow` | `internal/adapters/valkey` (`SET`, `GETDEL`) |
| Client secrets of the upstream providers | `internal/ports/idpsecrets` | `internal/adapters/secrets` (`platform-go` `secrets.Service`) |

The port `securitynotices` has one method, `NotifyUser`. The service has no email channel yet, so the adapter writes one log record for each notice. R12 replaces the adapter. The commands do not change.

The audit entries do not use a port of the service. Each command that changes data gets the `audit.Writer` of `platform-go`. The command calls it in the transaction of the change. The writer inserts one row into the table `platform_audit_outbox`. If the insert fails, the transaction rolls back and the request gets 503. The audit relay (`outbox.Relay` with the name `audit`) reads the unpublished rows and adds each entry to the Valkey stream `audit.stream:identity`. The transactor wakes the relay after the commit. The relay also polls each second. Only the audit service reads the stream. The retention jobs `audit_outbox` and `audit_stream` delete the old rows and trim the stream. The migrations of the audit outbox run before the migrations of the service. The `clientinfo` middleware of `platform-go` puts the client IP and the user agent into the context of each request. The writer copies them and the request ID into the entry. See [security.md](security.md) for the entries.

The ports of the sessions, users, user roles, clients, and client roles have the methods that the code flow and the admin API need: the session `Reauthenticate` and `RevokeCascade`, the lists with a cursor, the role `Page`, and the client create, update, and key methods.

## Routes

`oapi-codegen` makes the `std-http-server` and `strict-server` code for all operations of the contract. One generated router serves OAuth, discovery, and `/v1`. The service uses `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` as a client of the upstream providers Google and Microsoft. It is still not an OIDC provider library: the service signs and verifies its own tokens with `go-jose`.

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
| `GET /login/mfa`, `POST /login/mfa`, `GET /account/security`, `GET /account/totp`, `POST /account/totp`, `POST /account/totp/remove`, `POST /account/recovery-codes` | HTML pages of the second factor and of the MFA settings. They are not in the OpenAPI file. See [security.md](security.md). |
| `GET /account/passkeys`, `POST /account/passkeys/{id}/rename`, `POST /account/passkeys/{id}/remove` | HTML page and forms of the passkeys. No script is necessary for the rename and the removal. |
| `POST /account/passkeys/options`, `POST /account/passkeys/finish`, `POST /login/passkey/options`, `POST /login/passkey/finish`, `POST /login/mfa/passkey/options`, `POST /login/mfa/passkey/finish` | JSON routes of the WebAuthn ceremonies. The script calls them. They are not in the OpenAPI file. |
| `GET /login/oidc/{provider}`, `GET /login/oidc/{provider}/callback`, `GET /account/identity-links/{provider}/link`, `POST /account/identity-links/{provider}/link`, `POST /account/identity-links/{provider}/remove`, `POST /account/identity-links/passkey/options`, `POST /account/identity-links/passkey/link`, `POST /account/identity-links/passkey/remove`, `GET /account/password`, `POST /account/password` | HTML routes of the login with an upstream account, of the links on the account page, and of the first password of a user that has none. They are not in the OpenAPI file. See [security.md](security.md). |
| `GET /assets/passkey.js` | The one script of the service (embedded). It gives 404 when passkeys are off. |
| `GET /login`, `POST /login`, `GET /login/done`, `POST /logout`, `GET /setup`, `POST /setup`, `GET /invite`, `POST /invite`, `GET /assets/pages.css` | HTML pages. They are not in the OpenAPI file. See [security.md](security.md). |

The pages are on a router in front of the generated router. The chain is `RedactToken`, then `otelhttp`, then `requestid`, then `RestoreQuery`, then the router of the pages or the generated router. `RedactToken` replaces the values of `token`, `code`, `code_verifier`, `refresh_token`, `id_token_hint`, `authRequest`, `state`, `nonce`, `id_token`, `error_description`, and `session_state` with `REDACTED` in the URL, so no span and no log record holds a secret. It keeps the real query in the request context, and `RestoreQuery` puts it back for the handlers. The pages use `html/template` with embedded templates, one embedded CSS file, and one embedded script (`assets/passkey.js`) for the three pages that run the passkey ceremonies.

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

The service name is `identity`. Metrics: `identity.signing_keys` (gauge, attribute `state`) and `identity.key_rotation` (counter, attribute `outcome` with `ok` or `error`). Token metrics: `identity.tokens.issued` (counter, attributes `grant_type` and `principal_type`), `identity.token.errors` (counter, attribute `error`), `identity.code.reuse`, and `identity.refresh_token.reuse`. The counter `identity.audit.denied_dropped` (attributes `action` and `reason`) counts the denied audit entries that the service did not write because of a limit. See [tokens.md](tokens.md) for the log rule. Each key state change writes one `info` log record with `kid`, `old_state`, and `new_state`. No log record has a private key.
