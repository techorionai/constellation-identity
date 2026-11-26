# Configuration

The service reads its settings from environment variables with the prefix `IDENTITY_`. A double underscore `__` separates the levels of a nested name. A variable with a `_FILE` form reads its value from a file.

## Variables

| Variable | Default | Rule | Use |
| -------- | ------- | ---- | --- |
| `IDENTITY_ISSUER` | required | Absolute URL with no query and no fragment. `https` is required. `http` is accepted only when the host is `localhost`, `127.0.0.1`, or `[::1]`. | Public base URL, for example `https://id.example.com`. It is the `iss` claim of all tokens. |
| `IDENTITY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` | Log level. |
| `IDENTITY_HTTP__ADDR` | `:8080` | | Public listener. |
| `IDENTITY_HTTP__TRUSTED_PROXIES` | empty | Comma-separated CIDR ranges | Proxies whose `X-Forwarded-For` value the service uses for the client IP. Each proxy must append the peer address to `X-Forwarded-For`. See [security.md](security.md). |
| `IDENTITY_ADMIN__ADDR` | `:9090` | | Listener for `/livez` and `/readyz`. Do not publish it at the edge. |
| `IDENTITY_ADMIN__CHECK_TIMEOUT` | `2s` | | Time limit of the readiness checks. |
| `IDENTITY_ADMIN__DRAIN_DELAY` | `5s` | | Time that `/readyz` is 503 before the public server stops. |
| `IDENTITY_DATABASE__URL`, `IDENTITY_DATABASE__NAME` | required | platform-go `clients/postgres` rules | PostgreSQL. Also `IDENTITY_DATABASE__URL_FILE`. |
| `IDENTITY_VALKEY__ADDRESS`, `IDENTITY_VALKEY__KEY_PREFIX` | required | platform-go `clients/valkey` rules | Valkey. Use the key prefix `identity`. The service keeps the login failure counters, the auth requests, the authorization codes, and the used-code markers in Valkey. The `jti` values of client assertions are in PostgreSQL. API tokens are in PostgreSQL only. The service checks Valkey in `/readyz`. |
| `IDENTITY_SECRETS__MASTER_KEY` or `IDENTITY_SECRETS__MASTER_KEY_FILE` | required | 32 bytes, base64 | Master key for the envelope encryption of the signing keys. |
| `IDENTITY_SECRETS__MASTER_KEY_ID` | required | `^[a-z0-9-]{1,32}$` | ID of the master key. |
| `IDENTITY_SECRETS__PREVIOUS_KEYS` | empty | `<id>:<base64>` items, separated by commas | Old master keys, for master key rotation. |
| `IDENTITY_KEYS__ROTATION_PERIOD` | `2160h` (90 days) | More than `PUBLISH_DELAY` | Age of the active key before rotation. |
| `IDENTITY_KEYS__PUBLISH_DELAY` | `1h` | 20 minutes or more | Time that a new key is in the JWKS before it signs. It must be more than the refresh interval of the verifiers (10 minutes in `auth/jwt`) plus the key cache reload (1 minute) plus the JWKS `max-age` (5 minutes). |
| `IDENTITY_KEYS__RETIRE_AFTER` | `24h` | 30 minutes or more | Time that a replaced key stays in the JWKS. It must be more than the longest token life (15 minutes) plus the leeway of the verifiers. |
| `IDENTITY_SETUP__TTL` | `24h` | 10 minutes to 7 days | Life of the first-admin setup token. |
| `IDENTITY_INVITE__TTL` | `72h` | 10 minutes to 30 days | Life of an invite token. |
| `IDENTITY_SESSION__IDLE_TIMEOUT` | `12h` | 5 minutes to `SESSION__ABSOLUTE_TIMEOUT` | Idle expiry of a browser session. |
| `IDENTITY_SESSION__ABSOLUTE_TIMEOUT` | `168h` (7 days) | 1 hour to 90 days | Absolute expiry of a browser session. |
| `IDENTITY_PASSWORD__MAX_CONCURRENT` | `4` | 1 to 64 | Number of password hashes that run at the same time. Each hash uses 64 MiB of memory. |
| `IDENTITY_PASSWORD__QUEUE_TIMEOUT` | `2s` | 100 ms to 30 s | Longest wait for a hash slot. After it, the page gives status 503. |
| `IDENTITY_LOGIN__MAX_FAILURES_PER_EMAIL` | `5` | 1 to 100 | Login attempts for one email in the window. The attempt after the limit gets status 429. |
| `IDENTITY_LOGIN__MAX_FAILURES_PER_IP` | `50` | 1 to 10000 | Failed login attempts from one client IP in the window. A good login takes back its attempt. The attempt after the limit gets status 429. |
| `IDENTITY_LOGIN__FAILURE_WINDOW` | `15m` | 1 minute to 24 hours | Life of the failure counters. |
| `IDENTITY_MFA__REQUIRE_FOR_ADMINS` | `true` | `true` or `false` | The rule "MFA for admins". A user with the permission `identity:admin` must set up TOTP. Without TOTP, the user gets no authorization code and no refresh. |
| `IDENTITY_MFA__TOTP_ISSUER` | `Constellation` | 1 to 64 characters | The issuer name in the authenticator app. |
| `IDENTITY_MFA__MAX_FAILURES_PER_USER` | `10` | 1 to 100 | Failed second factor tries of one user in the window. The next try gets status 429. |
| `IDENTITY_MFA__FAILURE_WINDOW` | `15m` | 1 minute to 24 hours | Life of the MFA failure counter. |
| `IDENTITY_RATE_LIMIT__ENABLED` | `true` | `true` or `false` | Turns the rate limits of the public endpoints on or off. With `false`, the service does not call the limiter and writes one `warn` log record at start. The login limiter does not use this setting. |
| `IDENTITY_RATE_LIMIT__<BUCKET>__LIMIT` | See [security.md](security.md) | 1 to 1000000 | Requests that one key can send in the window. `<BUCKET>` is the bucket name in upper case, for example `IDENTITY_RATE_LIMIT__TOKEN_IP__LIMIT`. The buckets are `PUBLIC_META`, `OAUTH_PUBLIC`, `OAUTH_BACKEND_IP`, `TOKEN_IP`, `INTROSPECT_IP`, `TOKEN_CLIENT`, `INTROSPECT_CLIENT`, `SETUP_INVITE`, `API_TOKEN_CREATE`, `MANIFEST_PUBLISH`, and `MFA_VERIFY`. |
| `IDENTITY_RATE_LIMIT__<BUCKET>__WINDOW` | See [security.md](security.md) | 1 second to 24 hours | Length of the window of the bucket. |
| `IDENTITY_RETENTION__TOKENS__PERIOD`, `IDENTITY_RETENTION__SESSIONS__PERIOD`, `IDENTITY_RETENTION__REFRESH_TOKENS__PERIOD`, `IDENTITY_RETENTION__REFRESH_TOKEN_FAMILIES__PERIOD` | `168h` | | Age after which the service deletes ended tokens, sessions, refresh tokens, and refresh token families. Also `INTERVAL` and `BATCH_SIZE`. The refresh token job deletes a token only after it expired, so a used token stays until its session expires and a replay still starts the reuse detection. See `retention` in `constellation-platform-go`. |
| `IDENTITY_API_TOKEN__DEFAULT_TTL_DAYS` | `90` | 1 to `API_TOKEN__MAX_TTL_DAYS` | Life of a personal API token when the request has no `expiresInDays`. |
| `IDENTITY_API_TOKEN__MAX_TTL_DAYS` | `365` | 1 to 365 | Largest `expiresInDays` of a personal API token. |
| `IDENTITY_API_TOKEN__MAX_PER_USER` | `50` | 1 to 500 | Active API tokens of one user. The create also refuses a user with 10 times this number of rows (active, expired, and revoked). |
| `IDENTITY_RETENTION__API_TOKENS__PERIOD` | `168h` | | Age after which the service deletes API tokens that expired or were revoked. Also `INTERVAL` and `BATCH_SIZE`. |
| `IDENTITY_OIDC__AUTH_REQUEST_TTL` | `10m` | 1 to 60 minutes | Life of an auth request. |
| `IDENTITY_OIDC__CODE_TTL` | `60s` | 10 seconds to 10 minutes | Life of an authorization code. |
| `IDENTITY_OIDC__USER_TOKEN_TTL` | `15m` | 1 to 60 minutes | Life of the access tokens and the ID tokens of users. |
| `IDENTITY_CLIENTS_FILE` | empty | | Path of the clients file. Empty means no config clients. |

A service that uses the introspection verifier of `constellation-platform-go` has the setting `MaxCallsPerSecond` (default 20). The identity buckets count the calls of all instances. Thus `MaxCallsPerSecond` x 60 x the number of service instances must be below `introspect_client` and `introspect_ip`. With the defaults (1200 calls per minute for each instance and 6000 per minute for the buckets), 5 instances are possible. An operator with more instances must increase both limits or decrease `MaxCallsPerSecond`.

Telemetry uses the standard `OTEL_*` variables. See the `telemetry` package of `constellation-platform-go`.

The service stops at start with a message that names the variable when a rule fails.

The session cookie has the name `__Host-constellation_session` and the flag `Secure`. A browser accepts a `Secure` cookie on `http://localhost`. Every other host needs TLS. `IDENTITY_ISSUER` has the same rule.

## The clients file

A file with data, not settings. A list of keys does not fit in environment variables, so `IDENTITY_CLIENTS_FILE` gives the path.

```yaml
clients:
  - id: helpdesk
    app: helpdesk
    name: Helpdesk service
    keys:
      - kid: helpdesk-2026-11
        jwk: { kty: EC, crv: P-256, x: "...", y: "..." }
    roles:
      - demo:agent
  - id: admin-ui
    app: identity
    type: public
    name: Admin UI
    redirect_uris:
      - https://admin.example.com/cb
    post_logout_redirect_uris:
      - https://admin.example.com/bye
```

Rules:

- `app` matches `^[a-z][a-z0-9_]{0,31}$`. `id` has the same form, and it can also have hyphens.
- A service client must not have `app: identity`. A public client can have it. An admin UI is a public client with `app: identity`.
- `type` is `service`, `public`, or missing. A missing `type` means `service`.
- A public client has no `keys` and no `roles`. It must have at least one `redirect_uris` value. The `app` of a public client is the audience of its access tokens.
- A service client must not have `redirect_uris` or `post_logout_redirect_uris`.
- Each key is a public EC P-256 JWK. A private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) is an error. `kid` values are unique in a client.
- `roles` is a list of role references `<app>:<role>`. A value that does not match the form, or that occurs two times, is an error. The error names the client and the value.
- `clients: []` is valid.
- An error stops the start. The message names the client and the field.

At each start the service replaces the assignments with the source `config` of each client with the `roles` of the file. An assignment with the source `api` stays. A role that does not exist yet, because its app did not publish the manifest, is a pending assignment. It applies when the manifest arrives, so services can start in any order. Every service client also has the implicit role `identity:service`. See [manifests.md](manifests.md).

### Redirect URIs

The rules for `redirect_uris` and `post_logout_redirect_uris`, in the file and in the API:

1. The URI is absolute. The scheme is `https`, or `http` with the host `localhost`, `127.0.0.1`, or `[::1]`.
2. No fragment, no user information, and no `*`.
3. The host has only letters, digits, dots, and hyphens, or it is an IPv6 literal in brackets. The service puts the origin of the URI into the CSP header of the login page, so a character such as a semicolon, a space, or a comma is not valid.
4. At run time, the scheme, the host, the port, the path, and the query of the request must be equal to a registered URI. The host comparison ignores the case. A trailing slash is a difference.
5. Loopback exception (RFC 8252 section 7.3): a registered `http://127.0.0.1/<path>` or `http://[::1]/<path>` with no port matches any port. A registered URI with a port matches only that port. `localhost` always needs an exact port.

### CORS

The endpoints `/oauth/token`, `/oauth/revoke`, and `/oauth/userinfo` answer CORS requests from the origins of the login redirect URIs of the public clients that are not disabled. For a loopback IP URI with no port, the scheme and the host must be equal, with any port. The service reads the set from the database, with a cache of 5 seconds in each process. A change of a public client by the API is thus active on all instances in 5 seconds or less. The response has `Access-Control-Allow-Methods: GET, POST`, `Access-Control-Allow-Headers: Authorization, Content-Type`, `Access-Control-Max-Age: 600`, and `Vary: Origin`. It never has `Access-Control-Allow-Credentials`. Another origin gets no CORS header.

The only accepted audience of a client assertion is the value of `IDENTITY_ISSUER`. See [tokens.md](tokens.md).

At each start, under a database lock, the service writes each client of the file with the source `config`. A client with the source `config` that is not in the file is set to `disabled`. A client with the source `api` is not changed. If the file has the ID of an `api` client, the service ignores the file entry and writes a `warn` log record.

## Signing key rotation

- On the first start, the service makes one active ES256 key.
- When the active key is older than `ROTATION_PERIOD`, the service makes a `pending` key. The key is in the JWKS at once. It becomes `active` after `PUBLISH_DELAY`.
- The replaced key becomes `retired`. The service deletes its private key at once. Only the public key stays in the JWKS for `RETIRE_AFTER`. Then the service deletes the row.
- Verifiers refresh the JWKS every 10 minutes. The `PUBLISH_DELAY` gives them time to know the new key before it signs.
- The first key of a new install and the key after `rotate-signing-keys --force` have no publish delay. The new key signs at once. A verifier with a cached JWKS does not know the key. It can reject new tokens for up to about 15 minutes. This is the refresh interval of the verifier (10 minutes), the cache reload of the service (1 minute), and the JWKS `max-age` (5 minutes). The tokens are valid. No forgery is possible. The verifier accepts them after its next refresh.

## Recovery after a lost master key

The private signing keys are encrypted with the master key. If the master key is lost, or the start uses another master key, the service stops with this error:

```txt
the active signing key does not decrypt with the master key `<id>`. Use the master key of the install, or run `identity rotate-signing-keys --force`.
```

The service never makes new keys silently after a master key change. To recover without the old master key, run:

```sh
identity rotate-signing-keys --force
```

The command uses the same environment variables as the service. It deletes all signing keys and their secrets, and makes one new active key. All tokens that the old keys signed become invalid, and users must log in again. Without `--force`, the command prints what it will do and exits with code 2.

## Commands

| Command | Use |
| ------- | --- |
| `identity` | Starts the server. |
| `identity healthcheck` | Sends `GET /readyz` to `127.0.0.1` on the port of `IDENTITY_ADMIN__ADDR`. Exit code 0 on 200, 1 in all other cases. The image has no shell, so Compose uses this command. |
| `identity rotate-signing-keys --force` | Replaces all signing keys. |
| `identity setup-link` | Prints a new first-admin setup link. |
| `identity reset-mfa <email>` | Removes the TOTP factor and the recovery codes of the user with the email, and revokes all sessions and refresh token families of the user. It keeps the password and the API tokens. It is the recovery path of the last admin who lost the TOTP device and the recovery codes. Prints `reset`. It connects to PostgreSQL only and runs the migrations first. It writes the audit record with the actor `cli`. Exit code 1 if no user has the email or on an error, 2 for a wrong number of arguments. |
| `identity unlock-login <email>` | Removes the login lock of one email. Prints `unlocked` or `not locked`. It connects to Valkey only. Exit code 1 on an error, 2 for a wrong number of arguments. |
