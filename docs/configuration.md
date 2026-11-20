# Configuration

The service reads its settings from environment variables with the prefix `IDENTITY_`. A double underscore `__` separates the levels of a nested name. A variable with a `_FILE` form reads its value from a file.

## Variables

| Variable | Default | Rule | Use |
| -------- | ------- | ---- | --- |
| `IDENTITY_ISSUER` | required | Absolute URL with no query and no fragment. `https` is required. `http` is accepted only when the host is `localhost`, `127.0.0.1`, or `[::1]`. | Public base URL, for example `https://id.example.com`. It is the `iss` claim of all tokens. |
| `IDENTITY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` | Log level. |
| `IDENTITY_HTTP__ADDR` | `:8080` | | Public listener. |
| `IDENTITY_ADMIN__ADDR` | `:9090` | | Listener for `/livez` and `/readyz`. Do not publish it at the edge. |
| `IDENTITY_ADMIN__CHECK_TIMEOUT` | `2s` | | Time limit of the readiness checks. |
| `IDENTITY_ADMIN__DRAIN_DELAY` | `5s` | | Time that `/readyz` is 503 before the public server stops. |
| `IDENTITY_DATABASE__URL`, `IDENTITY_DATABASE__NAME` | required | platform-go `clients/postgres` rules | PostgreSQL. Also `IDENTITY_DATABASE__URL_FILE`. |
| `IDENTITY_VALKEY__ADDRESS`, `IDENTITY_VALKEY__KEY_PREFIX` | required | platform-go `clients/valkey` rules | Valkey. Use the key prefix `identity`. |
| `IDENTITY_SECRETS__MASTER_KEY` or `IDENTITY_SECRETS__MASTER_KEY_FILE` | required | 32 bytes, base64 | Master key for the envelope encryption of the signing keys. |
| `IDENTITY_SECRETS__MASTER_KEY_ID` | required | `^[a-z0-9-]{1,32}$` | ID of the master key. |
| `IDENTITY_SECRETS__PREVIOUS_KEYS` | empty | `<id>:<base64>` items, separated by commas | Old master keys, for master key rotation. |
| `IDENTITY_KEYS__ROTATION_PERIOD` | `2160h` (90 days) | More than `PUBLISH_DELAY` | Age of the active key before rotation. |
| `IDENTITY_KEYS__PUBLISH_DELAY` | `1h` | 20 minutes or more | Time that a new key is in the JWKS before it signs. It must be more than the refresh interval of the verifiers (10 minutes in `auth/jwt`) plus the key cache reload (1 minute) plus the JWKS `max-age` (5 minutes). |
| `IDENTITY_KEYS__RETIRE_AFTER` | `24h` | 30 minutes or more | Time that a replaced key stays in the JWKS. It must be more than the longest token life (15 minutes) plus the leeway of the verifiers. |
| `IDENTITY_CLIENTS_FILE` | empty | | Path of the clients file. Empty means no config clients. |

Telemetry uses the standard `OTEL_*` variables. See the `telemetry` package of `constellation-platform-go`.

The service stops at start with a message that names the variable when a rule fails.

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
```

Rules:

- `id` and `app` match `^[a-z][a-z0-9_]{0,31}$`.
- A service client must not have `app: identity`.
- `type` is `service` or missing. A missing `type` means `service`.
- Each key is a public EC P-256 JWK. A private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) is an error. `kid` values are unique in a client.
- `clients: []` is valid.
- An error stops the start. The message names the client and the field.

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
