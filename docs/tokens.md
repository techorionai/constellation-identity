# Tokens

The service issues access tokens for service clients with the client credentials grant and `private_key_jwt`. The user flows come in a later issue.

## Access token

The token is a JWT (RFC 9068) with the claims of `AccessTokenClaims` in `constellation-contracts`.

| Part | Value |
| ---- | ----- |
| Header | `typ` is `at+jwt`. `alg` is `ES256`. `kid` is the `kid` of the active signing key. No other member. |
| `iss` | `IDENTITY_ISSUER` |
| `aud` | The audience of the request, as one string |
| `sub`, `client_id` | The client ID |
| `principal_type` | `service` |
| `scope` | The granted permission keys, separated by spaces |
| `iat`, `nbf` | The time of the request |
| `exp` | `iat` plus 5 minutes |
| `jti` | A new UUID |

A token has one audience. It has only scopes that start with `<audience>:` and that the client has through its roles that are not pending, and through the implicit role `identity:service`. The response has no refresh token. A changed manifest does not change a token that exists. The token ends in 5 minutes at most.

## The request

`POST /oauth/token` with `Content-Type: application/x-www-form-urlencoded`.

| Field | Rule |
| ----- | ---- |
| `grant_type` | `client_credentials` |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | The signed assertion |
| `audience` | Required. The key of an app that has a published manifest. |
| `scope` | Required. Permission keys of the audience, separated by spaces. |
| `client_id` | Optional. If it is present, it must be equal to the `sub` of the assertion. |

A request with a client secret, with an `Authorization` header that has the scheme `Basic`, or with a repeated parameter is not valid. The service ignores an `Authorization` header with another scheme, for example a header that a gateway adds.

## The assertion

The client signs the assertion with a private key. The service knows the public key by its `kid`.

- The header has `alg` `ES256` and a `kid` of a key of the client. All other `alg` values are rejected, also `none`.
- `iss` and `sub` are the client ID.
- `aud` is `IDENTITY_ISSUER` (a string, or an item of an array). No other value is accepted. The URL of the token endpoint is not accepted. In Compose the issuer and the token URL are different, so use the issuer.
- `exp` and `iat` are present. `exp - iat` is 5 minutes at most. The leeway is 30 seconds.
- `nbf` is optional. If it is present, it is not in the future.
- `jti` is present and has 256 characters at most. The service accepts a `jti` one time for each client.

## Replay protection

The service records the `jti` after it checks the assertion (the header, the client, the signature, and the claims). It records the `jti` before it checks the audience and the scope. A request that fails the audience check or the scope check has used its `jti`, and the client must sign a new assertion for the next request. The record is a row of the PostgreSQL table `client_assertion_jtis`. The key is the hex SHA-256 of the client ID, a zero byte, and the `jti`. The statement is `INSERT ... ON CONFLICT (key) DO NOTHING` with `expires_at = now() + <ttl>`. A statement that inserts 0 rows is a replay. `ttl` is `max(exp - now + 30 s, 30 s)`. A second use gives `invalid_client`. If PostgreSQL fails, the answer is `temporarily_unavailable` (503) and the service issues no token. Valkey does not hold the `jti`, so a Valkey data loss does not allow a replay. Before each insert, the service deletes up to 100 rows with `expires_at` in the past. A row that expired cannot be a replay, because the service rejects the assertion first.

## Errors

Each error has the body `{"error": "<code>", "error_description": "<text>"}` and the headers `Cache-Control: no-store` and `Pragma: no-cache`. The text has no internal data.

| Code | Status | Cause |
| ---- | ------ | ----- |
| `invalid_request` | 400 | A field is missing or repeated. A client secret is present. |
| `unsupported_grant_type` | 400 | The grant type is not `client_credentials`. |
| `invalid_client` | 401 | The assertion is not valid, the client is unknown or disabled, or the `jti` was used. |
| `unauthorized_client` | 400 | The client is not a service client. |
| `invalid_target` | 400 | The audience is missing, is not an app key, or has no published manifest. |
| `invalid_scope` | 400 | No scope, a scope of another app, or a scope that the client does not have. |
| `temporarily_unavailable` | 503 | The `jti` store (PostgreSQL) or the signing key is not available. |
| `server_error` | 500 | Internal error. |

## Logs

The assertion, the token, and the form body never go to a log, a span, or an error text. A failed request writes one `warn` record with `error_code` and the client ID. The field is `client.id` after the signature check passed, and `client.id_unverified` before. Metrics: `identity.tokens.issued` (attributes `grant_type`, `principal_type`) and `identity.token.errors` (attribute `error`).

## The `/v1` API

Each `/v1` route runs `auth.Middleware` and then `auth.RequireScopes` with the `x-required-scopes` list of the operation. The token must have all scopes of the list. The audience is `identity`. At start, the service reads the list of each operation from the OpenAPI file. An operation with no list stops the start. Only `GET /v1/me` has an empty list.

The in-process verifier reads the signing keys from the key cache of the process. It does not call the network. `AllowInsecureHTTP` is true only when the issuer uses `http` with the host `localhost`, `127.0.0.1`, or `[::1]`.

The permission `identity:admin` has two segments. Only the role `admin` holds it. The operations that change clients need `identity:client:write` and `identity:admin`.
