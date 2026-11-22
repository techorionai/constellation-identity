# Tokens

The service issues access tokens for service clients with the client credentials grant and `private_key_jwt`. It issues access tokens, ID tokens, and refresh tokens for users with the authorization code flow with PKCE. The sections after "The `/v1` API" describe the user flow.

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
| `invalid_client` | 401 | The assertion is not valid, the client is unknown or disabled, the client is not a service client, or the `jti` was used. |
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

## User tokens and the authorization code flow

Only public clients use the code flow. All clients are first-party, so there is no consent page.

All grants of `/oauth/token` have one rule: a request with a `client_secret`, or with an `Authorization` header with the scheme `Basic`, gives `invalid_request`. A public client sends `client_id` only. A service client that sends the `authorization_code` or `refresh_token` grant gets `invalid_client`. A public client that sends the `client_credentials` grant gets `invalid_client`.

### Authorization request

`GET /oauth/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`. `prompt` and `max_age` are optional.

- An unknown, disabled, or service client, and a `redirect_uri` that does not match, give an error page and no redirect.
- Any other problem redirects to the `redirect_uri` with `error` and `state`. A missing `state` gives `invalid_request` and a redirect with no `state`. A missing `nonce` gives `invalid_request`. The service has no `unsupported_response_type`, so a `response_type` that is not `code` also gives `invalid_request`.
- `scope`: the service drops each token that is not an OIDC scope (`openid`, `profile`, `email`, `offline_access`) and not a permission key of the `app` of the client. If no permission key remains, the result is `invalid_scope`. The access token has the requested keys that the user has through roles that are not pending. Otherwise, `invalid_scope`. The OIDC scopes are valid in the request only. They never go into the `scope` claim.
- `prompt`: `none` and `login` are the values. The service ignores any other value. `none` with any other value gives `invalid_request`. `max_age` is an integer of 0 or more. `max_age=0` has the same effect as `prompt=login`. `prompt=none` with no session, or with a session that does not meet `max_age`, gives `login_required`.
- A valid session that needs no new login gets a code at once. Otherwise the service redirects to `/login?authRequest=<id>`. The auth request is in Valkey for `IDENTITY_OIDC__AUTH_REQUEST_TTL`. After a good login, `GET /oauth/authorize/continue?authRequest=<id>` uses the auth request one time, checks the session, and redirects with the code. If `prompt=login` or `max_age` needed a new login, the `auth_time` of the session must not be earlier than the auth request. Thus a good login ends the flow and there is no loop. A lost or used auth request gives an error page with the text to start again.

### Code, ID token, and access token

The code is 32 random bytes. Valkey holds its record for `IDENTITY_OIDC__CODE_TTL` under the SHA-256 hash of the code.

A client must make the `code_verifier` as RFC 7636 section 4.1 says: a random value of 43 to 128 characters from a cryptographic random source, with at least 256 bits of entropy. A failed check of the token request (client, `redirect_uri`, or `code_verifier`) does not use the code. Thus a short verifier is open to a guess in the life of the code.

| Token | Value |
| ----- | ----- |
| Access token | `aud` is the `app` of the client. `principal_type` is `user`. `sub` is the user ID. `scope` has the granted permission keys. `typ` is `at+jwt`. Life: `IDENTITY_OIDC__USER_TOKEN_TTL` (15 minutes). |
| ID token | Only with the scope `openid`. `typ` is `JWT`. Claims: `iss`, `sub`, `aud` (the client ID), `exp`, `iat`, `auth_time`, `nonce`, and `sid` (the session ID). `email` and `email_verified` with the scope `email`. `name` with the scope `profile`. |
| Refresh token | Only with the scope `offline_access`. 32 random bytes. The service stores the SHA-256 hash. |

`auth_time` is the time of the last login of the session (`sessions.auth_time`). A login of the same user changes it. It is never `created_at`.

The token request for a code runs these checks in order: the client, the read of the code (a read does not delete it), the client of the code, the `redirect_uri`, the `code_verifier`, the session and the user, the claim of the code (`GETDEL`), the marker of the used code, and the tokens. A Valkey fault gives `temporarily_unavailable` (503) and no token. It changes no session.

Reuse of a code: the service keeps a marker for 10 minutes. A request for a used code that has the same `client_id` and a `code_verifier` that matches the marker revokes the session and all refresh token families of the session. A request with another `client_id`, or with a wrong verifier, changes nothing. Only the holder of the verifier can end the session. The counter is `identity.code.reuse`. A `warn` log record has the session ID and the client ID.

### Refresh tokens

- A refresh rotates the token. The response has an access token and a new refresh token. It has no ID token. There is no grace period. A used token that comes back is a reuse, also for two browser tabs at the same time. UI authors must share one refresh in the browser.
- The checks run inside the lock of the family, before the token is marked as used. The client must be the client of the family and not disabled. The user must be `active`. The session must be valid. A failed check changes nothing, so a request with a wrong `client_id` for an unused token does not harm the real client. A used token that comes back is a reuse, also if the `client_id` is wrong, because a used refresh token is secret and shows a copy or a theft. The reuse revokes as in the next item.
- A reuse revokes the family, the session, and all other families of the session. The revoke is committed before the error returns. The counter is `identity.refresh_token.reuse`. A `warn` record has the session ID, the family ID, and the client ID.
- The new access token has the stored scope intersected with the current permissions of the user. A role that an admin takes away has an effect at the next refresh. If no scope remains, `invalid_grant`.
- The optional `scope` can only narrow the stored scope. A token that is not in the stored scope gives `invalid_scope`. The OIDC scopes of the original grant (`openid`, `offline_access`, `email`, and `profile`) are accepted and do not change the access token. The narrower scope applies to that access token only.
- A refresh moves the idle expiry of the session. The new token expires at the absolute expiry of the session.
- A re-login of the same user does not stop a stolen refresh token. A user who suspects a theft must log out, or an admin must revoke the sessions.

### Userinfo, revoke, and end session

- `GET /oauth/userinfo` with `Authorization: Bearer <access token>` returns `sub`, `email`, `email_verified`, and `name`. The service verifies the token with its own keys and accepts any audience. An ID token (`typ` `JWT`) gives 401. A service token gives 403 with `insufficient_scope`.
- `POST /oauth/revoke` (RFC 7009). A public client sends `client_id`. A service client uses `private_key_jwt`. A refresh token of the client: its family is revoked. A refresh token of another client: 400 `unauthorized_client` and no change. An unknown token or an access token gives 200. A `token_type_hint` that is not `refresh_token`, `access_token`, or empty gives 400 `unsupported_token_type`.
- `GET /oauth/end_session` with an optional `id_token_hint`. The hint needs a valid signature, the issuer, `typ` `JWT`, and the `aud` of a registered public client. An expired hint is valid. The service revokes the session of the cookie at once only if the hint is valid and its `sid` is the session of the cookie. It then also revokes all refresh token families. Otherwise it shows a confirmation form, and the `POST` of the form (no field) revokes the session of the cookie only. `post_logout_redirect_uri` is used only with the logout at once and only if it is a registered post-logout URI of the client in the hint.
- `POST /logout` revokes the session only. A refresh token of that session fails at the session check.

### Telemetry

`identity.tokens.issued` has the `grant_type` values `client_credentials`, `authorization_code`, and `refresh_token`. The counters `identity.code.reuse` and `identity.refresh_token.reuse` count the reuse cases. The values `code`, `code_verifier`, `refresh_token`, `id_token_hint`, `authRequest`, `state`, `nonce`, and `token` are `REDACTED` in the query of a logged or traced URL.
