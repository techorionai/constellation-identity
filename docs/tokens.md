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
| `app` | The key of the app of the service client. It is not the audience. Only access tokens of the client credentials grant have it, with `principal_type` `service`. Exchange tokens, user tokens, and API tokens do not have it. A verifier uses `app` only when `principal_type` is `service`. |
| `scope` | The granted permission keys, separated by spaces |
| `iat`, `nbf` | The time of the request |
| `exp` | `iat` plus 5 minutes |
| `jti` | A new UUID |

A token has one audience. It has only scopes that start with `<audience>:` and that the client has through its roles that are not pending, and through the implicit role `identity:service`. The response has no refresh token. A changed manifest does not change a token that exists. The token ends in 5 minutes at most.

The `app` claim has the app of the client at the time of issue. A change of the app of a client in the clients file takes effect for new tokens only. A token that exists keeps its app for its life of 5 minutes at most. If the app of the client is empty or is not an app key, the service issues no token. The response is `server_error`.

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
| ID token | Only with the scope `openid`. `typ` is `JWT`. Claims: `iss`, `sub`, `aud` (the client ID), `exp`, `iat`, `auth_time`, `amr`, `nonce`, and `sid` (the session ID). `email` and `email_verified` with the scope `email`. `name` with the scope `profile`. |
| Refresh token | Only with the scope `offline_access`. 32 random bytes. The service stores the SHA-256 hash. |

`auth_time` is the time of the last login of the session (`sessions.auth_time`). A login of the same user changes it. It is never `created_at`.

`amr` (RFC 8176) has the methods of the last login of the session: `["pwd"]` for a password only, `["pwd","otp","mfa"]` for a password and a TOTP code, and `["pwd","rec","mfa"]` for a password and a recovery code, `["hwk","user","mfa"]` for a passkey with no password, and `["pwd","hwk","user","mfa"]` for a password and a passkey. The method `hwk` (RFC 8176) is a proof of a key that the user holds, a passkey. The method `user` means that the authenticator verified the user (a PIN or a biometric). A passkey that was used as a second factor with no user verification gives `["pwd","hwk","mfa"]`. A service that needs MFA checks that `amr` has `mfa`. A session with no recorded method (a session from before the upgrade) gives no `amr` claim. The access token of a user from the code flow also has `amr` and `auth_time`, the values of the code. Service tokens, agent tokens, exchange tokens, and API tokens have neither claim. A token with `act` does not satisfy MFA.

The token request for a code runs these checks in order: the client, the read of the code (a read does not delete it), the client of the code, the `redirect_uri`, the `code_verifier`, the session and the user, the claim of the code (`GETDEL`), the marker of the used code, and the tokens. A Valkey fault gives `temporarily_unavailable` (503) and no token. It changes no session.

Reuse of a code: the service keeps a marker for 10 minutes. A request for a used code that has the same `client_id` and a `code_verifier` that matches the marker revokes the session and all refresh token families of the session. A request with another `client_id`, or with a wrong verifier, changes nothing. Only the holder of the verifier can end the session. The counter is `identity.code.reuse`. A `warn` log record has the session ID and the client ID.

### Refresh tokens

- A refresh rotates the token. The response has an access token and a new refresh token. It has no ID token. There is no grace period. A used token that comes back is a reuse, also for two browser tabs at the same time. UI authors must share one refresh in the browser.
- The checks run inside the lock of the family, before the token is marked as used. The client must be the client of the family and not disabled. The user must be `active`. The session must be valid. A failed check changes nothing, so a request with a wrong `client_id` for an unused token does not harm the real client. A used token that comes back is a reuse, also if the `client_id` is wrong, because a used refresh token is secret and shows a copy or a theft. The reuse revokes as in the next item.
- A reuse revokes the family, the session, and all other families of the session. The revoke is committed before the error returns. The counter is `identity.refresh_token.reuse`. A `warn` record has the session ID, the family ID, and the client ID.
- The new access token has the stored scope intersected with the current permissions of the user. A role that an admin takes away has an effect at the next refresh. If no scope remains, `invalid_grant`.
- The optional `scope` can only narrow the stored scope. A token that is not in the stored scope gives `invalid_scope`. The OIDC scopes of the original grant (`openid`, `offline_access`, `email`, and `profile`) are accepted and do not change the access token. The narrower scope applies to that access token only.
- A refresh moves the idle expiry of the session. The new token expires at the absolute expiry of the session.
- A refresh keeps the `amr` and the `auth_time` of the original login (OIDC Core 1.0 section 12.2, RFC 9470 section 6.1). The refresh token family stores both values when the code flow makes it. A later login in the same session (for example a step-up in a second client) does not change an existing family. A family from before the upgrade has no values, so its access token has no `amr` and no `auth_time`.
- A user that needs MFA (the rule "MFA for admins") and whose family has no `mfa` gets `invalid_grant`.
- A re-login of the same user does not stop a stolen refresh token. A user who suspects a theft must log out, or an admin must revoke the sessions.

### Userinfo, revoke, and end session

- `GET /oauth/userinfo` with `Authorization: Bearer <access token>` returns `sub`, `email`, `email_verified`, and `name`. The service verifies the token with its own keys and accepts any audience. An ID token (`typ` `JWT`) gives 401. A service token gives 403 with `insufficient_scope`.
- `POST /oauth/revoke` (RFC 7009). A public client sends `client_id`. A service client uses `private_key_jwt`. A refresh token of the client: its family is revoked. A refresh token of another client: 400 `unauthorized_client` and no change. An unknown token or an access token gives 200. A `token_type_hint` that is not `refresh_token`, `access_token`, or empty gives 400 `unsupported_token_type`.
- `GET /oauth/end_session` with an optional `id_token_hint`. The hint needs a valid signature, the issuer, `typ` `JWT`, and the `aud` of a registered public client. An expired hint is valid. The service revokes the session of the cookie at once only if the hint is valid and its `sid` is the session of the cookie. It then also revokes all refresh token families. Otherwise it shows a confirmation form, and the `POST` of the form (no field) revokes the session of the cookie only. `post_logout_redirect_uri` is used only with the logout at once and only if it is a registered post-logout URI of the client in the hint.
- `POST /logout` revokes the session only. A refresh token of that session fails at the session check.

## Step-up (fresh MFA login)

An operation that changes the MFA of a user (`MeTotp_remove`, `MePasskeys_update`, `MePasskeys_remove`, and `UserMfa_reset`) needs a fresh MFA login: `amr` has `mfa` and `auth_time` is 5 minutes old or less. If the token does not show this, the response is 401 (RFC 9470):

- Content type `application/problem+json`.
- Header `WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A fresh MFA login is necessary", max_age="300"`.
- Body: `type` `about:blank`, `title` `Reauthentication required`, `status` 401, `code` `reauthentication_required`, `detail`, `requestId`, and `traceId`.

A token with no `amr` (a service, agent, exchange, or API token), and a token with `act`, get the same response.

A client must not refresh the token to answer this. A refresh keeps the old `auth_time`. The client starts a new authorization request with `max_age` (and `prompt=login`). The login asks for the password and the second factor. The new code, ID token, and access token have the new `amr` and `auth_time`.

## Fresh login with no second factor

`MeIdentityLinks_remove` needs a fresh login, not a fresh MFA login: `auth_time` is 5 minutes old or less and `act` is absent. It does not check `mfa`. The 401 has the same body as the step-up and the header `WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"`. A token with no `auth_time` and an API token do not satisfy it.

## The claim `amr`

| Login | `amr` |
| ----- | ----- |
| Password | `["pwd"]` |
| Password and TOTP | `["pwd","otp","mfa"]` |
| Password and recovery code | `["pwd","rec","mfa"]` |
| Password and passkey | `["pwd","hwk","mfa"]`, and `["pwd","hwk","user","mfa"]` with user verification |
| Passkey only | `["hwk","user","mfa"]` |
| Google or Microsoft | `["fed"]` |
| Google or Microsoft and TOTP | `["fed","otp","mfa"]` |
| Google or Microsoft and recovery code | `["fed","rec","mfa"]` |
| Google or Microsoft and passkey | `["fed","hwk","mfa"]`, and `["fed","hwk","user","mfa"]` with user verification |

The `auth_time` of the ID token of the upstream provider stays inside the service. No token and no API response has it, and `amr` has no extra value for it. If the ID token had a valid `auth_time` (5 minutes old or less at the login), the service stores this fact in its database: with the session, with the refresh token family, and with the `jti` of each access token that it issues from that session or family (table `upstream_auth_tokens`). `MeIdentityLinks_remove` reads the stored fact through the `jti` of the access token for a user with no local factor. A refresh keeps the fact, because the family stores it. The contract does not change.

## Personal API tokens

A personal API token is a long-lived credential of one user. A user makes, lists, and revokes own tokens with `MeApiTokens_create`, `MeApiTokens_list`, and `MeApiTokens_revoke`. These operations need the access token of a user with the scope `identity:api_token:manage_own`. A service token, a token with an acting principal (`act`), and a `cpat_` value give 403 `user_token_required`. A `cpat_` value as the bearer token on a `/v1` route gives 401, because the `/v1` routes accept JWTs only.

- Each user with the status `active` has the implicit role `identity:user`. It grants `identity:api_token:manage_own`. See [manifests.md](manifests.md). A user with no role can make a token.
- The service records the `amr` of the session that made the token (column `api_tokens.amr`). The API does not show it. The removal of a link revokes the tokens with `fed`, and the removal of a passkey revokes the tokens with `hwk`. A token that was made before the migration `0014` has an empty `amr`, so no removal revokes it. A user can revoke such a token by hand.
- Format: `cpat_` and 43 base64url characters (32 random bytes). The service stores only the SHA-256 hash (hex). The response of create shows the token one time. It has `Cache-Control: no-store`. The service never logs the token or the hash.
- `name` has 1 to 100 characters after trim. `expiresInDays` is an integer from 1 to `IDENTITY_API_TOKEN__MAX_TTL_DAYS`. The default is `IDENTITY_API_TOKEN__DEFAULT_TTL_DAYS`. A bad name, a bad `expiresInDays`, an empty scope, an OIDC scope, and a value that is not a permission key give 400 `invalid_request`.
- `scope` has permission keys. Each key must be in the permissions of the user at the time of create. For each key that is not, the response is 422 with one field error (`field` `/scope`, `code` `scope_not_granted`). A key of the app `identity` is never possible, also for an admin. The reason is that a token with a long life must not carry the highest privilege of the identity service.
- Limits: a user can have `IDENTITY_API_TOKEN__MAX_PER_USER` active tokens (default 50). The create also checks the number of all rows of the user (active, expired, and revoked). It is 10 times the limit above. A user at this limit gets 422 `token_limit` until the retention job removes old rows (7 days after the end of a token).
- Create runs in one transaction under the lock of the user row. The user must have the status `active`. Otherwise the result is 403 `user_token_required` and no row is made. This closes the gap between the disable of a user and the end of the 15 minute access token.
- A revoke of a token of another user, of an unknown ID, or of an ID that is not a UUID gives 404 `api_token_not_found`. A revoke of a token that is revoked already gives 204.
- Each create and each revoke writes the `info` record `identity.api_token.change` with `actor_id`, `operation` (`create` or `revoke`), and `token_id`.
- The retention job `api_tokens` removes a row `IDENTITY_RETENTION__API_TOKENS__PERIOD` after it expired or was revoked.

## Token exchange

The grant `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) lets a service client get a short token for a user, and for an agent that acts for the user. The result has `sub` = the user. With an agent, it has `act` = `{"sub": <agent ID>, "principal_type": "agent"}`. VISION 6.5 and 6.6 describe the use.

### Request

`POST /oauth/token` with a form. The client authenticates with `private_key_jwt` as for the client credentials grant.

| Field | Rule |
| ----- | ---- |
| `subject_token` | Required. An access token of a user that the code flow issued. |
| `subject_token_type` | Required. `urn:ietf:params:oauth:token-type:access_token`. |
| `audience` | Required. One app key with a manifest. Not `identity`. |
| `scope` | Required. Permission keys of the audience. |
| `actor_token` and `actor_token_type` | Optional. They appear together. The token is the ID of an agent, not a signed token. The type is `urn:constellation:params:oauth:token-type:agent-id`. |
| `requested_token_type` | Optional. Only the access token URI. |

Each field has one value. A repeated field gives `invalid_request`.

### Order of the checks

1. A repeated field, a `client_secret` field, an `Authorization: Basic` header, a missing or wrong `client_assertion_type`, or an empty `client_assertion` gives `invalid_request`.
2. Client authentication. Each failure of the client gives 401 `invalid_client`. A failure of the `jti` store gives 503 `temporarily_unavailable`.
3. The client needs the permission `identity:token:exchange` through its roles (the role `identity:admin` has it). Else `unauthorized_client`. This check comes before the check of the parameters.
4. A missing `subject_token`, `subject_token_type`, `audience`, or `scope` (spaces only is missing), or an `actor_token` without `actor_token_type` (or the reverse), gives `invalid_request`.
5. A wrong `subject_token_type`, `requested_token_type`, or `actor_token_type` gives `unsupported_token_type`.
6. An `audience` that is not an app key, that has no manifest, or that is `identity` gives `invalid_target`.
7. The subject token. Each failure gives `invalid_grant` with the same text. The token must have a valid signature, the issuer of the service, and `typ` `at+jwt`. It must not be expired and must not be valid in the future (`nbf`). `principal_type` must be `user`. The `act` member must not be present in any form. `client_id` must name an existing, enabled public client, so an exchanged token (it has the `client_id` of a service client), a service token, and an API token (`cpat_`) are refused. `aud` must be one value that is equal to the `app` of the authenticated client, so a client can exchange only user tokens that were issued for its own app. The user must exist and have the status `active`. The token must have at least 10 seconds of life left.
8. The actor token. It must be a UUID. The agent must exist, be enabled, and belong to the authenticated client. A value that is not a UUID, an unknown agent, a disabled agent, and an agent of another client all give `invalid_grant` with the same text. A value that is not a UUID does not query the database.
9. The scope. The granted scope is the permissions of the user, with the implicit role `identity:user`. With an actor, it is the intersection with the permissions of the agent. A pending role of the agent gives no permission. A requested scope that is not granted, an OIDC scope, and a scope that does not start with `<audience>:` give `invalid_scope`.

### Result

- Claims: `iss`, `sub` (the user), `aud` (the audience), `client_id` (the authenticated client), `scope`, `principal_type` `user`, `jti`, `iat`, `nbf`, `exp`, and `act` if there is an actor.
- The exchange token has no `app` claim, also if the client has an app. It acts for a user, so it must not give the app of the client.
- `exp` is the lower value of `iat` + 5 minutes and the `exp` of the subject token. `expires_in` is at least 10.
- The response has `access_token`, `token_type` `Bearer`, `expires_in`, `scope`, and `issued_token_type`. It has no `refresh_token` and no `id_token`. It has `Cache-Control: no-store` and `Pragma: no-cache`.
- An exchanged token is not valid at `/oauth/userinfo` (401). It cannot call `/v1`, because its audience is never `identity`.

### Errors

| Code | Cause |
| ---- | ----- |
| `invalid_request` | A repeated or missing parameter, a second client authentication method, an actor token without its type. |
| `invalid_client` (401) | The client authentication failed. |
| `unauthorized_client` | The client does not have `identity:token:exchange`. |
| `unsupported_token_type` | A token type is not the expected URI. |
| `invalid_target` | The audience is not valid. |
| `invalid_grant` | The subject token or the agent is not valid. |
| `invalid_scope` | A scope is not in the granted set. |
| `temporarily_unavailable` (503) | The `jti` store or the key cache is not available. |

### Telemetry

`identity.tokens.issued` has `grant_type` `token_exchange`, `principal_type` `user`, and `with_agent`. `identity.token.errors` has `error` and `with_agent`. A user ID or an agent ID is never a metric attribute. Each success writes one `info` record `identity.token.exchange` with `client.id`, `user_id`, `agent_id` (empty without an actor), `audience`, `scope`, and `jti`. Until R09 this record is the only delegation trace. No token, assertion, or actor value is in a log record, a span, or a metric.

## Token introspection

`POST /oauth/introspect` (RFC 7662) tells a service if an API token is active, and for which scopes. The service sends a form.

- The caller is a service client with `private_key_jwt` (`client_assertion_type` and `client_assertion`). A public client, an unknown client, a client secret, and an `Authorization: Basic` header give 401 `invalid_client`. A missing or wrong `client_assertion_type` and an empty `client_assertion` give 401 `invalid_client` too (the token endpoint gives `invalid_request` for these). A repeated form field gives 400 `invalid_request`. A failure of the `jti` store or of PostgreSQL gives 503 `temporarily_unavailable`. The assertion is single-use, like at the token endpoint.
- The caller app is the `app` of the client. The response has only the scopes for this app: the keys of the token that are still in the current permissions of the user, with the prefix `<app>:`. A key of the app `identity` never shows. If no key is left, the token is not active for the caller.
- The token is not active if: it is longer than 512 bytes, it does not have the strict format, no row has its hash, it is revoked, it expires now or earlier, or its user does not have the status `active`. The answer is `{"active": false}` and no other field. The answer is the same for each reason, so the caller cannot learn why. A value with a bad format does not query the database.
- An active answer has `active`, `scope`, `sub` (the user ID), `aud` (the caller app), `exp` and `iat` (Unix seconds, integers), `jti` (the ID of the token), `token_type` `api_token`, and `principal_type` `user`. The response has `Cache-Control: no-store` and `Pragma: no-cache`.
- PostgreSQL is the source of truth for each call. Identity has no cache. A service keeps the result in memory for 60 seconds or less (`auth/introspect` in `constellation-platform-go`). A revoked token can work in a service for this time. A `cpat_` token works in a service that uses `auth.ByFormat` with this verifier.
- The service sets `last_used_at` at the first use, and then at most one time each hour. A failure of this update does not change the answer and writes one `warn` record.
- The counter `identity.introspections` has the attribute `result` (`active`, `inactive`, or `error`). No token, hash, or user ID is in a metric, a span, or a log record. The discovery document has `introspection_endpoint`.
- The service limits `/oauth/introspect` (buckets `introspect_ip` and `introspect_client`) and `MeApiTokens_create` (bucket `api_token_create`). A request over a limit gets status 429 with `Retry-After`. The introspection endpoint gives the OAuth JSON error `temporarily_unavailable`, and `MeApiTokens_create` gives the Problem `rate_limited`. If the counters are not available, the answer is 503 with `Retry-After: 5`. The token endpoint gives the same 429 and 503 answers. The token source of `constellation-platform-go` waits for the `Retry-After` time, up to 60 seconds. See [security.md](security.md) for the buckets.

### Telemetry

`identity.tokens.issued` has the `grant_type` values `client_credentials`, `authorization_code`, `refresh_token`, and `token_exchange`. The counters `identity.code.reuse` and `identity.refresh_token.reuse` count the reuse cases. The values `code`, `code_verifier`, `refresh_token`, `id_token_hint`, `authRequest`, `state`, `nonce`, and `token` are `REDACTED` in the query of a logged or traced URL.
