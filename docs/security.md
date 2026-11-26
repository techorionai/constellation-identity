# Security of users and sessions

This page describes how the service protects passwords, logins, sessions, and one-time links. See [first-start.md](first-start.md) for the setup link.

## Passwords

- The service stores an argon2id hash in the PHC string format. The default parameters are memory 64 MiB, 3 passes, 1 thread, a salt of 16 bytes, and a key of 32 bytes. A login with a hash that has other parameters stores a new hash.
- The service changes a password to the NFC form before it checks the length and hashes it.
- A password has 12 to 128 characters after the change. There are no composition rules (NIST SP 800-63B).
- A hash uses 64 MiB. A semaphore limits the hashes that run at the same time to `IDENTITY_PASSWORD__MAX_CONCURRENT`. A request waits for a slot for `IDENTITY_PASSWORD__QUEUE_TIMEOUT`. After that, the page gives status 503 with the text "The service is busy. Try again." and the counter `identity.password.queue_rejected` increases. The counter `identity.password.runs` (attribute `op`: `hash` or `verify`) counts the argon2 computations that ran.

## Login failure limit

- Two counters in Valkey count the login attempts: one for the email (`identity:login:fail:email:<sha256>`) and one for the client IP (`identity:login:fail:ip:<sha256>`). A counter lives for `IDENTITY_LOGIN__FAILURE_WINDOW` from the first attempt. The window does not move at later attempts.
- Before the hash, the login reserves an attempt. One `MULTI`/`EXEC` transaction in Valkey adds 1 to both counters and sets the life with `EXPIRE ... NX`. Thus a counter always has a life, and parallel requests get different values. If a value is more than its limit, the page gives status 429 and no hash runs. The Valkey ACL of the service denies scripts, so the service does not use one.
- An unknown email counts in the same way as a known email. A failed login does not show if the email exists. For an unknown email, the service hashes a constant dummy password, so the response time is about the same.
- A good login deletes the email counter and decreases the IP counter by 1. Thus the IP counter counts failures only, and users behind one NAT address do not lock each other out with good logins. The decrease uses `WATCH` and one `MULTI`/`EXEC` transaction. It never makes the counter less than 0, it never makes a new counter, and it keeps the life of the counter. The attempt stays reserved before the hash, so parallel requests still cannot pass the limit.
- If Valkey is not available, the login fails closed with status 503. No hash runs and no session starts.
- A person can lock out a user with failed logins for the email of that user. The lock ends after the window, or when an operator runs `identity unlock-login <email>`. See "Unlock a login". For IPv6, the IP counter uses the /64 prefix of the address. A second counter uses the /48 prefix. It counts all attempts and has a limit of 16 times the IP limit.

## Rate limits

The service counts requests in Valkey, so all instances use the same counters. Each bucket has a key, a limit, and a window. A window is a fixed period that starts at the first request. The key of a client bucket is the client ID of a verified client assertion. The key of an IP bucket is the client IP. For IPv6, the key is the /64 prefix of the address. A second, coarse key is the /48 prefix. It has a limit of 16 times the limit of the bucket, and it is checked first. A request over the coarse limit gets the error and does not make a key for its /64 prefix. Thus one /48 network cannot get more than 16 times the limit of a bucket, and it can make only a limited number of keys in one window. The Valkey key name has a hash of the key (`identity:rl:<bucket>:<sha256>`). Each key has a life, but the life does not limit the number of keys. An attacker with many /48 networks can make many keys, and with the Valkey policy `noeviction` a full Valkey makes all buckets that fail closed, and the login, give 503. Set `maxmemory` of Valkey with a large margin and monitor `used_memory` and the counter `identity.rate_limit.decisions` with the outcome `error`.

| Bucket | Endpoints | Key | Default limit | When Valkey is down |
| ------ | --------- | --- | ------------- | ------------------- |
| `public_meta` | `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration` | IP | 300 per 1 minute | Fail open |
| `oauth_public` | `/oauth/authorize`, `/oauth/authorize/continue`, `/oauth/end_session` | IP | 60 per 1 minute | Fail closed |
| `oauth_backend_ip` | `POST /oauth/revoke`, `/oauth/userinfo` | IP | 600 per 1 minute | Fail closed |
| `token_ip` | `POST /oauth/token` | IP | 600 per 1 minute | Fail closed |
| `introspect_ip` | `POST /oauth/introspect` | IP | 6000 per 1 minute | Fail closed |
| `token_client` | `/oauth/token` with `client_credentials` or token exchange | Verified client ID | 300 per 1 minute | Fail closed |
| `introspect_client` | `/oauth/introspect` | Verified client ID | 6000 per 1 minute | Fail closed |
| `setup_invite` | `GET` and `POST` of `/setup` and `/invite` | IP | 10 per 15 minutes | Fail closed |
| `api_token_create` | `POST /v1/me/api-tokens` | User ID | 20 per 1 hour | Fail closed |
| `manifest_publish` | `PUT /v1/permission-manifests/{app}` | Client ID of a service caller, or user ID of a user caller | 60 per 1 hour | Fail closed |
| `mfa_verify` | `POST /login/mfa` | IP | 30 per 1 minute | Fail closed |

- The IP buckets run before any database call, hash, or token check. The client buckets run after the signature check of the client assertion. Thus a caller who names a client ID with a bad signature cannot use the budget of that client.
- The grants `client_credentials` and token exchange use one bucket for each client ID, `token_client`. The token source of `constellation-platform-go` uses one wait time for both grants.
- `POST /oauth/introspect` has its own IP bucket. A caller with no credential can send random API tokens to a service, and the service sends one introspection call for each token. With one shared IP bucket, these calls would use up the token budget of the service.
- A cross-site request to `/setup` or `/invite` that is not a navigation (`Sec-Fetch-Site: cross-site` and a `Sec-Fetch-Dest` value that is not `document`) gets 403 and is not counted. The page limit runs after the cross-origin check, so a cross-site page cannot use up the bucket of a victim.
- The own publish of the manifest of the identity service at start is not counted. A CORS preflight request (`OPTIONS`) is not counted.
- Fail open means that the request passes when Valkey does not answer. Fail closed means that the request gets a 503 response with `Retry-After: 5`.
- The login limiter (5 failures for each email and 50 failures for each IP in 15 minutes) is a separate limit. Its IP counter also uses the /64 key for IPv6, and a second counter uses the /48 prefix.

Responses:

| Family | 429 | 503 (Valkey not available) |
| ------ | --- | -------------------------- |
| `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/oauth/userinfo` | OAuth JSON `temporarily_unavailable`, `Retry-After`, `Cache-Control: no-store`, `Pragma: no-cache` | The same body, `Retry-After: 5` |
| Pages (`/oauth/authorize`, `/oauth/end_session`, `/setup`, `/invite`) | HTML "Too many requests. Try again later.", `Retry-After`, the security headers of the pages | HTML "The service is not available. Try again later.", `Retry-After: 5` |
| Discovery and JWKS | Problem `rate_limited`, `Retry-After` | Not applicable (fail open) |
| `POST /v1/me/api-tokens`, `PUT /v1/permission-manifests/{app}` | Problem `rate_limited`, `Retry-After` | Problem `unavailable`, `Retry-After: 5` |

The 429 of an API route has the CORS headers, so a browser can read it. The metric `identity.rate_limit.decisions` counts each decision with the attributes `bucket` and `outcome` (`allowed`, `limited`, `error`, `fail_open`). A rate limit log record has the bucket only. It has no key, IP, email, or user.

A service that uses the introspection verifier of `constellation-platform-go` has a local limit (`MaxCallsPerSecond`) for each process. The identity buckets count the calls of all instances. Thus this rule applies: `MaxCallsPerSecond` x 60 x the number of service instances must be below `introspect_client` and `introspect_ip`. With the default of 20 calls per second (1200 per minute), the defaults of 6000 per minute permit 5 instances. An operator with more instances must increase both limits or decrease `MaxCallsPerSecond`.

Many services behind one NAT share the `token_ip` bucket and the `introspect_ip` bucket. A wrong `IDENTITY_HTTP__TRUSTED_PROXIES` setting puts all users behind one proxy into one IP bucket. A gateway that exchanges one token for each user must increase `token_client`. See [configuration.md](configuration.md) for the variables.

## Unlock a login

A person can lock out a user with failed logins for the email of that user. An operator removes the lock of one email with the subcommand:

```sh
identity unlock-login <email>
```

The command normalizes the email in the same way as the login. It deletes the failure counter of the email in Valkey and does not change the counters of the IPs. It writes `unlocked` or `not locked` to standard output and exits with code 0. A Valkey error gives exit code 1. A wrong number of arguments gives exit code 2. The command writes the log event `identity.login.unlocked` with no email.

## Client IP and trusted proxies

The client IP is the remote address of the connection. If the remote address is in a range of `IDENTITY_HTTP__TRUSTED_PROXIES`, the client IP is the last address of `X-Forwarded-For` that is not in a trusted range. A client can add addresses in front of the header, so the service does not use the first address. Without trusted proxies, the service ignores the header.

Each trusted proxy must append the address of its peer to `X-Forwarded-For`. It must not send a value of the client unchanged, and it must not replace the header with another header, for example `X-Real-IP`. If a trusted proxy sends the header of the client unchanged, the client chooses its own IP address, and it can pass all IP limits or use up the bucket of another address. In nginx, use `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

## Sessions and cookies

- The cookie is `__Host-constellation_session` with the flags `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`. It has no `Domain`.
- The cookie holds 32 random bytes in base64url. The database stores only the SHA-256 hash.
- A session ends at the idle expiry or at the absolute expiry. A logout revokes the session. A login of the same user keeps a valid session, sets a new `auth_time`, and keeps its refresh tokens. The cookie value always changes at a login, and the old value stops in the same statement, so there is no session fixation. A login of a different user revokes the old session and its refresh tokens, and makes a new session. A re-login does not stop a stolen refresh token. A user who suspects a theft must log out, or an admin must revoke the sessions. A re-login near the absolute expiry gives a session that ends soon, because the absolute expiry does not move.
- A session of a user that is not `active` is not valid.
- The service updates the last seen time at most one time each minute.

## CSRF and page headers

- Each `POST` page uses `http.CrossOriginProtection` of the Go standard library, and the cookie has `SameSite=Lax`. A request with `Sec-Fetch-Site: cross-site` gets status 403.
- Each page has these headers: `Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`.
- Each page has the header `Strict-Transport-Security: max-age=31536000` if the request is over https (TLS at the service) or if `IDENTITY_ISSUER` has the scheme `https`. The header has no `includeSubDomains` and no `preload`. A local use over `http` gets no header, so it still works.
- The pages have no JavaScript.
- The `return_to` value of a login must be a local path. The service rejects a control character, a backslash, a scheme, a host, and a path that starts with `//`.

## One-time links

- A setup token and an invite token are 32 random bytes in base64url. The database stores only the SHA-256 hash.
- A use of a token is one SQL statement that sets `used_at`. Two parallel submits cannot use one token.
- `POST /setup` and `POST /invite` read the token before the password checks and before the hash. A token that is not valid gives the error page and no hash runs. Then the transaction uses the token. The setup transaction also checks that no active admin exists. If one exists, the setup fails and the token stays unused.
- The log has no setup link and no token. At the first start, the log has one record with the expiry of the link. The operator gets the link with `identity setup-link`.
- The token is in the query string of the link. `Referrer-Policy: no-referrer` stops leaks to other sites. The page puts the token in a hidden form field. The service replaces the `token` query value with `REDACTED` in the URL that logs and traces see. The service never logs a form body.
- An invite is only for a user with the status `invited`. An invite for an `active` user gives `user_not_invited`. An invite for a `disabled` user gives `user_disabled`. Slice 1 has no password reset. A new invite deletes the older unused invites of the user.
- The service deletes ended tokens and sessions 7 days after they ended (`IDENTITY_RETENTION__*`).

## Code flow

- The service stores the auth request, the code, and the used-code marker in Valkey with `SET`, `GET`, and `GETDEL` only. The ACL of the service denies scripts.
- A code is claimed with `GETDEL`, so two parallel requests cannot both get tokens. A used code with the matching `client_id` and `code_verifier` is a reuse. It revokes the session. A person who knows only a used code cannot end the session.
- A refresh token is a secret, and a used token that comes back shows a copy or a theft. The service revokes the family and the session. All paths lock the session row first, then the family rows in ascending ID order, so a revoke and a refresh cannot deadlock.
- The values `code`, `code_verifier`, `refresh_token`, `id_token_hint`, `authRequest`, `state`, `nonce`, and `token` are `REDACTED` in the query that logs and traces see. The handlers read the real query. The service never logs the form body of an `/oauth/*` request.
- The login page of an auth request adds the origin of the redirect URI to the CSP `form-action`. The service checks the host of each redirect URI, so the origin cannot add a directive. No other page has an extra origin.
- `POST /oauth/end_session` takes the session from the cookie only and ignores the body. A valid `id_token_hint` with another `sid` does not log out the cookie session without the confirmation form.
- The endpoints `/oauth/*` have IP and client rate limits. See "Rate limits".

## Personal API tokens

- The service stores the SHA-256 hash of a token (hex), never the token. The create response shows the token one time with `Cache-Control: no-store`. A list never has the token or the hash. No log record, span, or metric has the token, the hash, or the user ID of an introspection.
- An introspection answer for a token that is not active is the same for each reason, so the caller cannot learn why. An answer for an active token has only the scopes for the app of the caller, never a key of the app `identity`.
- The service checks the format of a value before it looks it up. A value that is longer than 512 bytes or does not have the format `cpat_` and 43 base64url characters is not active and does not query the database.
- A revoke or a disable takes effect at the next introspection. A service keeps a result in memory for 60 seconds or less, so a revoked token can work in a service for this time. Revocation events come later.
- Create takes the lock of the user row and checks that the user is `active`. A user who is disabled cannot make a token with an access token that is not expired. A disable revokes all tokens of the user. An enable does not restore them.
- A token cannot have a key of the app `identity`. The limit of the number of rows of a user (10 times `API_TOKEN__MAX_PER_USER`) stops a loop of create and revoke. The buckets `introspect_ip`, `introspect_client`, and `api_token_create` limit the introspection and the create. See "Rate limits".

## Agents and token exchange

- An agent belongs to one service client. The exchange accepts an agent ID only from that client, and only if the agent is enabled. An unknown agent, a disabled agent, an agent of another client, and a value that is not a UUID give the same `invalid_grant` text. The actor token is an ID, not a signed token. The security comes from the client authentication and from this binding. A stolen client key lets an attacker act as each agent of that client, but only with user tokens that were issued for the app of that client.
- The scope of a token with an agent is the intersection of the scopes of the user and of the agent. A pending role of the agent gives no permission.
- There are no `act` chains. A subject token with `act` (in any JSON form) is refused. An exchanged token is refused as a subject token, because its `client_id` is a service client. A service token and an API token are refused too.
- A subject token must come from an enabled public client, for the app of the authenticated client, for an `active` user, with at least 10 seconds of life left. Thus a holder of a client key cannot move a user token of another app.
- The audience `identity` is refused, so no exchanged token can call the `/v1` API of the identity service.
- `/oauth/userinfo` refuses a token with `act` and a token whose `client_id` is not an enabled public client. An exchanged token for another app cannot read the email or the name of the user.
- An exchanged token lives 5 minutes at most and never longer than its subject token. It has no refresh token. The service does not revoke it. A disable of an agent or a user stops new exchanges only.
- The `info` record `identity.token.exchange` (client, user, agent, audience, scope, and `jti`) is the only delegation trace until R09. It has no token, assertion, or actor value.

## Second factor (MFA)

TOTP (RFC 6238) is a second factor after the password. A user sets it up on the hosted pages. A user with TOTP also has 10 recovery codes.

- Parameters: SHA-1, 6 digits, a period of 30 seconds. A code is good for the step of the time, the step before, and the step after. These are the values that the common authenticator apps support.
- The secret has 20 random bytes. The service seals it with the key ring of the `platform-go` `secrets` package (envelope encryption) and the additional data `identity/totp/<user id>`. The table `user_totp` has the envelope and the key ID, never the secret in clear text. A sealed value that is copied to the row of another user does not open. The secret is never in a log or a span. Before the first code, the setup secret waits in Valkey for 10 minutes. It is sealed there too, with the additional data `identity/totp/setup:<user id>`. After a change of the master key, keep the previous key in `IDENTITY_SECRETS__PREVIOUS_KEYS`, because the rewrap of the secrets service does not see the table `user_totp`.
- Replay guard: the service accepts a code only if its time step is larger than `last_used_step`. One `UPDATE` with `last_used_step < step` makes the check atomic. The same code cannot log in two times. The code of the setup counts as used.
- Recovery codes: 10 codes of 10 characters from the base32 alphabet (50 bits), shown as two groups of 5. The table `recovery_codes` has the SHA-256 hash of the code in upper case with no space and no hyphen. Each code works one time. A new set replaces the old set in one transaction. The pages show the codes one time, with `Cache-Control: no-store`.
- Login: after a good password, a user with a second factor gets no session. The service keeps a pending login in Valkey for 5 minutes and sets the cookie `__Host-constellation_mfa` (`Secure`, `HttpOnly`, `SameSite=Lax`). `POST /login/mfa` takes a TOTP code or a recovery code. A good code removes the pending login (`GETDEL`) and makes or keeps the session with the methods `["pwd","otp","mfa"]` or `["pwd","rec","mfa"]`. A login with a password only gives `["pwd"]`.
- Limits: a pending login has 5 attempts. Then the service removes it. A user has 10 failed tries in 15 minutes (`IDENTITY_MFA__MAX_FAILURES_PER_USER`, `IDENTITY_MFA__FAILURE_WINDOW`). The next try gets status 429 and the code is not checked. If Valkey does not answer, the login fails closed with status 503. A second counter of the user limits 30 failed tries in 24 hours. The first try over a limit sends the security notice `mfa_attempts_limited` through the port `securityevents`, because someone can know the password. The bucket `mfa_verify` (30 per minute for each IP) counts each `POST /login/mfa`. It does not count a `GET`.
- A good password resets the counters of the login failures, also for a user with a second factor. The second factor has its own counters.
- A new login of a user with a second factor goes through `/login/mfa` also when a session exists. The old session keeps its old `amr` and `auth_time` until the second factor is good. A good password alone does not make the session fresh.
- Rule "MFA for admins" (`IDENTITY_MFA__REQUIRE_FOR_ADMINS`, default `true`): a user with the permission `identity:admin` needs MFA. A login of such a user with no second factor makes the session with `["pwd"]` and goes to `/account/totp?required=1`. The authorization request of such a user, and a session with no `mfa`, gets no code. The service sends the user to the setup page (no second factor) or to a new login (second factor). A refresh token family with no `mfa` in its methods gives `invalid_grant`. The rule applies also to sessions and families from before the upgrade.
- Hosted pages: a change of the MFA settings needs a session with an `auth_time` of 5 minutes or less. If the session is older, the page redirects to the login page, and the login asks for all factors. The removal of TOTP and new recovery codes also need the method `mfa` in the session. A user that needs MFA cannot remove TOTP. The pages that show a secret or codes have `Cache-Control: no-store`. The setup page has no script. Its CSP has `img-src 'self' data:` for the QR code.
- The API operations `MeTotp_remove` and `UserMfa_reset` need a token with `mfa` in `amr` and an `auth_time` of 5 minutes or less. A token with `act` (an exchange token) does not satisfy MFA, and an API token does not either. The refusal is 401 `reauthentication_required` with the RFC 9470 challenge. See [tokens.md](tokens.md) and [admin-api.md](admin-api.md).
- An admin cannot reset the own MFA with `UserMfa_reset` (409 `mfa_required`). The recovery path of the last admin is the subcommand `identity reset-mfa <email>`. See [configuration.md](configuration.md).
- Audit entries and security notices: `MeTotp_remove` (audit action `identity:mfa:totp_remove`), `UserMfa_reset`, and the subcommand `reset-mfa` (audit action `identity:mfa:reset`) call the port `securityevents`. It has one method for the audit entry and one for the security notice. The service has no audit store and no email channel yet. The adapter writes one `info` log record for each call (`identity.audit` and `identity.security_notice`). The record has the action, the actor, the target user ID, and the result. It has no email and no secret. Until R08, R09, and R12 replace the adapter, the user gets no real notice, so the operator must keep the logs. A failure of the port is logged and does not undo the change.
- Log events: `identity.mfa.enabled`, `identity.mfa.removed`, `identity.mfa.reset`, `identity.mfa.failed`, and `identity.mfa.recovery_code_used`. The counter `identity.mfa.verifications` has the attributes `method` (`otp`, `rec`) and `outcome` (`ok`, `bad_code`, `replay`, `limited`). The counter `identity.logins` has the outcome `mfa_pending`. No record has a code, a secret, or an email.

## Not in this version

Passkeys and upstream OIDC come with R07. Password reset by email needs R12. Audit entries for logins, for admin changes, for token issue, and for the unlock command come with R08 and R09. Until then the structured log records (`identity.login.ok`, `identity.login.failed`, and others) are the only record.
