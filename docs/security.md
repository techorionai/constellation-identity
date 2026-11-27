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
| `passkey` | `POST /login/passkey/options`, `POST /login/passkey/finish`, `POST /login/mfa/passkey/options`, `POST /login/mfa/passkey/finish`, `POST /account/passkeys/options`, `POST /account/passkeys/finish` | IP | 30 per 1 minute | Fail closed |
| `token_denied` | The denied audit entry of `POST /oauth/token` (a gate, not a request limit) | IP | 30 per 1 minute | In-process limit |
| `token_denied_daily` | The same entries | IP | 1000 per 24 hours | In-process limit |
| `token_denied_global` | The same entries | One key `all` | 100000 per 24 hours | In-process limit |
| `token_denied_client` | The same entries of a registered client | Client ID | 600 per 1 hour | In-process limit |

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

The command normalizes the email in the same way as the login. It deletes the failure counter of the email in Valkey and does not change the counters of the IPs. It also writes the audit entry `identity:login:unlock` in PostgreSQL, so it needs the database variables `IDENTITY_DATABASE__*` and runs the migrations first. It writes `unlocked` or `not locked` to standard output and exits with code 0. A Valkey error or a database error gives exit code 1. A wrong number of arguments gives exit code 2. The command writes the log event `identity.login.unlocked` with no email.

## Audit entries

The service writes an audit entry for each change of its data. The entry is a CloudEvent of the type `identity.audit.recorded` on the Valkey stream `audit.stream:identity`. The writer of `platform-go` writes it in the same PostgreSQL transaction as the change, so no change has no entry. If the write fails, the transaction rolls back and the request gets 503 with the code `unavailable`. A request that fails a validation (422) or does not change data writes no entry. A change that changes nothing writes no entry, for example a publish of the same manifest or an update with no changed field.

### Actor

The writer takes the actor only from the authenticated principal of the context. A command cannot set the actor.

| Flow | Principal in the context | Actor | `details.origin` |
| ---- | ------------------------ | ----- | ---------------- |
| Admin API and account API | The token principal | The user, client, or agent of the token | None |
| Page with an account session | The user of the session | The user, type `user` | None |
| `AcceptInvite`, `CompleteSetup`, set password with a one-time link | None | `identity`, type `service` | `invite` or `setup`. The value `password_link` is reserved |
| Subcommand `reset-mfa` | None | `identity`, type `service` | `cli` |
| Own manifest publish at the start, sync of the clients file | None | `identity`, type `service` | None |

A page handler puts the user into the context only after it checked the session. The one-time link flows have no session, so `target` gives the user and `details.origin` gives the flow.

### Entries

| Command | Action | Target type | Details |
| ------- | ------ | ----------- | ------- |
| Remove TOTP | `identity:mfa:totp_remove` | `user` | None |
| Reset MFA (API and subcommand) | `identity:mfa:reset` | `user` | None (API), `origin` (subcommand) |
| Passkey add, rename, remove | `identity:mfa:passkey_add`, `identity:mfa:passkey_rename`, `identity:mfa:passkey_remove` | `user` | `passkeyId`. Rename also `oldName` and `newName` |
| Link add, remove | `identity:identity_link:add`, `identity:identity_link:remove` | `user` | `provider`. `origin` for a link of an invite |
| Set password | `identity:password:set` | `user` | None. The value `origin` `password_link` is reserved for a future one-time link flow |
| Create user, update user | `identity:user:create`, `identity:user:update` | `user` | `fields` (the names of the fields) |
| Create invite, accept invite | `identity:invite:create`, `identity:invite:accept` | `user` | `origin` (accept) |
| Complete setup | `identity:setup:complete` | `user` | `origin` |
| Assign or remove a user role | `identity:user_role:assign`, `identity:user_role:remove` | `user` | `role` |
| Revoke a session, revoke all sessions | `identity:session:revoke`, `identity:session:revoke_all` | `session`, `user` | `sessions` (the number, for all sessions) |
| Create client, update client | `identity:client:create`, `identity:client:update` | `client` | `type` and `app` (create), `fields` (update) |
| Add or remove a client key | `identity:client_key:add`, `identity:client_key:remove` | `client` | `kid` |
| Assign or remove a client role | `identity:client_role:assign`, `identity:client_role:remove` | `client` | `role` |
| Sync of the clients file | `identity:client:sync` | `client` | `fields`, and `disabled` (the new state) if `fields` has `disabled` |
| Create agent, update agent | `identity:agent:create`, `identity:agent:update` | `agent` | `clientId` (create), `fields` (update) |
| Assign or remove an agent role | `identity:agent_role:assign`, `identity:agent_role:remove` | `agent` | `role` |
| Create or revoke an API token | `identity:api_token:create`, `identity:api_token:revoke` | `api_token` | `scopes` (create) |
| Publish a manifest that changes | `identity:manifest:publish` | `manifest` (the app) | `version`, `permissions`, `roles` (the counts) |

An update lists only the fields whose stored value changed. An update or a role assign that changes nothing writes no entry. Each entry has the result `success`, except the entries of the next section. `details` has IDs, names, and the names of changed fields only. It has no password, secret, token, TOTP secret, recovery code, private key, or email address. The audit data is personal data, and it stays 7 days in the outbox and in the stream by default. The entry has the request ID, the client IP, and the user agent of the request, if they agree with the contract. The writer leaves out a bad value and still writes the entry.

### Signing keys, tokens, logins, and operator commands

These entries have the result `success`, except the entries that the table marks `denied`. The actor of each entry is the verified principal of the context. A flow with no principal has the actor `identity` (type `service`).

| Action | Action key | Target | `details` |
| ------ | ---------- | ------ | --------- |
| Create a signing key | `identity:signing_key:create` | `signing_key` (the `kid`) | `kid`, `algorithm`, `state` |
| Activate a signing key | `identity:signing_key:activate` | `signing_key` | `kid`, `previousKid` |
| Retire a signing key | `identity:signing_key:retire` | `signing_key` | `kid` |
| Delete a signing key | `identity:signing_key:delete` | `signing_key` | `kid`, `forced` |
| Forced rotation | `identity:signing_key:force_rotate` | `signing_key` (the new `kid`) | `deletedKeys`, `newKid`, `origin` |
| Issue a token | `identity:token:issue` | `client` (client credentials), `user` (other grants) | `grant`, `clientId`, `audience`, `scopes`, `jti`, `expiresAt`, and `agentId` and `subjectType` (token exchange) |
| Refuse a token request (`denied`) | `identity:token:issue` | `client`, only for a client that exists. `user` for a refresh token reuse. | `grant`, `reason`, `clientId` (only for a client that exists, and the client of the family for a refresh token reuse), and `familyId` and `sessionId` (refresh token reuse) |
| Log in | `identity:session:login` | `user` | `method` (`password`, `upstream`, `passkey`), `mfa` (`totp`, `passkey`, `recovery_code`) |
| Refuse a login or a second factor (`denied`) | `identity:session:login` | `user`, only for a known email | `method`, `mfa`, `reason` |
| Unlock a login | `identity:login:unlock` | `user`, only for a known email | `origin`, `knownUser`, `wasLocked` |
| Make a setup link | `identity:setup:link_create` | None | `origin`, `expiresAt` |
| Store an upstream client secret | `identity:idp:secret_set` | `idp_provider` | `provider`, `origin` |

Actor of each flow:

| Flow | Actor | `details.origin` |
| ---- | ----- | ---------------- |
| Automatic key action (ticker, startup) | `identity` (`service`) | None |
| Operator command (`rotate-signing-keys --force`, `unlock-login`, `setup-link`, `set-idp-secret`) | `identity` (`service`) | `cli` |
| Token issue after the client authentication | The client (`service`) or, for a token exchange with an agent, the agent (`agent`) | None |
| Token request with `invalid_client` | `identity` (`service`) | None |
| Login success | The user (`user`) | None |
| Login denied, failed second factor | `identity` (`service`) | None |

Rules:

- A key change and its entry commit in one transaction. The secret store call stays outside the transaction. A secret with no row is deleted at the next pass. The forced rotation stores the new secret first. One transaction then deletes the rows, inserts the new row, and writes the entries. The old secrets go after the commit. If the transaction fails, the old keys stay. A failed delete of an old secret after the commit gives an error log record and no error of the command, because the rotation is done. The next pass deletes the secret.
- A token is never issued without its entry. A writer error gives 503 and no token. The authorization code path and the refresh path write the entry in the transaction of the refresh token. The client credentials path and the token exchange path use a short transaction. The entry has the `jti`, never the token text.
- A token request that fails with `invalid_client`, `invalid_grant` (also a refresh token reuse, with the reason `refresh_token_reuse`), `unauthorized_client`, or `invalid_scope` writes an entry with the result `denied` and `details.reason`. The entry of a refresh token reuse is in the same transaction as the revocation. It has the client and the user of the reused family, not the `client_id` of the request. If its writer fails, the revocation rolls back and the response is `temporarily_unavailable`. A request with `invalid_request` or `unsupported_grant_type` writes no entry. A request that a rate limit stops writes no entry. The gate of the section "Denied token requests" controls the number of denied token entries. If the writer fails for a `denied` entry, the response stays the OAuth error, and the service writes the log record `identity.audit.failed` with the action and the reason only.
- A login that the login limiter stops writes no entry. A denied login has the target user only when the email is known. No entry has an email address. The entry of a login with a second factor is written when the second factor step works, in the transaction of the session.
- Introspection calls and JWKS reads write no entry.
- An operator command writes only the row of the audit outbox. It runs no audit relay. The relay of a running service publishes the entry to `audit.stream:identity`. If no service instance runs, the entry stays in the outbox until an instance starts.
- `unlock-login` opens PostgreSQL and runs the migrations, the same as the other subcommands. It deletes the Valkey counter inside the transaction and commits only after the delete works. If the commit fails after the delete, the user can log in again and no entry exists. The command then writes the log record `identity.audit.failed` with the user ID and exits with code 1.
- The cost: each token issue adds one insert in a short transaction. A full database stops the token issue.

### Denied admin requests

Take an admin route (all `/v1` routes except `/v1/me`). A principal can lack a scope of the route. Then the request writes an entry. The entry has the result `denied`, the action of the route, and no target. `details.missingScopes` has the missing scopes. The step runs between the token check and the scope check. The answer is 403 in all cases. The step does not read the response status.

`details.missingScopes` has the scopes that the principal does not have. A route that only reads data also writes an entry, with an action such as `identity:user:read`. The entry has no secret.

Two buckets limit this step, with the principal ID as key. The bucket `admin_denied` allows 30 requests in 1 minute. The bucket `admin_denied_daily` allows 1000 requests in 24 hours. A request over a limit gets 429 with `Retry-After` and writes no entry. The service writes the log record `identity.audit.denied_dropped` for each dropped entry, with the action, the principal ID, and the reason. If Valkey does not answer, a small limit in the memory of each process applies instead (10 entries in 1 minute for each principal, and a maximum of 10000 principals). An entry over that limit is dropped with the same log record. The answer is 403 in these cases. The limits stop a user with no admin scope from filling the outbox and the stream. With `IDENTITY_RATE_LIMIT__ENABLED=false` the step has no shared limit, and the limit in the memory is not used. Each dropped entry also adds 1 to the counter `identity.audit.denied_dropped` with the reasons `rate_limit_admin_denied`, `rate_limit_admin_denied_daily`, and `fallback_limit`.

### Denied token requests

A failed token request with `invalid_client`, `invalid_grant`, `unauthorized_client`, or `invalid_scope` needs no login. An attacker can send many of them with no credentials, for example with an assertion that cannot be parsed, an unknown `client_id`, or a random refresh token. The token IP limit of 600 requests in 1 minute is the only limit before this gate. The gate controls the number of `denied` entries. It does not change the OAuth response. The caller gets the same error with or without an entry.

The gate runs before the entry transaction, for the denied entry of all four grants. A request that names a client ID that exists goes through the buckets `token_denied` and `token_denied_client`. All other requests go through the buckets `token_denied`, `token_denied_daily`, and `token_denied_global`. The first bucket that refuses stops the check, and the service writes no entry.

- `token_denied`: 30 entries in 1 minute for each client IP.
- `token_denied_daily`: 1000 entries in 24 hours for each client IP.
- `token_denied_global`: 100000 entries in 24 hours for all clients. It has one key, `all`. It puts a bound on the memory when an attacker uses many IP addresses. 100000 entries of approximately 1 KB are approximately 100 MB.
- `token_denied_client`: 600 entries in 1 hour for each registered client. The key is the client ID. Only a registered client has such a key, so the number of keys has a bound. A caller who uses up the global bucket does not use up this bucket. A caller who names a client ID with a bad signature can use the budget of that client, but only if the caller sends the requests from many IP addresses, because `token_denied` limits each IP address first.

The two IP buckets use the same keys as the other IP buckets (an IPv4 address, or an IPv6 /64 prefix with a coarse /48 key at 16 times the limit). A request with no client IP has no IP key, and only the global bucket applies, because all such requests would share one key. Each new IPv6 /64 prefix makes a `token_denied_daily` key with a life of 24 hours. The coarse key limits one /48 prefix to 16000 such keys in 24 hours (approximately 2 MB). When a bucket refuses, the gate keeps the refusal in memory until the wait time of the bucket ends. In that time the gate makes no call to the shared limiter for the same bucket and key, so a flood of new IP prefixes makes no new key after a refusal. The table of kept refusals has a maximum of 10000 entries. The login entries and the refresh token reuse entry do not go through the gate. The login limiter limits the login entries, and a reuse entry needs a real used refresh token.

If Valkey does not answer, a limit in the memory of each process applies. It allows 10 entries in 1 minute for each client IP, 600 entries in 1 minute in total, and 100000 entries in 24 hours in total. The table has a maximum of 10000 IP keys. When it is full, a new key gets no entry. The table is scanned for old keys at most one time each second. A request with no client IP uses only the totals. A registered client has its own in-process limit of 60 entries in 1 minute, with no total, so the totals do not stop it. The same limit applies when `IDENTITY_RATE_LIMIT__ENABLED=false`, because the gate protects the Valkey memory and the outbox, not the request rate. With N instances, the total bound is N times these values.

Each dropped entry adds 1 to the counter `identity.audit.denied_dropped` with the attributes `action` and `reason`. The reason is `rate_limit_token_denied`, `rate_limit_token_denied_daily`, `rate_limit_token_denied_global`, `rate_limit_token_denied_client`, or `fallback_limit`. The denied admin step uses the same counter with the reasons `rate_limit_admin_denied`, `rate_limit_admin_denied_daily`, and `fallback_limit`. The gate writes the log record `identity.audit.denied_dropped` with `action`, `reason`, and `dropped` (the number of drops since the last record) a maximum of one time each minute for each action and reason. It writes no `identity.rate_limit.limited` record. No IP and no client ID go into the metric or the log record. An attacker can use the global bucket and stop the denied token entries of unknown callers for 24 hours. The entries of registered clients still pass. The counter still shows the volume, and an operator can change the limit.

## Client IP and trusted proxies

The `clientinfo` middleware of `platform-go` finds the client IP of each request. It is the only code that reads `X-Forwarded-For`. The rate limits, the pages, and the audit entries read the result from the context. Thus all of them use the same address. The middleware removes the zone of an IPv6 address and the IPv4-mapped form. It runs first on the public handler, before the rate limit.

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
- Only three pages use JavaScript: `/login`, `/login/mfa`, and `/account/passkeys`. They use one first-party file, `GET /assets/passkey.js`, and only when passkeys are on. The file has no third-party code, no inline script, and no `eval`. The CSP of these pages has `script-src 'self'` and `connect-src 'self'`. All other pages keep the CSP with no `script-src`. The password login works with no JavaScript. The JSON routes of the passkeys accept only `Content-Type: application/json` (else 415) and a body of 64 KiB or less (else 413).
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
- Login: after a good password, a user with a second factor gets no session. The service keeps a pending login in Valkey for 5 minutes and sets the cookie `__Host-constellation_mfa` (`Secure`, `HttpOnly`, `SameSite=Lax`). `POST /login/mfa` takes a TOTP code or a recovery code. A good code removes the pending login (`GETDEL`) and makes or keeps the session with the methods `["pwd","otp","mfa"]` or `["pwd","rec","mfa"]`. A login with a password only gives `["pwd"]`. After an upstream login, the first factor is `fed` in place of `pwd` (see the section on the upstream login).
- Limits: a pending login has 5 attempts. Then the service removes it. A user has 10 failed tries in 15 minutes (`IDENTITY_MFA__MAX_FAILURES_PER_USER`, `IDENTITY_MFA__FAILURE_WINDOW`). The next try gets status 429 and the code is not checked. If Valkey does not answer, the login fails closed with status 503. A second counter of the user limits 30 failed tries in 24 hours. The first try over a limit sends the security notice `mfa_attempts_limited` through the port `securitynotices`, because someone can know the password. The bucket `mfa_verify` (30 per minute for each IP) counts each `POST /login/mfa`. It does not count a `GET`.
- A good password resets the counters of the login failures, also for a user with a second factor. The second factor has its own counters.
- A new login of a user with a second factor goes through `/login/mfa` also when a session exists. The old session keeps its old `amr` and `auth_time` until the second factor is good. A good password alone does not make the session fresh.
- Rule "MFA for admins" (`IDENTITY_MFA__REQUIRE_FOR_ADMINS`, default `true`): a user with the permission `identity:admin` needs MFA. A login of such a user with no second factor makes the session with `["pwd"]` and goes to `/account/totp?required=1`. The authorization request of such a user, and a session with no `mfa`, gets no code. The service sends the user to the setup page (no second factor) or to a new login (second factor). A refresh token family with no `mfa` in its methods gives `invalid_grant`. The rule applies also to sessions and families from before the upgrade.
- Hosted pages: a change of the MFA settings needs a session with an `auth_time` of 5 minutes or less. If the session is older, the page redirects to the login page, and the login asks for all factors. The removal of TOTP and new recovery codes also need the method `mfa` in the session. A user that needs MFA cannot remove TOTP. The pages that show a secret or codes have `Cache-Control: no-store`. The TOTP setup page has no script. Its CSP has `img-src 'self' data:` for the QR code.
- The API operations `MeTotp_remove` and `UserMfa_reset` need a token with `mfa` in `amr` and an `auth_time` of 5 minutes or less. A token with `act` (an exchange token) does not satisfy MFA, and an API token does not either. The refusal is 401 `reauthentication_required` with the RFC 9470 challenge. See [tokens.md](tokens.md) and [admin-api.md](admin-api.md).
- An admin cannot reset the own MFA with `UserMfa_reset` (409 `mfa_required`). The recovery path of the last admin is the subcommand `identity reset-mfa <email>`. See [configuration.md](configuration.md).
- Audit entries and security notices: `MeTotp_remove` (audit action `identity:mfa:totp_remove`), `UserMfa_reset`, and the subcommand `reset-mfa` (audit action `identity:mfa:reset`) write an audit entry in the transaction of the change (see [Audit entries](#audit-entries)). They also send a security notice through the port `securitynotices`. The service has no email channel yet. The adapter writes one `info` log record for each notice (`identity.security_notice`). The record has the kind, the target user ID, and the time. It has no email and no secret. Until R12 replaces the adapter, the user gets no real notice, so the operator must keep the logs. The service logs a failure of the notice. The failure does not undo the change.
- Log events: `identity.mfa.enabled`, `identity.mfa.removed`, `identity.mfa.reset`, `identity.mfa.failed`, and `identity.mfa.recovery_code_used`. The counter `identity.mfa.verifications` has the attributes `method` (`otp`, `rec`) and `outcome` (`ok`, `bad_code`, `replay`, `limited`). The counter `identity.logins` has the outcome `mfa_pending`. No record has a code, a secret, or an email.

## Passkeys

A passkey (WebAuthn, `github.com/go-webauthn/webauthn`) is a login method and a second factor. A user registers passkeys on `/account/passkeys`. A user can have 10 passkeys.

- Relying party: the RP ID is the host of `IDENTITY_ISSUER` with no port. The allowed origin is the scheme, the host, and the port of the issuer. A change of the issuer host makes all passkeys useless. If the issuer host is an IP address, the service turns passkeys off and writes one `warn` log record at start, because WebAuthn does not accept an IP address as the RP ID.
- Registration: the service asks for a resident key, user verification `required`, attestation `none`, and the algorithms EdDSA, ES256, and RS256. It does not check the model of the authenticator. It excludes the passkeys that the user has already. A registration needs a session with an `auth_time` of 5 minutes or less. The state of the ceremony waits in Valkey for 5 minutes and the service reads it one time (`GETDEL`).
- Login with no password: the page `/login` has a button "Log in with a passkey". The ceremony uses no `allowCredentials` and user verification `required`. The cookie `__Host-constellation_webauthn` (`Secure`, `HttpOnly`, `SameSite=Strict`, 5 minutes) binds the challenge to the browser. The service finds the credential by the credential ID and the user by the user handle. Both must fit. The user must be active. Each refusal gives the same text, "The passkey is not valid". The session gets the methods `["hwk","user","mfa"]`. The login limiter does not change.
- Second factor: after a good password, a user with a passkey can use it on `/login/mfa`. The ceremony lists the passkeys of the user and asks for user verification `preferred`, so a security key with no PIN works. The session gets `["pwd","hwk","mfa"]`, and `user` if the authenticator verified the user. The attempt limit and the failure counters of the TOTP check apply. The counter `identity.mfa.verifications` has the method `hwk`.
- User handle: 32 random bytes that the service makes at the first registration. It is not the user ID and not the email.
- Sign count (WebAuthn Level 3 section 7.2): the rule applies when the new count or the stored count is not 0. Then the new count must be larger. Else the service refuses the login and writes the log record `identity.passkey.clone_warning`. One `UPDATE ... WHERE sign_count < new` makes the check atomic, so two parallel logins with the same count cannot both pass.
- Rule "MFA for admins": a passkey that the service accepts is a second factor. An admin with a passkey and no TOTP satisfies the rule. An admin with no factor goes to `/account/totp?required=1`. That page has a link to `/account/passkeys?required=1`. After the registration, the session gets `hwk`, `user`, and `mfa`, and the login continues.
- Passkeys off (`IDENTITY_WEBAUTHN__ENABLED=false` or an IP issuer): the hosted passkey routes and `GET /assets/passkey.js` give 404, and the pages show no passkey button. The four API operations stay. A stored passkey does not count as a second factor for `MfaStatus.enabled`, the login, the setup target, and the rule for admins.
- Rename and removal: the hosted forms (no script) and the API need a fresh MFA login (5 minutes). A removal that leaves a user with no accepted second factor, where the policy needs MFA, gives 409 `mfa_required`. The removal of TOTP and the recovery codes does not remove passkeys. After a TOTP removal, the sessions and the refresh token families of the user lose `otp` and `rec`. They lose `mfa` only if they do not have `hwk`. After a passkey removal, the service revokes all sessions and all refresh token families of the user that have `hwk` in `amr`, also the session of the page. The service does not record which passkey made a session. A user must log in again on all devices. `UserMfa_reset` and `identity reset-mfa` remove TOTP, the recovery codes, and all passkeys, and revoke all sessions. A passkey removal also revokes the personal API tokens that a session with `hwk` made. The rule "last login method" applies (409 `last_login_method`, after `mfa_required`).
- Recovery: a user with passkeys only has no recovery codes. The recovery paths are a second passkey, TOTP, `UserMfa_reset` by an admin, and `identity reset-mfa <email>`. Register at least two passkeys.
- Audit entries and security notices: each change of the passkeys writes an audit entry in the transaction of the change. A registration writes `identity:mfa:passkey_add`. A rename writes `identity:mfa:passkey_rename` with the old name and the new name. A removal writes `identity:mfa:passkey_remove`. The registration and the removal also send a notice (`mfa_passkey_added` and `mfa_passkey_removed`) through the port `securitynotices`.
- Log events and metrics: `identity.passkey.registered`, `identity.passkey.removed`, `identity.passkey.refused`, and `identity.passkey.clone_warning`. The counter `identity.passkey.ceremonies` has the attributes `type` (`register`, `login`, `second_factor`) and `outcome` (`ok`, `bad_signature`, `bad_origin`, `unknown_credential`, `clone_warning`, `limited`, `expired`). No record has a credential ID, a public key, a challenge, or a user handle.

## Upstream login (Google and Microsoft)

A user can log in with a Google account or a Microsoft work account. The service is a client of the provider. It uses `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` and no other OIDC code. The service is not an OIDC provider library. A provider is on when the operator sets its client ID (see [configuration.md](configuration.md)).

- Explicit links only. A user links an upstream account on `/account/security` after a local login, or when the user accepts an invite. There is no self sign-up and no link by email. The login finds the user by the link (provider and subject key) only. It never looks up the email, so an attacker with an upstream account that has the email of a user gets no session ("This account is not linked"). The subject key is `sub` for Google and `<tid>:<oid>` for Microsoft. It is never shown and never in a log.
- Invite with an upstream account: `/invite` shows "Accept with Google" and "Accept with Microsoft". The verified email of the upstream account (normalized) must be the email of the invited user. Google needs `email_verified` true. Microsoft needs the optional claim `xms_edov` true (see [first-start.md](first-start.md)). If not, the page says "This account does not match the invitation." and the invite token stays valid. A user that accepts an invite with an upstream account has no password. The page `/account/security` has "Set a password" (a fresh session is necessary).
- The flow: the start `GET /login/oidc/{provider}?purpose=login|link|invite` checks the request and makes a flow record in Valkey (`idp:flow:<sha256(state)>`, 10 minutes). The record has the state, the nonce, the PKCE verifier (S256), and the hash of the binding cookie (`Secure`, `HttpOnly`, `SameSite=Lax`) that binds the flow to the browser. The name of the cookie is `__Host-constellation_idp_` and the first 16 characters of the hash of the state. Thus a second flow in another tab has its own cookie and does not replace the cookie of the first flow. The callback `GET /login/oidc/{provider}/callback` takes the record with `GETDEL`, so a state works one time. A wrong state, a used state, and a cookie of another browser give "The login expired. Try again." The response mode is `query`, so the callback is a top-level GET. A request with a wrong state does not clear the cookie.
- ID token checks: the signature, the issuer, the audience, the expiry, and the nonce. The service refuses more than one audience, and an `azp` that is not the client ID. Google must send the `iss` parameter (RFC 9207), and it must be `https://accounts.google.com`. Microsoft does not support it, so the service ignores it. With `ALLOWED_DOMAINS`, a Google token needs an `hd` claim in the list. The service asks for the scope `openid email profile` only, with no offline access, and it does not keep or log the access token or the refresh token of the provider.
- Microsoft: the configuration refuses the tenants `common` and `consumers`, because they allow personal accounts. With a tenant GUID, the issuer is exact and the token `tid` must be the tenant. With `organizations`, the discovery issuer has the text `{tenantid}`, so the service does its own checks: `tid` is a GUID, `iss` is `https://login.microsoftonline.com/<tid>/v2.0`, and a signing key with an `issuer` property is good only for the same `iss` (a key with the text `{tenantid}` after the replacement by the `tid`). `go-oidc` does not read the `issuer` property of a key, so the service reads the JWKS with its own code in this case. A key with no `issuer` property needs the first and third checks only, as the Microsoft text limits only keys that have the property.
- Fresh login: a login page with `prompt=login` and the purpose `link` send `prompt=login` to Microsoft and `prompt=select_account` to Google. The callback checks that the Microsoft `auth_time` (else `iat`) or the Google `auth_time` is 5 minutes old or less. Accepted risk: the Google documents have no forced login and no `max_age`. A person at an unlocked browser with an active Google session can pass the fresh check with one click on the account choice. A user with a local second factor always needs the factor.
- Local factor before a link and before a link removal: the fresh login check cannot stop a holder of a young stolen session, because Google sends no `auth_time` and can ignore the prompt. Thus the service asks for a local factor of the user. The local factors are the password, a TOTP code or a recovery code, and a passkey. For a link, the page `/account/identity-links/{provider}/link` asks for the password, a code, or a passkey. The check uses the failure counters of the second factor. The passkey check uses the WebAuthn second factor ceremony of the service. The routes `POST /account/identity-links/passkey/options`, `POST /account/identity-links/passkey/link`, and `POST /account/identity-links/passkey/remove` are JSON routes of the script. The state of the ceremony waits in Valkey for 5 minutes, bound to the hash of the session cookie, and the service reads it one time. A response with another session, another user, a key that the user does not have, or a sign count that did not advance gives no proof. After a good check, the service makes a value that works one time, for one provider and one session, for 5 minutes. The start of the purpose `link` needs this value. For a link removal, the button "Remove" on the account page asks for the password, a code, or a passkey in the same way. A user with only a passkey can link and can remove a link. A user with no local factor has nothing to check. For a link, the ID token must have a valid `auth_time` that is 5 minutes old or less. A token with no `auth_time` is refused, so a Google account cannot be linked by a user with no password, no TOTP, and no passkey. The `iat` does not replace the `auth_time` here. A user with no local factor removes a link with the purpose `unlink` of the upstream flow. The account page shows "Remove with <provider>" for each linked provider that is on. The route is `GET /login/oidc/{provider}?purpose=unlink&remove=<provider>`. The start needs a fresh session, the same-origin rule of the purpose `link`, and a user with no local factor (a user with a local factor gets the refusal). The callback needs an ID token with a valid `auth_time`, and the upstream account of the login must be a link of the user of the session. Else an attacker with a young stolen session could use an own account with a new `auth_time`. The callback then does the removal with the rules of `Remove` (last login method, revocation, audit entry, notice). A Google login cannot do this, because Google sends no `auth_time`, so a user with only Google links sets a password, a TOTP factor, or a passkey first. The API operation `MeIdentityLinks_remove` has no input for a password. For a user with a local factor, it needs a token that shows a local factor in `amr` (`pwd`, `otp`, `rec`, or `hwk`). For a user with no local factor, it needs a token of an upstream login whose ID token had a valid `auth_time`. The upstream `auth_time` stays inside the service (P24). At the login, the service stores a flag with the session and, for the code flow, with the refresh token family. When the service signs an access token from a flagged session or family, it stores the `jti` of the token in the table `upstream_auth_tokens` until the token expires. The operation reads this row. No token (access token or ID token) and no API response has the flag or a value for it, and `amr` has only `fed`. The session `auth_time` is the time of the login, so the check of 5 minutes applies. A login with no valid `auth_time`, for example a Google login, stores no flag. A token with `fed` and no stored row, and a token of a user that has a local factor and has only a stored row, get 401 `reauthentication_required`. A login of the same user with another method sets the flag of the session to false. The admin operation `UserIdentityLinks_remove` does not need the factor of the user. It needs the fresh MFA login of the admin.
- Local second factor: the service does not trust the MFA of the provider. A user with TOTP, recovery codes, or a passkey gets a pending login with the first factor `["fed"]` and goes to `/login/mfa`. The `amr` values are `["fed"]`, `["fed","otp","mfa"]`, `["fed","rec","mfa"]`, `["fed","hwk","mfa"]`, and `["fed","hwk","user","mfa"]`. The TOTP setup in a `fed` session keeps `fed`. The rule "MFA for admins" applies in the same way as for a password login.
- CSRF: the start of the purposes `link` and `invite` needs `Sec-Fetch-Site` `same-origin` or no header, because a cross-site page can send a `Lax` cookie with a top-level GET. The start checks `return_to` with the same rule as `POST /login` and checks that the auth request exists, and it makes no flow record for a wrong value. The page links to the start with a link, not a form, because a form that redirects to another host breaks the CSP rule `form-action 'self'`. The service needs no new script and no change of the CSP.
- Client secrets: the secret of each provider is in the `platform-go` secrets store under `identity/idp/<provider>/client-secret`. The subcommand `identity set-idp-secret <provider>` writes it from stdin. A provider that is on with no secret stops the start (log event `identity.idp.secret_missing`). The secret is never in a log or a span.
- Outbound calls: all outbound calls of one request (discovery, keys, token endpoint) share one deadline of `IDENTITY_IDP__HTTP_TIMEOUT` (10 seconds by default, 25 seconds at most, because the public server has a write timeout of 30 seconds). The HTTP client follows no redirect. The service calls the hosts of the configured providers only and no other host. The service keeps the discovery document for one hour. If the new read fails, it uses the old copy for up to 24 hours and logs the warning `identity.idp.discovery_stale`. Parallel requests make one read. The service reads the Microsoft key set again for an unknown `kid` at most one time in a minute, and never for a known `kid`.
- Removal and revocation: a link removal (`MeIdentityLinks_remove`, `UserIdentityLinks_remove`, and the "Remove" button on the account page) ends all sessions and refresh token families of the user that have `fed` in `amr`, also the current one, and it revokes the personal API tokens that a session with `fed` made. The API token records the `amr` of the session that made it (column `api_tokens.amr`). The API does not show it. A token from before this version has an empty `amr`, so a removal does not revoke it. A user can revoke the old tokens by hand. A passkey removal and the reset of the MFA revoke the API tokens that a session with `hwk` made in the same way. A pending login with the method `fed` that exists at the removal also ends: the second factor reads the link again in the transaction that makes the session, after the lock of the user row, and gives "The login expired" if the link is gone. The login path without a second factor reads the link in the same way.
- First password: the page `/account/password` sets the first password of a user that has none. It needs a fresh session. The command writes the audit entry `identity:password:set` in the transaction and sends the notice `password_set`, because a password is a new login method.
- Rule "last login method": a user must keep one login method: a password, a passkey that the service accepts, or a link of a provider that is on. `domain.HasLoginMethod` is the only definition. The link removals, `MePasskeys_remove`, `UserMfa_reset`, the page removals, and the enable of a disabled user use it. A refusal is 409 `last_login_method`. `identity reset-mfa` does not use the rule. It logs `identity.mfa.reset_last_login_method` when the user has no login method after the reset, and it does not change the status. Before an operator removes a client ID or turns off passkeys, the operator must link the users or set passwords. At start, the service counts the active users with no login method and writes the `warn` record `identity.idp.users_without_login_method` with the count.
- Audit entries and security notices: a link (`identity:identity_link:add`, notice `identity_link_added`) and a removal (`identity:identity_link:remove`, notice `identity_link_removed`) write the audit entry in the transaction of the change and send the notice through the port `securitynotices`. The entry has the actor, the target user, the result, and the provider. It has no subject and no email.
- Log events and metrics: `identity.idp.linked`, `identity.idp.unlinked`, `identity.idp.login_failed`, `identity.idp.users_without_login_method`, and `identity.mfa.reset_last_login_method`. The counter `identity.idp.logins` has the attributes `provider`, `purpose` (`login`, `link`, `invite`), and `outcome` (`ok`, `not_linked`, `linked_elsewhere`, `email_mismatch`, `bad_state`, `provider_error`, `token_invalid`, `not_fresh`, `limited`, `refused`, `user_inactive`). The outcome `refused` is a start that the rules refuse, for example a request from another site. The outcome `user_inactive` is a login of a user that is not active. No record has a code, a state, a nonce, an ID token, a subject, or an email. The values of the query parameters `id_token`, `error_description`, `session_state`, and `confirm` are redacted, as `code`, `state`, and `nonce` are. The page never shows the `error_description` of a provider.
- Rate limit: the bucket `idp` (30 per minute for each IP) counts the start and the callback.

## Not in this version

Password reset by email needs R12. The audit entries of logins, token issue, signing keys, and operator commands are in [Signing keys, tokens, logins, and operator commands](#signing-keys-tokens-logins-and-operator-commands). Other providers, a generic OIDC provider setting, and Microsoft personal accounts are not in this version.
