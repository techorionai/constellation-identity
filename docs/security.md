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
- A good login deletes the email counter. The IP counter keeps the attempt, so it counts all attempts of the IP in the window.
- If Valkey is not available, the login fails closed with status 503. No hash runs and no session starts.
- A person can lock out a user with failed logins for the email of that user. The lock ends after the window. The roadmap tracks a subcommand `identity unlock-login <email>` and an IP rate limit on `/setup` and `/invite` with R07. General rate limits on other endpoints also come with R07.

## Client IP and trusted proxies

The client IP is the remote address of the connection. If the remote address is in a range of `IDENTITY_HTTP__TRUSTED_PROXIES`, the client IP is the last address of `X-Forwarded-For` that is not in a trusted range. A client can add addresses in front of the header, so the service does not use the first address. Without trusted proxies, the service ignores the header.

## Sessions and cookies

- The cookie is `__Host-constellation_session` with the flags `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`. It has no `Domain`.
- The cookie holds 32 random bytes in base64url. The database stores only the SHA-256 hash.
- A session ends at the idle expiry or at the absolute expiry. A logout revokes the session. A login always makes a new session and revokes the session of the old cookie, so there is no session fixation.
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

## Not in this version

General rate limits on other endpoints, MFA, passkeys, and upstream OIDC come with R07. Password reset by email needs R12. Audit entries for logins come with R08 and R09. Until then the structured log records (`identity.login.ok`, `identity.login.failed`, and others) are the only record.
