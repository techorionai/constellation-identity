# First start

A new install has no user. The service makes a one-time setup link at the first start. You use the link to make the first admin account.

## Get the setup link

The log never has the setup link or the token, because a person who can read the log could take over the install. At the first start, the service writes one log record at the level `WARN` with the message `identity: first-admin setup link pending`. The record says that a setup link exists. The attribute `expires_at` gives the time when the link ends.

To get the link, run the subcommand `setup-link`. It needs the same database config as the server. It prints the link to standard output only:

```sh
docker compose exec identity identity setup-link
```

```txt
<IDENTITY_ISSUER>/setup?token=<value>
```

Each run of `setup-link` deletes the unused setup tokens and makes a new one. Thus only the link of the last run works. Each run also writes the audit entry `identity:setup:link_create` with the actor `identity` and `details.origin` `cli`. The entry has the expiry time and never the link or the token.

## Make the first admin

1. Open the link in a browser.
2. Enter the email, the name, and the password two times. The password has 12 to 128 characters.
3. Submit the form. The service makes the account with the role `identity:admin` and logs you in.

The service sends the first admin to the TOTP setup page (`/account/totp?required=1`), because the rule "MFA for admins" is on by default (`IDENTITY_MFA__REQUIRE_FOR_ADMINS`). Scan the QR code with an authenticator app, enter the first code, and save the 10 recovery codes. An admin with no TOTP gets no authorization code and no refresh token. If you lose the device and the recovery codes, run `identity reset-mfa <email>`.

Do this at once. The link ends after `IDENTITY_SETUP__TTL` (24 hours by default). The link works one time. A link that was used or that has ended gives an error page.

Anyone who has the link can make the first admin account. Do not put the output of `setup-link` in a log, a ticket, or a chat. Complete the setup at once.

## Get a new link

If the link ended or you lost it, run the subcommand `setup-link` again:

```sh
identity setup-link
```

If an admin exists, `setup-link` prints an error and exits with code 1.

A restart of the service after the link ended makes a new token and writes a new log record. The record does not have the link. Run `setup-link` to get it.

## Login with Google or Microsoft (optional)

The service can log users in with a Google account or a Microsoft work account. A user links the account on `/account/security`, or accepts an invite with it. There is no sign-up with an upstream account.

1. Register the redirect URI at the provider. It is `<IDENTITY_ISSUER>/login/oidc/google/callback` or `<IDENTITY_ISSUER>/login/oidc/microsoft/callback`. A change of the issuer changes the redirect URI.
2. Google: make an OAuth client of the type web application. The scopes are `openid`, `email`, and `profile`. Set `IDENTITY_IDP__GOOGLE__CLIENT_ID`. To limit the login to your domains, set `IDENTITY_IDP__GOOGLE__ALLOWED_DOMAINS`.
3. Microsoft: make an app registration for accounts in an organizational directory only. Add a client secret. In the token configuration, add the optional claims `email` and `xms_edov` to the ID token. Without `xms_edov`, the invite with Microsoft fails, and the login of a linked user still works. Set `IDENTITY_IDP__MICROSOFT__CLIENT_ID`, and `IDENTITY_IDP__MICROSOFT__TENANT` (a tenant GUID, or `organizations` for all work and school accounts).
4. Store the client secret. The value comes from stdin and is not in the process list:

   ```sh
   identity set-idp-secret google
   identity set-idp-secret microsoft
   ```

5. Start the service. If a provider has a client ID and no stored secret, the service does not start and logs `identity.idp.secret_missing`.

## Next step

Log in at `<IDENTITY_ISSUER>/login`. The admin API for users and invites comes with a later issue. Until then, only code inside the process can call the use cases `CreateUser` and `CreateInvite`.
