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

Each run of `setup-link` deletes the unused setup tokens and makes a new one. Thus only the link of the last run works.

## Make the first admin

1. Open the link in a browser.
2. Enter the email, the name, and the password two times. The password has 12 to 128 characters.
3. Submit the form. The service makes the account with the role `identity:admin` and logs you in.

Do this at once. The link ends after `IDENTITY_SETUP__TTL` (24 hours by default). The link works one time. A link that was used or that has ended gives an error page.

Anyone who has the link can make the first admin account. Do not put the output of `setup-link` in a log, a ticket, or a chat. Complete the setup at once.

## Get a new link

If the link ended or you lost it, run the subcommand `setup-link` again:

```sh
identity setup-link
```

If an admin exists, `setup-link` prints an error and exits with code 1.

A restart of the service after the link ended makes a new token and writes a new log record. The record does not have the link. Run `setup-link` to get it.

## Next step

Log in at `<IDENTITY_ISSUER>/login`. The admin API for users and invites comes with a later issue. Until then, only code inside the process can call the use cases `CreateUser` and `CreateInvite`.
