# First start

A new install has no user. The service makes a one-time setup link at the first start. You use the link to make the first admin account.

## Find the setup link

At the first start, the service writes one log record at the level `WARN` with the message `identity: first-admin setup link`. The attribute `link` holds the URL:

```txt
<IDENTITY_ISSUER>/setup?token=<value>
```

The token value is in this log record only. The service writes it one time. A restart before the setup does not write a new link, because the first token is still valid.

Search the log of the service, for example:

```sh
docker logs <identity container> 2>&1 | grep "first-admin setup link"
```

## Make the first admin

1. Open the link in a browser.
2. Enter the email, the name, and the password two times. The password has 12 to 128 characters.
3. Submit the form. The service makes the account with the role `identity:admin` and logs you in.

Do this at once. The link ends after `IDENTITY_SETUP__TTL` (24 hours by default). The link works one time. A link that was used or that has ended gives an error page.

Anyone who has the link can make the first admin account. Treat the log as a secret until the setup is done. Logs can go to a log store, so complete the setup before other people can read the log.

## Get a new link

If the link ended or you lost it, use one of these methods:

- Restart the service. If no admin exists and no valid link exists, the service writes a new link to the log.
- Run the subcommand `setup-link`. It needs the same database config as the server. It deletes each unused setup token, makes a new one, and prints the link to standard output. It does not write the link to the log.

  ```sh
  identity setup-link
  ```

If an admin exists, `setup-link` prints an error and exits with code 1.

## Next step

Log in at `<IDENTITY_ISSUER>/login`. The admin API for users and invites comes with a later issue. Until then, only code inside the process can call the use cases `CreateUser` and `CreateInvite`.
