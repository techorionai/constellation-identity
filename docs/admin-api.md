# Admin API

The `/v1` operations for users, invites, role assignments, clients, client keys, and sessions. The contract is in `constellation-contracts`. A caller needs an access token for the audience `identity` with the scopes of the operation. See [tokens.md](tokens.md). An admin UI is a public client with `app: identity`. It gets the token with the code flow.

Each change writes one `info` log record (`identity.admin.change`) with `actor_id`, `operation`, and `target_id`. The record has no secret value. Audit entries come with R08 and R09.

## Operations and scopes

| Operation | Scope |
| --------- | ----- |
| `Users_list`, `Users_get` | `identity:user:read` |
| `Users_create`, `Users_update`, `Invites_create` | `identity:user:write` |
| `UserRoles_list`, `ClientRoles_list` | `identity:role:read` |
| `UserRoles_assign`, `UserRoles_remove`, `ClientRoles_assign`, `ClientRoles_remove` | `identity:role:assign` |
| `Clients_list`, `Clients_get` | `identity:client:read` |
| `Clients_create`, `Clients_update`, `ClientKeys_add`, `ClientKeys_remove` | `identity:client:write` and `identity:admin` |
| `Sessions_list` | `identity:session:read` |
| `Sessions_revoke`, `Sessions_revokeAll` | `identity:session:revoke` |
| `Me_get` | No scope. A user token is necessary. |

Only the role `admin` holds `identity:admin`. A holder of `identity:client:write` alone could add a key to a service client and get its tokens, so the client writes also need `identity:admin`. A holder of `identity:role:assign` can assign each role, also `identity:admin`. In slice 1 this permission is equal to full admin access.

## Lists

- `pageSize` is from 1 to 200. The default is 50. A value outside the range gives 400 `invalid_request`. The service does not cut it.
- The order is stable. Users, clients, and sessions: by `created_at`, then by ID. Role lists: by `app`, then by `role`.
- `pageToken` is the base64url of a JSON array of the last item. For users, clients, and sessions it is `[created_at, id]`. `created_at` is a string in RFC 3339 with 6 digits of fraction in UTC. For role lists it is `[app, role]`. The token is not signed. A token that does not decode, that is not a JSON array of two strings, that has the wrong form for the list, or that is longer than 1024 characters gives 400 `invalid_request`.
- The response has `nextPageToken` only if more items exist.
- `Sessions_list` returns the sessions that are valid now (not revoked, not expired).

## Users

- `Users_create` returns 201 with the user and the invite. A duplicate email gives 409 `email_taken`. An email or a name that breaks the rules gives 422 `invalid_user`.
- `Invites_create` works only for a user with the status `invited`. A `disabled` user gives 409 `user_disabled`. An `active` user gives 409 `user_not_invited`. Slice 1 has no password reset by invite.
- The last `active` user with `identity:admin` cannot be disabled and cannot lose `identity:admin`. The result is 409 `last_admin`. The count is the number of `active` users that have a role that is not pending and that grants `identity:admin` (any such role). The check and the change run in one transaction under `pg_advisory_xact_lock`, so two parallel changes cannot both pass.
- Disabling a user revokes all sessions and refresh token families of the user, and deletes the unused invite tokens of the user.
- Enabling a disabled user with no password sets the status `invited`. With a password, the status is `active`.

## Role assignments

- A role assignment needs a role in a published manifest. Otherwise 422 `role_unknown`.
- `UserRoles_list` and `ClientRoles_list` return `RoleAssignment` items with `source` and `pending`. The list of a service client has the implicit role `identity:service`.

## Clients

- The service makes the ID of a client that the API creates.
- A public client needs at least one `redirectUris` value. Each URI follows the rules in [configuration.md](configuration.md). A bad URI gives 422 `invalid_redirect_uri`.
- A service client must not have `app: identity`. Otherwise 422 `app_reserved`.
- `app` of a client cannot change. The body of `Clients_update` has no `app`. The server rejects an unknown member, so a body with `app` gives 400. `type` cannot change (422 `client_type_immutable`).
- A client with `source=config` cannot be changed by the API (409 `client_managed_by_config`). The API cannot delete the roles of the file. Extra roles by the API are allowed.
- `ClientKeys_*` and `ClientRoles_*` on a public client give 422 `client_type_unsupported`. `ClientKeys_*` on a config client gives 409 `client_managed_by_config`.
- A key that the API adds is a public EC P-256 JWK with a `kid` and no private member. Otherwise 422 `invalid_jwk`. A second key with the same `kid` gives 409 `key_exists`.
- Disabling a client revokes all refresh token families of the client.
- `GET /v1/me` returns the user of the token. A service token gets 403.
