# Admin API

The `/v1` operations for users, invites, role assignments, clients, client keys, agents, and sessions. The contract is in `constellation-contracts`. A caller needs an access token for the audience `identity` with the scopes of the operation. See [tokens.md](tokens.md). An admin UI is a public client with `app: identity`. It gets the token with the code flow.

Each change writes one `info` log record (`identity.admin.change`) with `actor_id`, `operation`, and `target_id`. The record has no secret value. Audit entries come with R08 and R09.

## Operations and scopes

| Operation | Scope |
| --------- | ----- |
| `Users_list`, `Users_get` | `identity:user:read` |
| `Users_create`, `Users_update`, `Invites_create` | `identity:user:write` |
| `UserRoles_list`, `ClientRoles_list`, `AgentRoles_list` | `identity:role:read` |
| `UserRoles_assign`, `UserRoles_remove`, `ClientRoles_assign`, `ClientRoles_remove`, `AgentRoles_assign`, `AgentRoles_remove` | `identity:role:assign` |
| `Agents_list`, `Agents_get` | `identity:agent:read` |
| `Agents_create`, `Agents_update` | `identity:agent:write` and `identity:admin` |
| `Clients_list`, `Clients_get` | `identity:client:read` |
| `Clients_create`, `Clients_update`, `ClientKeys_add`, `ClientKeys_remove` | `identity:client:write` and `identity:admin` |
| `UserApiTokens_list` | `identity:api_token:read` |
| `ApiTokens_revoke` | `identity:api_token:revoke` |
| `MeApiTokens_create`, `MeApiTokens_list`, `MeApiTokens_revoke` | `identity:api_token:manage_own` (user token only) |
| `MeMfa_get`, `MeTotp_remove`, `MePasskeys_list`, `MePasskeys_update`, `MePasskeys_remove` | `identity:mfa:manage_own` (user token only) |
| `UserPasskeys_list` | `identity:mfa:read` |
| `MeIdentityLinks_list`, `MeIdentityLinks_remove` | `identity:identity_link:manage_own` (user token only) |
| `UserIdentityLinks_list` | `identity:identity_link:read` |
| `UserIdentityLinks_remove` | `identity:identity_link:remove` and `identity:admin` |
| `UserMfa_get` | `identity:mfa:read` |
| `UserMfa_reset` | `identity:mfa:reset` and `identity:admin` |
| `Sessions_list` | `identity:session:read` |
| `Sessions_revoke`, `Sessions_revokeAll` | `identity:session:revoke` |
| `Me_get` | No scope. A user token is necessary. |

Only the role `admin` holds `identity:admin`. A holder of `identity:client:write` alone could add a key to a service client and get its tokens, so the client writes also need `identity:admin`. A holder of `identity:role:assign` can assign each role, also `identity:admin`. In slice 1 this permission is equal to full admin access.

## MFA

- `MeMfa_get` returns `MfaStatus` of the user of the token. It needs a user token with no `act` (403 `user_token_required`).
- `MeTotp_remove` removes the TOTP factor and the recovery codes of the user of the token. The order of the checks: the token (401), the scopes (403), `user_token_required` (403), `reauthentication_required` (401), `totp_not_found` (404), `mfa_required` (409). The 409 means that the policy needs MFA for the user.
- `UserMfa_get` returns `MfaStatus` of any user. The permission is `identity:mfa:read`, not `identity:user:read`. An unknown user gives 404 `user_not_found`.
- `MePasskeys_list` lists the passkeys of the user of the token. `UserPasskeys_list` lists the passkeys of any user (permission `identity:mfa:read`, not `identity:user:read`, 404 `user_not_found`). Both sort by `createdAt` and then `id`, ascending. A `Passkey` has `id`, `name`, `createdAt`, `lastUsedAt` (absent until the first use), and `synced` (the flag BS). It has no credential ID, no public key, and no sign count. The operations stay available when passkeys are off. They show the stored passkeys.
- `MePasskeys_update` renames a passkey. The order of the checks: the token (401), the scopes (403), `user_token_required` (403), `reauthentication_required` (401), `passkey_not_found` (404), the name (422). The name has 1 to 64 characters, no leading or trailing white space, no control character, no format character, and no line or paragraph separator. It writes the audit entry `identity:mfa:passkey_rename` with the old name and the new name.
- `MePasskeys_remove` removes a passkey. The order of the checks: the token (401), the scopes (403), `user_token_required` (403), `reauthentication_required` (401), `passkey_not_found` (404), `mfa_required` (409), `last_login_method` (409). The first 409 means that the policy needs MFA for the user and the passkey is the last second factor. The second 409 means that the removal would leave the user with no login method. The service revokes all sessions and refresh token families of the user that have `hwk` in `amr`, and the personal API tokens that a session with `hwk` made. It writes the audit entry `identity:mfa:passkey_remove` and sends the notice `mfa_passkey_removed`. A passkey of another user and an ID that is not a UUID give 404 `passkey_not_found`.
- `UserMfa_reset` removes the factors of any user (TOTP, recovery codes, and passkeys) and revokes all sessions and refresh token families of the user. It keeps the password and the API tokens. A user with no factor also gives 204, and the sessions are also revoked. The order of the checks: the token (401), the scopes (403), `reauthentication_required` (401), `user_not_found` (404), `mfa_required` (409), `last_login_method` (409). The first 409 means that the `userId` is the `sub` of the token. The second 409 means that the reset would leave the user with no login method (the reset removes all passkeys). The reset does not set the user to `invited`. An admin cannot reset the own MFA with this operation. The admin uses `identity reset-mfa <email>`.
- `MeTotp_remove` and `UserMfa_reset` need a fresh MFA login: `amr` has `mfa` and `auth_time` is 5 minutes old or less. A token with `act`, an agent or exchange token, and an API token do not satisfy this. The refusal is 401 with the code `reauthentication_required` and the header `WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A fresh MFA login is necessary", max_age="300"`. See the step-up section of [tokens.md](tokens.md).
- Fields of `MfaStatus`: `enabled` (a TOTP row, an unused recovery code, or a passkey that the service accepts exists), `required` (the policy needs MFA for the user), `totp` (absent when TOTP is off, else `createdAt` and `lastUsedAt`, and `lastUsedAt` is absent until a code is used), `recoveryCodesRemaining` (0 to 10), and `passkeys` (the number of stored passkeys, also 0, also when passkeys are off).
- The audit entries and the notices of the passkeys: `identity:mfa:passkey_add` with the notice `mfa_passkey_added` (a registration on the hosted page), `identity:mfa:passkey_rename`, and `identity:mfa:passkey_remove` with the notice `mfa_passkey_removed`.
- `MeTotp_remove` and `UserMfa_reset` write an audit entry (`identity:mfa:totp_remove` and `identity:mfa:reset`) and send a security notice to the user through the port `securityevents`. For now, the log has both. See [security.md](security.md).
- The service gives the keys `identity:mfa:manage_own` to the roles `admin` and `user`, and `identity:mfa:reset` and `identity:mfa:read` to the role `admin`. The publish of the own manifest at start replaces the role permissions, so an existing role gets the new keys with no other step. A client must request `identity:mfa:manage_own` in the `scope` of the authorization request.

## Identity links

- `MeIdentityLinks_list` lists the links of the user of the token. `UserIdentityLinks_list` lists the links of any user. The permission is `identity:identity_link:read`, not `identity:user:read`. Both sort by `createdAt` and then `provider`, ascending. An `IdentityLink` has `provider`, `email` (the email claim at the last login, only for people, never a key for a decision), `createdAt`, and `lastUsedAt`. It has no subject. An unknown user gives 404 `user_not_found`.
- `MeIdentityLinks_remove` removes a link of the user of the token. The order of the checks: the token (401), the scopes (403), `user_token_required` (403), `reauthentication_required` (401), `identity_link_not_found` (404), `last_login_method` (409). It needs a fresh login (5 minutes), and it does not check `mfa`. A user with a local factor (password, TOTP, or passkey) needs a local factor in `amr` (`pwd`, `otp`, `rec`, or `hwk`). A user with no local factor needs a token of an upstream login whose ID token had a valid `auth_time`. The service stores this fact with the `jti` of the token, and `amr` does not show it. A user with a local second factor has `mfa` in every login, so the rule includes the second factor for such a user. The 401 has the header `WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A fresh login is necessary", max_age="300"`.
- `UserIdentityLinks_remove` removes a link of any user. The order of the checks: the token (401), the scopes (403), `reauthentication_required` (401), `user_not_found` (404), `identity_link_not_found` (404), `last_login_method` (409). It needs a fresh MFA login. An admin can use it on the own account, with the same rules.
- `{provider}` is valid only when it is exactly `google` or `microsoft`. Any other value gives 404 `identity_link_not_found`. A `userId` that is not a UUID gives 404 `user_not_found`.
- A removal revokes all sessions and refresh token families of the user that have `fed` in `amr` (also the current session), and the personal API tokens that a session with `fed` made. It writes the audit entry `identity:identity_link:remove` and sends the notice `identity_link_removed`.
- The service gives `identity:identity_link:manage_own` to the roles `admin` and `user`, and `identity:identity_link:read` and `identity:identity_link:remove` to the role `admin`.

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
- Each user with the status `active` has the implicit role `identity:user`. `UserRoles_list` shows it one time, with the source `config`, in its place in the order of `app` and `role`. If a row for this role exists, the implicit entry is the one in the list. `UserRoles_assign` for `identity:user` gives 200 with the source `config` and writes no row. `UserRoles_remove` for `identity:user` gives 204 and changes nothing. Both check that the user exists.
- `UserRoles_list` and `ClientRoles_list` return `RoleAssignment` items with `source` and `pending`. The list of a service client has the implicit role `identity:service`.

## API tokens

The self-service operations are in [tokens.md](tokens.md).

- `UserApiTokens_list` lists the tokens of one user (active, expired, and revoked), newest first, with the same pages as the other lists. An unknown user, or a `userId` that is not a UUID, gives 404 `user_not_found`. No response has the token value or the hash.
- `ApiTokens_revoke` revokes the token of any user. An unknown ID, or an ID that is not a UUID, gives 404 `api_token_not_found`. A revoke of a token that is revoked already gives 204. The log record is `identity.admin.change` with `operation` `api_token.revoke`.
- `Users_update` with `disabled` `true` also revokes all active API tokens of the user, in the same transaction. The `identity.admin.change` record of the disable has `api_tokens_revoked` with the number of tokens. An enable does not restore the tokens.

## Agents

An agent is a principal with roles. It belongs to one service client. The client can exchange a user token for a token with `act` = the agent. See [tokens.md](tokens.md).

| Operation | Success | Error codes |
| --------- | ------- | ----------- |
| `Agents_create` | 201 `Agent` | 400 `invalid_request` (bad name or body), 409 `agent_name_taken`, 422 `client_not_found`, 422 `client_not_service` |
| `Agents_list` | 200 `AgentPage` | 400 for a bad `pageSize` or `pageToken` |
| `Agents_get` | 200 `Agent` | 404 `agent_not_found` |
| `Agents_update` | 200 `Agent` | 400 `invalid_request`, 404 `agent_not_found`, 409 `agent_name_taken` |
| `AgentRoles_list` | 200 `RoleAssignmentPage` | 404 `agent_not_found` |
| `AgentRoles_assign` | 200 `RoleAssignment` | 404 `agent_not_found`, 422 `role_unknown` |
| `AgentRoles_remove` | 204 | 404 `agent_not_found` |

- The name is unique and case-sensitive. The service trims it. It must be valid UTF-8, have no control character, and have 1 to 100 characters. A parallel create with the same name gives one 201 and one 409, because the table has a unique constraint.
- `clientId` must name a service client. A disabled service client is allowed, because client authentication refuses it at the exchange. The client of an agent does not change. A new agent is enabled.
- `Agents_update` changes `name` and `enabled`. An empty body changes nothing and returns 200. A disabled agent cannot act. A disable does not revoke tokens that exist. An exchanged token lives 5 minutes at most.
- An `agentId` that is not a UUID gives 404 `agent_not_found` in each operation, with no database query.
- `AgentRoles_assign` is idempotent. The role must be in a published manifest (422 `role_unknown`). The error for an unknown agent comes before the error for an unknown role. `AgentRoles_remove` of a role that the agent does not have gives 204 (`ClientRoles_remove` gives 404). `AgentRoles_*` have no `identity:admin` scope. An agent has no implicit role. The list is in order of `app` and `role`.
- An assignment of a role that leaves the manifest stays and is `pending`. A pending role gives no permission.
- The log records are `identity.admin.change` with the operations `Agents_create`, `Agents_update`, `AgentRoles_assign`, and `AgentRoles_remove`.
- To let a client use the token exchange grant, assign a role with the permission `identity:token:exchange` to the client with `ClientRoles_assign`. In this version only the role `identity:admin` has it, for example `PUT /v1/clients/<client ID>/roles/identity:admin`.

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
