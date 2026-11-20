# Permission manifests and roles

A service publishes the permissions and the default roles of its app in a manifest. The identity service stores the manifests, and gives the roles to clients.

## Publish

`PUT /v1/permission-manifests/{app}` with the scope `identity:manifest:publish` and the audience `identity`.

1. `{app}` is not `identity`. The app `identity` is reserved. The service publishes its own manifest at start, from the embedded copy of `services/identity/manifest.json` of `constellation-contracts`. No client can publish it.
2. The caller is a service client. Its `app` is equal to `{app}` and to `manifest.app`.
3. The checks of the keys run and return all problems in one answer.
4. The service stores the manifest in one transaction. It locks the row of the app first. If the hash is the stored hash, nothing changes and the answer has the stored version. Otherwise the service replaces the permissions, the roles, and the role permissions, and increments the version. The inserts run in batches of at most 1000 rows, with one statement for each batch.

## Limits

A manifest over a limit gets 422 and a field error. A character is one Unicode code point.

| Limit | Value | Code | Pointer |
| ----- | ----- | ---- | ------- |
| Permissions in a manifest | 200 | `too_many_permissions` | `/permissions` |
| Roles in a manifest | 50 | `too_many_roles` | `/defaultRoles` |
| Permissions in one role | 100 | `too_many_role_permissions` | `/defaultRoles/<i>/permissions` |
| Characters in a description | 256 | `description_too_long` | `/permissions/<i>/description` and `/defaultRoles/<i>/description` |

## Errors

The answer is 422 with a `Problem`. The `code` of the `Problem` is the code of the first error. The list `errors` has all errors. Each error has a JSON Pointer in `field`.

| Code | Meaning | Pointer |
| ---- | ------- | ------- |
| `manifest_app_mismatch` | `{app}` is `identity`, `manifest.app` is not `{app}`, or the caller is not a service client of `{app}`. | `/app` |
| `permission_app_mismatch` | A permission key does not start with `<app>:`. | `/permissions/<i>/key` |
| `role_permission_unknown` | A role permission is not in `permissions`. | `/defaultRoles/<i>/permissions/<j>` |
| `duplicate_key` | A permission key, a role key, or a role permission occurs two times. | The second occurrence |
| `invalid_key` | A key does not match its pattern. | The key |
| `too_many_permissions`, `too_many_roles`, `too_many_role_permissions`, `description_too_long` | A manifest is over a limit. See "Limits". | See "Limits" |

A permission key has the form `<app>:<resource>:<action>`. The only exception is `identity:admin`.

## The canonical hash

The hash is the SHA-256 of a canonical JSON form. The permissions and the roles are in `key` order. The permissions of each role are in order. The object keys are sorted and the JSON has no spaces. A change of the order of the lists does not change the hash. A change of a description or a name does.

## Roles and assignments

- The clients file gives a `roles` list for each client. See [configuration.md](configuration.md).
- Every service client has the implicit role `identity:service` with the permission `identity:manifest:publish`. It has no row in the database, and the API cannot remove it.
- An assignment is pending when its role is not in the current manifest of its app. The service calculates this in each query. A publish never changes or deletes an assignment. An assignment of a deleted role is pending, and applies again when the role comes back. Pending assignments grant nothing.
- A token that exists keeps its scopes after a manifest change. A token lives 5 minutes at most.

## Read

| Operation | Scope |
| --------- | ----- |
| `GET /v1/permission-manifests`, `GET /v1/permission-manifests/{app}` | `identity:role:read` |
| `GET /v1/roles`, `GET /v1/roles/{role}` | `identity:role:read` |

A list has `pageSize` (1 to 200, default 50) and an opaque `pageToken`.
