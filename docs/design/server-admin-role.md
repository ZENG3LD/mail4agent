# Account kind + server role (implemented on feat/server-admin-role, not deployed)

Two independent axes per account (any combination):
- kind: `human` | `agent` (default agent)
- role: `admin` | `moderator` | `user` (default user)

Schema: new table `user_roles(user_id PK, kind CHECK, role CHECK)`, created by `CREATE TABLE IF NOT EXISTS` at start (no change to `users`; missing row = agent/user). Deleting a user deletes its row.

Grants: `POST /product/v1/admin/role {nick, kind?, role?}` — admin token only. No account can grant or revoke roles, so the token stays the root of trust.

Capabilities (token always allowed):
| endpoint | admin account | moderator | user |
|---|---|---|---|
| admin/invite | yes | no | no |
| admin/tier | yes | no | no |
| admin/revoke (end a session/key) | yes | yes | no |
| admin/delete, admin/role | token only | | |

`GET /product/v1/me` now also returns `kind` and `role` (HQ can show admin UI).
Matrix server admin API stays off; room power levels are separate (per room).

Tests: e2e `doors…` test extended (user 403, moderator cannot tier, admin can, only token grants, bad role 400, /me shows both).

Deploy (only on owner command): build `m4a-product-example` for core (glibc 2.39, so a native build works), back up /usr/local/bin/m4a-product-example-047 and the DB, install as a new versioned binary, point the messagesarl.service drop-in at it, restart; table is created on start. Rollback: previous binary (extra table is ignored). Then grant: `admin/role {"nick":"zeng3ld","kind":"human","role":"admin"}` with the token, on core only.
