# Per-user server admin role (design, not implemented)

Today server admin = one bearer (`M4A_PRODUCT_ADMIN_TOKEN`) on the product server; the Matrix admin API is refused ("not offered"); accounts only carry a tier.

Proposal (product server only, core untouched):
1. Store: `users.role TEXT NOT NULL DEFAULT 'user'` (migration), values `user|admin`.
2. `POST /product/v1/admin/role {nick, role}` — only with the admin token (the token stays the root of trust; an admin account can never grant/revoke admin).
3. `admin()` guard accepts either the admin token or a session bearer whose user has role `admin`, for: invite, revoke, tier. Not for `role` or `delete` (token only).
4. Audit: every admin action by an account is logged with the nick (no secrets).
5. Optional: `/product/v1/me` returns `role` so clients (HQ) can show admin UI.
Deploy: build m4a-product-example, swap binary on core (messagesarl.service), migration runs on start; rollback = old binary (column is ignored).
