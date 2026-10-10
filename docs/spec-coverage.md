# Matrix spec coverage (v1.19)

`crates/mail4agent-server/tests/spec_coverage.rs` lists every client-server and server-server endpoint a homeserver is expected to expose and fails if one has no handler. Run with `cargo test -p mail4agent-server --test spec_coverage`.

Deliberately not offered, each answering with the spec's own error:

- Single sign-on redirects and OIDC `auth_metadata`: 404 `M_UNRECOGNIZED` (the product server owns login).
- Knocking (client and federation): 403 `M_FORBIDDEN`; no room here allows it.
- Third-party identifiers and invites: `M_THREEPID_DENIED` / 403; thirdparty bridging lookups: empty lists, unknown protocol 404 `M_NOT_FOUND`.
- Admin API (`admin/whois`) and appservice directory: 403 `M_FORBIDDEN`.
- URL previews: `preview_url` answers `{}`; the server never fetches arbitrary URLs for a client.
- Deprecated `events`, `initialSync`: 404 `M_UNRECOGNIZED` (removed from the current spec line for sync clients).
- Custom federation queries other than profile/directory: 404 `M_UNRECOGNIZED`.

Owned by the product server in front of the core (core answers 403 `M_FORBIDDEN` naming the product): `login/get_token`, `refresh`, registration and password/3pid token requests. The reference product (`m4a-product-example`) implements get_token, refresh, `account/password`, `deactivate`, 3pid and capabilities.

Optional pieces and their switches (cargo feature, default on, plus environment): presence (`M4A_PRESENCE=off`), media federation (`M4A_MEDIA_FEDERATION=off`; limits `M4A_MEDIA_MAX_BYTES`, `M4A_MEDIA_REMOTE_TTL_SECS`, `M4A_MEDIA_REMOTE_CACHE_BYTES`), thumbnails (`media-thumbnails`), federated directory search (`M4A_DIRECTORY_FEDERATION=off`), database snapshot before migration (`M4A_DB_SNAPSHOT=off`, `M4A_DB_SNAPSHOT_DIR`), support well-known (`M4A_WELLKNOWN_SUPPORT`), refresh-token access lifetime at the product (`M4A_PRODUCT_ACCESS_TTL_SECS`, 0 = off), audience name of the key-signature login (`M4A_PRODUCT_AUDIENCE`, default `m4a-product`).

## Key-signature login (agents)
Not part of the Matrix spec; a custom login type for agent identities, next to the password and token flows that stock clients use. The product (not the core) verifies the proof; the core only sees the assertion that follows. Matrix carriage: `POST /login` with `type: org.m4a.login.signature`, `key_id`, then `challenge_id` and `signature` (a request with only `key_id` is answered 401 with the challenge under the type name); it is listed in `GET /login`. Product endpoints: `POST /product/v1/admin/invite`, `/product/v1/enroll`, `/product/v1/login/key/challenge`, `/product/v1/login/key`. Message formats and replay rules: `m4a_seam::keyproof`. Client: crate `m4a-agent`.
