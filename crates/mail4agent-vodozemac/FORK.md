# mail4agent-vodozemac -- fork ledger

Upstream: https://github.com/matrix-org/vodozemac
Pinned tag: `0.10.0`
Pinned commit: `bb39ec65357989f975e0d47f9fb35e0656180151`
Pinned tree: `02a2feb249d57d215ae2e54da83e863834b6ebe2`
Signer key (verified via `git verify-tag 0.10.0`): `B9A8 4A7F 1F42 C0E9 716C 94FE F3F7 BA99 3F12 1F7D` (Damir Jelic, key published at `https://github.com/poljar.gpg`)
License: Apache-2.0 -- see `LICENSE`, `NOTICE`

## Module reduction (per the audit's `Recorded decision` section)

Kept: `lib.rs`, `cipher/**`, `types/**`, `utilities/mod.rs`, `olm/**`,
`megolm/**`, `sas.rs`. Dropped entirely, not vendored: `ecies/**`,
`hazmat/**`, `pk_encryption.rs`, `afl/**`, `benches/**`, `.github/**`,
`.vscode/**`, `contrib/**`, `justfile`, `codecov.yaml`, `release.toml`,
`RELEASING.md`, `CONTRIBUTING.md`, `README.md`. `utilities/libolm_compat.rs`
is dropped in full -- its sole surviving export after the `libolm-compat`
strip below (`get_version`, used only by MSC3814 dehydration's version
check) has no remaining caller once dehydration is also dropped.

`src/{ecies,olm,types}/snapshots/*.snap` and `src/snapshots/*.snap` are not
vendored: every `insta` snapshot test was converted to a plain `assert_eq!`
against the snapshot file's expected text, inlined directly in the
converted test (see "Test conversions" below), so the `.snap` files
themselves are no longer read by anything.

## Stripped features and code paths

| Feature / path | Disposition | Where |
|---|---|---|
| `libolm-compat` (Cargo feature) | Dropped entirely, including from `default` (upstream's `default = ["libolm-compat"]` becomes `default = []`) | `Cargo.toml` |
| `insecure-pk-encryption` (Cargo feature) | Dropped with `pk_encryption.rs` (module not vendored; audit F7: its own code labels the MAC construction a known-broken libolm replica) | `Cargo.toml`, `lib.rs` |
| Upstream `js` feature | Replaced by a `[target.'cfg(target_arch = "wasm32")'.dependencies]` block on `getrandom` | `Cargo.toml` |
| `Account::{from,to}_libolm_pickle`, `from_decrypted_libolm_pickle`, the `libolm` submodule | Removed | `olm/account/mod.rs` |
| `Account::{to,from}_dehydrated_device`, `from_decrypted_dehydrated_device`, the `dehydrated_device` submodule, `DehydratedDeviceResult` | Removed (MSC3814 device dehydration). This fork does not deliver offline keys | `olm/account/mod.rs` |
| `DehydratedDeviceError`, `LibolmPickleError` (error enums) | Removed from `lib.rs` -- nothing constructs them once the two paths above are gone | `lib.rs` |
| `chacha20poly1305` dependency | Dropped -- its only KEEP-set consumer was `to/from_dehydrated_device` | `Cargo.toml` |
| `ed25519.rs` expanded-key support: `ExpandedSecretKey` struct + impls, `Ed25519Keypair::{from_expanded_key, expanded_secret_key, from_unexpanded_key, unexpanded_secret_key}`, `SecretKeys::Expanded` variant | Removed -- these existed only to serve libolm-pickle-compatible signing and MSC3814 dehydration, both dropped; `SecretKeys` is now a single-variant enum (`Normal`) | `types/ed25519.rs` |
| `ed25519-dalek` `hazmat` Cargo feature | Dropped -- it was requested only for the now-removed `ExpandedSecretKey` (`ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign}`) | `Cargo.toml` |
| `utilities/libolm_compat.rs` (whole file), `utilities/mod.rs`'s `mod libolm_compat;` wiring and `get_pickle_version` re-export | Removed -- `get_version`'s only caller was the dropped dehydration version-check | `utilities/mod.rs` |
| `olm/account/one_time_keys.rs::is_secret_key_published` cfg | Narrowed from `#[cfg(any(test, feature = "libolm-compat"))]` to `#[cfg(test)]` | `olm/account/one_time_keys.rs` |
| `olm/session/chain_key.rs::{ChainKey,RemoteChainKey}::from_bytes_and_index` | Removed (libolm-pickle-only constructors) | `olm/session/chain_key.rs` |
| `olm/session/double_ratchet.rs::{from_ratchet_and_chain_key, inactive_from_libolm_pickle}` | Removed | `olm/session/double_ratchet.rs` |
| `olm/session/receiver_chain.rs::{ratchet_key, insert_message_key}` (libolm-compat gated) | Removed | `olm/session/receiver_chain.rs` |
| `olm/session/mod.rs::{Session::from_libolm_pickle, ChainStore::get}`, the `libolm_compat` submodule | Removed | `olm/session/mod.rs` |
| `#[cfg(feature = "low-level-api")] use crate::hazmat::olm::MessageKey;` | Repointed to `message_key::MessageKey` (the local module) since `crate::hazmat` no longer exists -- `low-level-api` stays declared and off by default, this only fixes what it would resolve to if ever enabled | `olm/session/mod.rs` |
| `megolm/mod.rs::libolm` submodule (`LibolmRatchetPickle`) | Removed | `megolm/mod.rs` |
| `megolm/group_session.rs::{GroupSession::from_libolm_pickle}`, `libolm_compat` submodule | Removed | `megolm/group_session.rs` |
| `megolm/inbound_group_session.rs::{InboundGroupSession::from_libolm_pickle}`, `libolm_compat` submodule | Removed | `megolm/inbound_group_session.rs` |
| `sas.rs::EstablishedSas::calculate_mac_invalid_base64` | Removed (libolm-compat-only, replicates a libolm MAC-encoding bug) | `sas.rs` |
| AFL fuzz-corpus test helpers (`lib.rs::{corpus_data_path, run_corpus}`) and every `fuzz_corpus_*` test | Removed along with the (not vendored) `afl/` corpora -- these were `#[cfg(test)]`-only filesystem reads of AFL seed files, never regression vectors | `lib.rs`, `olm/messages/mod.rs`, `olm/account/mod.rs`, `megolm/mod.rs` |
| `#[timeout(10)]` (`ntest`) on `utilities/mod.rs::integer_encoding_required_space` | Attribute and `ntest` dependency removed; the test itself (a fixed-size pure computation) needs no timeout | `utilities/mod.rs` |
| `Curve25519Keypair::from_secret_key`, `OneTimeKeys::secret_keys` | Removed -- both became genuinely dead (`dead_code = "deny"` caught them at the first `cargo check`) once their only callers, the `libolm`/`dehydrated_device` submodules of `olm/account/mod.rs`, were deleted | `types/curve25519.rs`, `olm/account/one_time_keys.rs` |

## Dependency changes

- Direct dependencies added with the kept modules: `cbc`, `matrix-pickle` (+
  `matrix-pickle-derive`), `prost` (+ `prost-derive`), `serde_bytes`,
  `x25519-dalek`, `zeroize_derive` (confirmed transitive via
  `x25519-dalek`'s own `zeroize` feature request -- `cargo tree -e features
  -i zeroize` shows `zeroize feature "zeroize_derive" -> x25519-dalek`, so
  the crate-level `zeroize` dependency did not need an explicit `derive`
  feature added). Two more transitive crates enter with these, not named
  individually in the audit: `block-padding` (via `cipher` -> `cbc`/`aes`)
  and `itertools` (via `prost-derive`) -- both small, low-risk, and not
  optional.
- `matrix-pickle` **stays** a direct dependency after the `libolm-compat`
  strip (audit finding F8): `olm/session_keys.rs`'s `SessionKeys`,
  `olm/session/ratchet.rs`'s `RemoteRatchetKey`, and
  `types/curve25519.rs`'s `Curve25519PublicKey` all derive/implement
  `matrix_pickle::Decode` **unconditionally**, not only inside
  `libolm_compat.rs`. Nothing in this fork decodes a full matrix-pickle
  byte stream any more (that was `utilities/libolm_compat.rs`'s job, now
  removed), but the trait impls on those three types are still compiled and
  still exercised by `cargo test`'s normal type-checking, so the dependency
  is kept per decision #4 of the recorded decision.
- `chacha20poly1305` dropped entirely (see the dehydration row above).
- `ed25519-dalek`'s `hazmat` feature dropped (see the expanded-key row
  above); `curve25519-dalek` stays a **direct** dependency per the audit's
  final list even though nothing in this fork's own `src/` names
  `curve25519_dalek::*` any more after the expanded-key removal -- it
  remains required transitively through `ed25519-dalek`/`x25519-dalek`, and
  keeping it direct pins the version in lock step with those two crates
  rather than letting Cargo pick independently.
- `getrandom` is **not** a plain `[dependencies]` entry (it has no direct
  call site anywhere in `src/`, same as upstream) -- it is declared only
  under `[target.'cfg(target_arch = "wasm32")'.dependencies]` with the `js`
  feature, so wasm32 builds get an entropy source for `rand`'s
  `thread_rng()` backend without any Cargo feature a caller has to
  remember to enable.
- `olm-rs` (C libolm FFI, dev-only) is never vendored, never built, never
  linked -- per the audit's F5 and the supply-chain policy, that requires
  its own separate, explicit "execute once in isolation" decision this
  fork does not need for a single-server Matrix deployment.

## Test conversions

- **`insta` snapshot tests -> `assert_eq!`** against the `.snap` file's
  expected text, inlined as a string literal in the test itself (no `insta`
  dependency, no `.snap` files vendored): `types/curve25519.rs::
  snapshot_public_key_debug`, `types/ed25519.rs::{snapshot_public_key_debug,
  snapshot_signature_debug}`, `olm/session_keys.rs::
  snapshot_session_keys_debug`, `sas.rs::snapshot_debug`.
- **`assert_matches2::{assert_matches, assert_let}` -> `assert!(matches!(..))`
  / `let PATTERN = value else { panic!(..) }`** throughout every kept test
  module (`cipher/mod.rs`, `types/curve25519.rs`, `types/ed25519.rs`,
  `megolm/message.rs`, `olm/account/mod.rs`, `olm/messages/{mod,message}.rs`,
  `olm/session/{mod,double_ratchet,receiver_chain}.rs`). Panicking in test
  code is allowed by `clippy.toml`'s `allow-panic-in-tests = true` (kept
  verbatim from upstream, needed for the `unwrap`/`expect`/`panic`
  `clippy::*_used`/`panic` deny-lints in `Cargo.toml` to still permit normal
  test idioms).
- **`proptest!` blocks -> deterministic seeded loops** in `sas.rs`: the two
  `proptest!` blocks (`proptest_emoji`, `proptest_decimals`) became
  `emoji_indices_are_in_range`/`decimal_values_are_in_range`, each looping
  500 times over `rand::rngs::StdRng::seed_from_u64(..)`-derived random
  6-byte inputs and asserting the same range properties the original
  property tests checked.
- **`olm_rs`-dependent tests dropped** (every test that constructed or
  called into a real `olm_rs`/C-libolm object): `olm/account/mod.rs::
  {vodozemac_libolm_communication, inbound_session_creation,
  inbound_session_creation_using_fallback_keys, libolm_unpickling,
  pickle_cycle_with_{one,two}_fallback_key(s), signing_with_expanded_key,
  libolm_pickle_cycle, decrypt_with_dehydrated_device,
  fails_to_rehydrate_with_wrong_key, encodes_optional_fallback_key,
  decrypted_dehydration_cycle}`; `olm/session/mod.rs::libolm_unpickling`;
  `olm/session/double_ratchet.rs::ratchet_counts_for_imported_session`;
  `megolm/mod.rs::{encrypting, decrypting, libolm_inbound_unpickling,
  libolm_unpickling}`; `megolm/inbound_group_session.rs::verify_mac`;
  `sas.rs::{libolm_and_vodozemac_generate_same_bytes,
  calculate_mac_vodozemac_libolm, calculate_mac_invalid_base64}`. No
  hard-coded libolm-produced byte vectors existed anywhere in the upstream
  suite to lift out as static fixtures instead (confirmed by the audit,
  §7) -- every one of these tests generated its libolm-side state live via
  `olm_rs::OlmAccount::new()`/`OlmSession`/`OlmOutboundGroupSession`, so
  dropping `olm_rs` loses this interop coverage with no static replacement
  available, per the recorded decision.
- **`session_and_libolm_pair()` rebuilt as a pure vodozemac↔vodozemac pair**
  (recorded decision, point 6): `olm/session/mod.rs::test`'s helper now
  builds both sides with `mail4agent_vodozemac::olm::Account`/`Session` directly
  (the same shape `olm/session/double_ratchet.rs::test::create_session_pair`
  already used), so `session_config`, `has_received_message`,
  `out_of_order_decryption`, `more_out_of_order_decryption`,
  `max_keys_out_of_order_decryption`, `max_gap_out_of_order_decryption`,
  `session_pickling_roundtrip_is_identity`, and (behind `low-level-api`)
  `next_message_key_returns_a_key` all keep running as pure-Rust,
  libolm-free regression tests instead of being dropped.
- **AFL corpus tests dropped** along with the (not vendored) `afl/`
  directories: `olm/messages/mod.rs::fuzz_corpus_decoding`,
  `olm/account/mod.rs::fuzz_corpus_unpickling`, `megolm/mod.rs::
  fuzz_corpus_{decoding, session_creation, session_import}`.
- **Kept unchanged**: every other test, including all hard-coded regression
  vectors (`olm/messages/mod.rs`'s `PRE_KEY_MESSAGE`/`MESSAGE` base64
  constants, `megolm/ratchet.rs`'s 128-byte expected ratchet state at what
  was upstream lines 305-317), the 3DH/double-ratchet/receiver-chain
  property tests, and every pickling-roundtrip test.

## Upstream delta-review procedure (audit §8, carried forward verbatim)

On every future upstream vodozemac release considered for adoption: read
the new tag's `CHANGELOG.md`, diff every file in the KEEP set (`cipher/`,
`types/`, `utilities/`, `olm/`, `megolm/`, `sas.rs`) against this fork's
vendored copy, classify each change as *security fix to port*, *behaviour
change to evaluate*, or *cosmetic-deps-only*, and port every security fix
regardless of whether the accompanying dependency-version bump is also
adopted. A dependency-generation bump (e.g. `rand 0.8`->`0.10`, `aes
0.8`->`0.9`, `curve25519-dalek 4`->`5`) is never adopted silently -- it
needs its own explicit decision. This fork's crypto crates stay
generation-pinned. The one post-0.10.0 security fix
identified by the audit (#382, an off-by-one in the libolm-pickle OTK-id
counter) is moot for this fork because `libolm-compat` is dropped entirely
-- if `libolm-compat` is ever reintroduced, port that fix first.

## Residual risk note

Vendoring means this crate no longer receives upstream security fixes
automatically; the delta-review procedure above is the compensating
control. Of the Soatok 2026-02-17 disclosure items, the Olm MAC-truncation
downgrade is moot while `experimental-session-config` stays off, ECIES
check-code entropy is moot because `ecies` is dropped, and the
skipped-key-eviction limit and static pickle-IV info string are inherited
upstream design choices, not defects introduced by this fork.
