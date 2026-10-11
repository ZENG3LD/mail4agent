# Versioning rule

One version for the whole set. Every publishable crate of this repository (the root `mail4agent`, `mail4agent-api`, `-attest`, `-core`, `-store-sqlite`, `-client`, `-grok`, `-vodozemac`, `-messenger`, `-messenger-shell`, `-server`, `-server-bin`, `m4a-edge`, `m4a-matrix-core`, `m4a-seam`, `m4a-matrix-core`, `m4a-agent`, `m4a-product-kit`, `m4a-product-example`) carries the same number, taken from `[workspace.package] version` in the root `Cargo.toml`. Inter-crate dependencies are `[workspace.dependencies]` entries pinned `=<that version>`.

If anything changes in any crate, the version is raised once, for all crates, and all of them are published together in dependency order under that number, with one tag (`v<version>`), one pin in the handoffs, and one push. No crate keeps an older number. A crate that did not change is still re-published at the new number.

The vendored `mail4agent-vodozemac` follows the same rule; the upstream version it forks (0.10.0) is recorded in its `FORK.md`, not in its version.

Order of publication: `mail4agent-api`, `-attest`, `-core`, `-store-sqlite`, `-client`, `-grok`, `-vodozemac`, `-messenger`, `m4a-seam`, `m4a-matrix-core`, `m4a-agent`, `m4a-product-kit`, `mail4agent-server`, `m4a-edge`, `mail4agent-messenger-shell`, `m4a-product-example`, `mail4agent-server-bin`, `mail4agent`. Always dry-run first.

## Which digit moves

Since 0.4.3 the workspace dependency on `m4a-agent` is declared with `default-features = false`; a crate that needs the full pack asks for `features = ["full"]` explicitly (the shell has its own `full` feature that does).

Only the patch component moves on its own: 0.4.0 -> 0.4.1 -> 0.4.2 and so on, without limit, for any change including new features. The minor (second) digit, and anything above it, moves ONLY with the owner's explicit approval. Do not pick 0.5.0 (or 1.0.0) on your own.

Publish order note (0.4.4): the dev-dependency cycle means `mail4agent-messenger-shell` is published before `m4a-product-example`, and `mail4agent-server-bin` last.
