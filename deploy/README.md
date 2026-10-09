# deploy/ : how to deploy (the only path)

Everything comes from GitHub. No tarballs, no release artifacts, no values in git.

1. Clone and check out `matrix-compat`, build the binaries yourself: `hub/build-jammy.md`.
2. CORE first (`core/README.md`), then EDGE (`edge/README.md`). Topology: `EDGE-CORE.md`. DB migration: `MIGRATION.md`.
3. Environment files are created by you from the `*.env.example` templates; every variable is explained in the READMEs, and
   secrets are generated on the host with the commands given there. Never commit or paste a real value.
4. Start, then smoke (`edge/smoke.sh`, `core/smoke-core.sh`).
