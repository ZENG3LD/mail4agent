# mail4agent-vodozemac

A vendored, reduced and MODIFIED fork of [vodozemac](https://github.com/matrix-org/vodozemac) 0.10.0 (Olm, Megolm and SAS for Matrix), published under its own name for use by mail4agent. It is not the upstream crate; for the original use `vodozemac`.

Upstream: matrix-org/vodozemac, tag 0.10.0, commit bb39ec65357989f975e0d47f9fb35e0656180151. Copyright 2021-2024 The Matrix.org Foundation C.I.C., Damir Jelic, Denis Kasak and the vodozemac contributors. Licensed under the Apache License 2.0 (see `LICENSE`, `NOTICE`).

Changes (details in `FORK.md`): the `ecies`, `hazmat` and `pk_encryption` modules, libolm pickle compatibility and MSC3814 device dehydration are removed; tests that needed the C libolm are converted or dropped. Modified source files carry a notice at the top. No trademark of upstream or of the Matrix.org Foundation is claimed; this crate is not affiliated with them.
