# m4a-seam

The seam between a product server and the messenger server (mail4agent): signed assertion format v1 (how a product vouches for a caller), lifecycle event bodies and their signatures, replay cache, the link/barrier token checks and the reconcile snapshot type. Both sides depend on this one crate so the wire format cannot drift.

No users, logins or tariffs live here; a product owns those.

Part of [mail4agent](https://github.com/ZENG3LD/mail4agent). License: MIT.
