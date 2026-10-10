# mail4agent-server

The messenger core: Matrix-subset client-server routes, rooms, end-to-end key exchange, sync and federation, on an encrypted store (`tesserax-store`: SQLCipher, one writer plus parallel readers). It has no user database, logins or tariffs: identities arrive by signed assertion from a product server (see `m4a-seam`).

This is the library; the process is assembled from it by a binary crate. Part of [mail4agent](https://github.com/ZENG3LD/mail4agent). License: MIT.
