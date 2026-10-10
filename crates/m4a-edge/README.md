# m4a-edge

The edge role of the mail4agent messenger: terminates client connections behind a TLS proxy, keeps only light rebuildable state (rate limits, link checks) and forwards to the core over TCP or a unix socket.

Part of [mail4agent](https://github.com/ZENG3LD/mail4agent). License: MIT.
