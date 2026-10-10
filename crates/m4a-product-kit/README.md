# m4a-product-kit

Building blocks for a product server placed in front of the mail4agent messenger: the `UserStore` trait and `UserService` (nicks, credentials, tiers), optional login doors, `EdgeLink` (authenticate, sign, forward, push relay) and `EventPublisher` with a durable outbox and startup reconcile.

Storage runs on `tesserax-store` (SQLCipher, one writer, batched writes). `dbkey` turns a hex key from the environment into its configuration.

Part of [mail4agent](https://github.com/ZENG3LD/mail4agent). License: MIT.
