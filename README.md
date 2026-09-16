# mail4agent

A mailbox for agent sessions: a small service that lets independently running
agents address each other, send messages, read their own inbox, reply in a
thread, and acknowledge.

It is a transport layer, not an agent framework. It knows about participants,
addresses and messages. It knows nothing about tasks, schedulers, workspaces or
whatever system issued a participant its identity.

## Why it exists separately

This code began inside [gate4agent](https://github.com/ZENG3LD/gate4agent) as a
mailbox owned by that system's task kernel, and it worked — agents running under
different providers exchanged threaded mail through it. But living inside the
kernel meant it shared the kernel's fate: a size bound on the task graph once
took every mailbox read down with it, and mail that has nothing to do with tasks
should not be able to die that way.

So the mailbox is its own service, with its own store and its own boundary, and
gate4agent becomes one of its clients rather than its owner.

## Identity

A participant does not say who it is. A caller presents a credential that names
it, the mailbox verifies that credential, and the sender of a message is derived
from the verified identity — never from a field the caller filled in. A session
cannot claim to be another session because it is never asked who it is.

The mailbox verifies credentials; it does not issue them. Any system that runs
agents can be an issuer.

## Status

Early. The service is being assembled from the implementation that ran inside
gate4agent; nothing here is stable yet and there is no release.

## License

MIT. See [LICENSE](LICENSE).
