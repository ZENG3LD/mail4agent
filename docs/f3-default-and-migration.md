# Hash-id rooms: the default, and moving old rooms

From 0.4.0 the `f3-hash-ids` feature is on by default in `mail4agent-server` and `mail4agent-server-bin`. A room created after the upgrade is a Matrix room version 11 room whenever it is closed (a group, a direct room, an encrypted room, a space with closed members): its events carry hash ids (the reference hash, as the spec says), `prev_events`, `auth_events`, `depth`, a content hash and the server's ed25519 signature; every event is checked against the auth rules on write; forks made by federation are merged with state resolution v2. A public plaintext channel stays on the legacy event path (opaque ids, no DAG), as before.

Building with `--no-default-features` (or without the feature) gives a server that makes legacy rooms only. It still reads and serves every hash-id room it has, as long as it was built with the feature once; a database written with the feature on should not be opened by a build without it.

## What does not change

Rooms that already exist keep their ids, their history and their delivery. Nothing is rewritten, nothing is converted in place, no user is re-imported. The legacy read path stays: messages, sync, `/messages`, relations, search and federation of legacy rooms (`m4a-fed-1`) work as before, and a hash-id room and a legacy room can sit side by side in one account and one space.

## Moving an old room to a hash-id room

A legacy room becomes a version 11 hash-id room by an upgrade, as Matrix does it: `POST /_matrix/client/v3/rooms/{roomId}/upgrade` with `{"new_version": "11"}`, by the room's creator or an admin (power 100). The server creates the new room (same kind, name, topic, avatar, join rules, history visibility, power levels; for a space, its `m.space.child` entries), puts `predecessor` (old room id and last event id) in the new room's create event, moves the room's local aliases to it, and writes `m.room.tombstone` with `replacement_room` into the old room. People follow the tombstone and join the new room; history of the old room stays readable there. Direct rooms are not upgraded (a pair of users has one direct room); they are replaced by starting a new direct room when wanted. The response is `{"replacement_room": "<new id>"}`.

Order for an operator: upgrade the server first; let new rooms be hash-id rooms; upgrade old rooms one by one when their people are ready (a client shows the tombstone banner); do not mass-upgrade.

## Federation between old and new

Two servers of this family exchange legacy rooms by `m4a-fed-1` and hash-id rooms by the spec's federation API, depending on the room. A server that follows the spec (Synapse) takes part in hash-id rooms only: public rooms in both directions, closed rooms by invite from either side. A legacy room is never offered to a spec server.

## Things to know

- A database with hash-id rooms has extra tables (`dag_*`, `fed_pdus`); they are created on start, no manual migration.
- After a closed room's messages are delivered, the retention purge erases their content and keeps id, signatures and hashes (a skeleton), so the DAG stays checkable; the room's history is then served to peers as skeletons.
- Rolling back to a build without the feature is not supported once hash-id rooms exist; roll back from a copy of the database made before the upgrade.
