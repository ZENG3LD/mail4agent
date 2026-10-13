# Encrypted history for new members (feat/history-keys-for-new-members, not deployed)

Before: a member missing a Megolm session asks only the original sender (and its own devices); a receiver accepts a forwarded key only from the original sender or its own account. Offline/gone senders = history stays "[cannot decrypt yet]".

Change (messenger core only, server untouched):
1. Key request targets also include the room admins' devices (power >= 100), only when history_visibility is shared/world_readable.
2. A forwarded room key is accepted from a room admin under the same condition, bound to the original sender's device by its curve key (as before).
3. Answering side unchanged: an admin client forwards any inbound session it holds to a joined/invited member when history is shared.

Trust note: a room admin can vouch for other members' sessions in that room. Rollout: new member's client (hq-m4a on edge) and an admin client holding the keys (hatcheryweb) both need this build; no server change. Follow-up: proactive push on invite (needs a store listing of inbound sessions per room).
