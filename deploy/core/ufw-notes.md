# Core firewall (ufw) and tunnel (wg-msg)

The core has no public name and exposes nothing publicly. Default deny incoming.

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow from <mgmt-source> to any port 22 proto tcp     # or the tunnel only
    ufw allow in on wg-msg from <edge-wg-ip> to <core-wg-ip> port 8741 proto tcp
    ufw allow 51821/udp                                       # wg-msg listen port, restricted to <edge-public-ip> if it is stable
    ufw enable

Rules: no other inbound; the server refuses wildcard binds and binds only `<core-wg-ip>`; the edge secret header is the
second layer. Do not reuse the MLC chart tunnel or its interface. `wg-msg` notes: see `deploy/core/wg-msg.md`.
