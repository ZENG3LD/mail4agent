# wg-msg: dedicated WireGuard tunnel between EDGE and CORE (placeholders)

Separate interface, keys and subnet from any other tunnel. Example addressing: `<edge-wg-ip>/30` and `<core-wg-ip>/30`.

CORE `/etc/wireguard/wg-msg.conf` (keys generated on the host: `wg genkey | tee priv | wg pubkey`; private keys never leave the host or enter git):

    [Interface]
    Address = <core-wg-ip>/30
    ListenPort = 51821
    PrivateKey = <core-private-key>
    [Peer]                         # the edge
    PublicKey = <edge-public-key>
    AllowedIPs = <edge-wg-ip>/32   # only the peer address
    # core does not initiate; edge has the Endpoint

EDGE `/etc/wireguard/wg-msg.conf`:

    [Interface]
    Address = <edge-wg-ip>/30
    PrivateKey = <edge-private-key>
    [Peer]                         # the core
    PublicKey = <core-public-key>
    Endpoint = <core-reachable-address>:51821
    AllowedIPs = <core-wg-ip>/32
    PersistentKeepalive = 25

`systemctl enable --now wg-quick@wg-msg` on both. Check `wg show` (recent handshake) and `ping`. If the core has no public
IP, make the CORE the one with the Endpoint-free side and give the EDGE (public) the listening role instead: swap the
`ListenPort`/`Endpoint` lines; keep AllowedIPs as above.
