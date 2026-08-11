## GGrok

GGrok is a private TCP/UDP tunnel: `share` forwards a local service from your
laptop, `listen` forwards it back out on someone else's, and `relay` brokers
the two over the public internet without ever terminating your traffic at
the application layer. Every node `share`, `listen`, and `relay` is
mutually authenticated by a private CA you run yourself (`ggrok ca`), never
the public web PKI.

The share/listen/relay link runs over plain TCP+TLS 1.3. UDP-mode
tunnels get their own encryption on top: each hop's traffic is sealed with
ChaCha20-Poly1305 using a key derived straight from that hop's TLS
connection (RFC 5705 keying-material export, no separate handshake), with a
sliding replay window standing in for the ordering guarantees a stream
transport gets for free. See `internal/udpcrypto` and `internal/relay/udp.go`
for the mechanism.

Features:

- **The relay server never parses your traffic**: relay pairs a `share` and its `listen` subscribers by token and splices bytes/datagrams between them, and it authenticates and terminates mTLS with each peer independently, but it never understands the protocol running over your forwarded service. In UDP mode it does have to read (and re-frame) a small routing header per datagram to fan traffic out to the right subscriber. For more information, see the "Fan-out design" section of `docs/plans/tcp-udp-tunnel.md`.

- **Post-quantum hybrid KEX**: `X25519MLKEM768` is pinned as the only option rather than a negotiable fallback - since every peer speaks the `ggrok/1` protocol over our own CA, there's no interop reason to allow downgrade.

- **Two-tier trust model**: cert = "you're allowed on my network", token = "you're allowed in *this* tunnel."

- **Firewall note**: relay needs *both* the TCP and UDP ports open at whatever `-listen` address you give it. That same port recognizes both TCP and UDP.
