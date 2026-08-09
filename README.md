## GGrok

GGrok is a secure stream sharing service, where you may share TCP/UDP streams
directly from your laptop to anyone who has permission to access the stream.

The share/get/relay link runs over QUIC (via `quic-go`), which gives
real UDP datagram forwarding, connection migration (survives a laptop
roaming between networks), and TLS 1.3-native mTLS between nodes with post quantum key exchange.

Features:

- **The relay server never teminates anything**: The relay server serves as a broker for QUIC streams/datagrams by token, so it cannot read your traffic even if compromised, and only metadata (who's talking to whom). Additionally, only UDP needs to be allowed by a firewall since QUIC is an application-level protocol over UDP.

- **QUIC connection migration**: The share/listen sessions will survive a network change (Wifi -> Cellular, VPN -> No VPN). This is something that a plain TCP tunnel cannot do for free, but since we are using QUIC we automatically get this feature.

- **Post-quantum hybrid KEX**: `X25519MLKEM768` is pinned as the only option rather than the negotiable fallback - since every peer is one that speaks the `ggrok/1` protocol, there's no interop reason to allow downgrade.

- **Two-tier trust model**: Cert = "you're allowed on my network", Token = "You're allowed in *this* tunnel."