## GGrok

GGrok is a secure stream sharing service, where you may share TCP/UDP streams
directly from your laptop to anyone who has permission to access the stream.

The share/get/relay link runs over QUIC (via `quic-go`), which gives
real UDP datagram forwarding, connection migration (survives a laptop
roaming between networks), and TLS 1.3-native mTLS between nodes with post quantum key exchange.
