## GGrok

GGrok is a secure file sharing service, where you may share files
directly from your laptop and ignore upload limits.

The share/get/relay link runs over QUIC (via `quic-go`), which gives
real UDP datagram forwarding, connection migration (survives a laptop
roaming between networks), and TLS 1.3-native mTLS between nodes.
