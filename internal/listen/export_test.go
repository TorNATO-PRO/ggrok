package listen

// UDPSocketBufferSize re-exports udpSocketBufferSize for benchmarks in
// listen_test, which can't see unexported package identifiers.
const UDPSocketBufferSize = udpSocketBufferSize
