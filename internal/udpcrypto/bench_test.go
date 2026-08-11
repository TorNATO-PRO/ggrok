package udpcrypto_test

import (
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/udpcrypto"
)

// mtuPayloadSize approximates a realistic UDP-mode datagram payload -
// under typical Ethernet MTU once IP/UDP headers and this package's own
// wire overhead are accounted for.
const mtuPayloadSize = 1200

func BenchmarkSeal(b *testing.B) {
	key := [udpcrypto.KeySize]byte{1, 2, 3, 4}
	aead, err := udpcrypto.NewAEAD(key)
	if err != nil {
		b.Fatal(err)
	}

	routing := proto.RoutingID{5, 6, 7, 8}
	payload := make([]byte, mtuPayloadSize)

	b.SetBytes(mtuPayloadSize)
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		_ = udpcrypto.Seal(aead, routing, uint64(i), payload)
	}
}

func BenchmarkSealOpen(b *testing.B) {
	key := [udpcrypto.KeySize]byte{1, 2, 3, 4}
	sendAEAD, err := udpcrypto.NewAEAD(key)
	if err != nil {
		b.Fatal(err)
	}
	recvAEAD, err := udpcrypto.NewAEAD(key)
	if err != nil {
		b.Fatal(err)
	}

	routing := proto.RoutingID{5, 6, 7, 8}
	payload := make([]byte, mtuPayloadSize)
	var window udpcrypto.ReplayWindow

	b.SetBytes(mtuPayloadSize)
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		datagram := udpcrypto.Seal(sendAEAD, routing, uint64(i), payload)
		if _, err := udpcrypto.Open(recvAEAD, &window, datagram); err != nil {
			b.Fatal(err)
		}
	}
}
