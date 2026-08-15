package listen

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// BenchmarkUDPBurstDrop measures what udpSocketBufferSize actually
// protects against: not steady-state throughput (which isn't buffer-bound
// - each datagram still costs its own read syscall regardless of SO_RCVBUF
// size), but how much of a burst survives arriving before the read loop
// gets a chance to drain it. It fires burstPackets at a UDP socket with no
// reader running yet, only starts draining once the whole burst has been
// written, and reports what fraction never made it - this is the exact
// "OS receive buffer overflows and silently drops packets" scenario
// udpSocketBufferSize's doc comment describes.
func BenchmarkUDPBurstDrop(b *testing.B) {
	const (
		burstPackets = 8000
		packetSize   = 512
		drainWindow  = 200 * time.Millisecond
	)

	cases := []struct {
		name       string
		bufferSize int // 0 = leave at OS default
	}{
		{"OSDefault", 0},
		{"256KiB", 256 * 1024},
		{"1MiB", 1 * 1024 * 1024},
		{"4MiB", 4 * 1024 * 1024},
		{"8MiB (current)", udpSocketBufferSize},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var totalSent, totalRecv int64

			for i := 0; i < b.N; i++ {
				server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					b.Fatal(err)
				}
				if tc.bufferSize > 0 {
					_ = server.SetReadBuffer(tc.bufferSize)
				}

				client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}

				payload := make([]byte, packetSize)

				// Write the entire burst before a single read happens -
				// the worst case udpSocketBufferSize exists for: the app
				// is momentarily not reading (GC pause, scheduler
				// contention, a slow iteration of the read loop) while
				// datagrams keep arriving.
				for range burstPackets {
					_, _ = client.Write(payload)
				}
				_ = client.Close()

				_ = server.SetReadDeadline(time.Now().Add(drainWindow))
				buf := make([]byte, packetSize)
				var recv int64
				for {
					_, _, err := server.ReadFromUDP(buf)
					if err != nil {
						break
					}
					recv++
				}
				_ = server.Close()

				totalSent += burstPackets
				totalRecv += recv
			}

			lossPct := 100 * float64(totalSent-totalRecv) / float64(totalSent)
			b.ReportMetric(lossPct, "%loss")
		})
	}
}

// BenchmarkUDPThroughput measures sustained loopback UDP throughput with a
// reader continuously draining (unlike BenchmarkUDPBurstDrop's
// read-nothing-until-the-burst-ends setup) - the steady-state case, where
// each datagram still costs its own syscall regardless of SO_RCVBUF size.
// Run across both a realistic MTU-ish payload and a small one, and across
// OS-default vs udpSocketBufferSize, to check whether the buffer tuning
// that eliminated burst loss (BenchmarkUDPBurstDrop) has any steady-state
// throughput effect too.
func BenchmarkUDPThroughput(b *testing.B) {
	sizes := []int{64, 512, 1200, 8192}

	for _, payloadSize := range sizes {
		for _, tc := range []struct {
			name       string
			bufferSize int // 0 = leave at OS default
		}{
			{"OSDefault", 0},
			{"tuned", udpSocketBufferSize},
		} {
			b.Run(fmt.Sprintf("%dB/%s", payloadSize, tc.name), func(b *testing.B) {
				server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					b.Fatal(err)
				}
				defer func() { _ = server.Close() }()
				if tc.bufferSize > 0 {
					_ = server.SetReadBuffer(tc.bufferSize)
				}

				client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
				if err != nil {
					b.Fatal(err)
				}
				defer func() { _ = client.Close() }()
				if tc.bufferSize > 0 {
					_ = client.SetWriteBuffer(tc.bufferSize)
				}

				var recv int64
				readerDone := make(chan struct{})
				go func() {
					defer close(readerDone)
					buf := make([]byte, payloadSize)
					for {
						_, _, err := server.ReadFromUDP(buf)
						if err != nil {
							return
						}
						recv++
					}
				}()

				payload := make([]byte, payloadSize)
				b.SetBytes(int64(payloadSize))
				b.ResetTimer()

				for range b.N {
					if _, err := client.Write(payload); err != nil {
						b.Fatal(err)
					}
				}

				b.StopTimer()
				_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				<-readerDone

				lossPct := 100 * float64(int64(b.N)-recv) / float64(b.N)
				b.ReportMetric(lossPct, "%loss")
			})
		}
	}
}
