package listen_test

import (
	"context"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
	"tornato.dev/ggrok/v2/internal/share"
)

// faninSubscriberCounts are the subscriber counts BenchmarkUDPTunnelFanIn
// sweeps, all against one share.
//
// This is the axis BenchmarkUDPTunnel cannot reach: it runs a single
// listen, so every datagram crossing relay's subscriber-to-publisher leg
// arrives already packed for the one destination it's bound for, and there
// is nothing to coalesce it with. Fan-in is the case relay's udpSender was
// built for - N subscribers' datagrams pile up in one queue bound for one
// publisher, and merge into one packet instead of N.
var faninSubscriberCounts = []int{1, 2, 4, 8}

const (
	// faninPerSubRate is the offered load *per subscriber*, so total load
	// rises with the subscriber count.
	//
	// Holding the total constant instead would measure nothing: relay's
	// publisher leg is one queue, and what decides whether anything is
	// waiting there to merge is the rate arriving at it. Splitting a fixed
	// total across more subscribers leaves that rate unchanged - it just
	// spreads the same arrivals over more connections, which if anything
	// makes them *less* bursty. More subscribers converging on one
	// publisher is the case worth measuring, and that means more load.
	//
	// 2500 keeps the top of the sweep (8 subscribers, 20k/s) around the
	// knee BenchmarkUDPTunnel's doc comment describes rather than deep
	// past it, where loss swamps the effect being measured. It is also
	// above pacerTick's granularity floor: below 1000/s the pacer degrades
	// to one datagram per tick, which is perfectly smooth arrivals - the
	// worst case for coalescing and not one any real client produces.
	faninPerSubRate = 2_500

	// faninPayloadSize is small enough that many frames fit one datagram,
	// which is where per-packet cost dominates and coalescing pays - see
	// tunnelPayloadSizes.
	faninPayloadSize = 128
)

// BenchmarkUDPTunnelFanIn measures a complete UDP-mode tunnel with several
// subscribers sharing one publisher, sweeping subscriber count at a fixed
// total offered load.
//
// It reports the same metrics as BenchmarkUDPTunnel, aggregated across
// every subscriber. allocs/pkt is the one to read: allocations on this
// path are dominated by quic-go and the kernel socket layer, and both
// scale with *packets* rather than bytes, so it tracks how many packets
// the tunnel emitted per datagram it carried. If relay merges N
// subscribers' backlogged datagrams into one, it falls as the subscriber
// count rises; if each subscriber's traffic crosses the publisher leg in
// its own packet, it stays flat.
func BenchmarkUDPTunnelFanIn(b *testing.B) {
	for _, subs := range faninSubscriberCounts {
		b.Run(strconv.Itoa(subs)+"sub", func(b *testing.B) {
			benchmarkFanIn(b, subs)
		})
	}
}

// benchmarkFanIn runs one BenchmarkUDPTunnelFanIn case: it stands up a
// tunnel with subs subscribers, warms every one of them, then drives them
// all concurrently while counting what comes back.
func benchmarkFanIn(b *testing.B, subs int) {
	b.Helper()

	clients := dialFanInClients(b, subs)

	// Every subscriber offers the same rate and the same share of b.N, so
	// each point in the sweep adds load to the one publisher leg rather
	// than redistributing it - see faninPerSubRate.
	perSub := max(1, b.N/subs)
	perSubRate := faninPerSubRate

	pacers := make([]*pacer, subs)
	readers := make([]*echoReader, subs)
	dones := make([]chan struct{}, subs)
	payload := make([]byte, faninPayloadSize)

	for i, client := range clients {
		pacers[i] = newPacer(perSubRate)
		defer pacers[i].stop()
		warmUpTunnel(client, payload, pacers[i], perSubRate)
	}

	base := time.Now()
	for i, client := range clients {
		readers[i] = &echoReader{base: base, rtts: make([]time.Duration, 0, perSub)}
		dones[i] = make(chan struct{})
		go readers[i].run(client, dones[i])
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	b.ResetTimer()

	offered := make([]int64, subs)
	var wg sync.WaitGroup
	for i, client := range clients {
		wg.Go(func() {
			// Each sender needs its own payload buffer: stampSentAt writes
			// into it, and a shared one would be raced by every goroutine.
			buf := make([]byte, faninPayloadSize)
			offered[i] = pacers[i].send(client, buf, perSub, base)
		})
	}
	wg.Wait()

	b.StopTimer()

	elapsed := b.Elapsed()

	var totalOffered, totalEchoed int64
	for i := range subs {
		totalOffered += offered[i]
		totalEchoed += readers[i].delivered.Load()
	}
	runtime.ReadMemStats(&after)

	for i, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(tunnelDrainWindow))
		<-dones[i]
	}

	// Safe to touch rtts only now: each reader owns its slice until it
	// closes its done channel, and receiving that is what publishes it.
	var rtts []time.Duration
	for i := range subs {
		rtts = append(rtts, readers[i].rtts...)
	}

	reportTunnelMetrics(b, tunnelResult{
		offered: totalOffered,
		echoed:  totalEchoed,
		elapsed: elapsed,
		mallocs: after.Mallocs - before.Mallocs,
		rtts:    rtts,
	})
}

// dialFanInClients stands up a tunnel with subs subscribers and returns a
// connected UDP socket for each, already carrying traffic end to end.
func dialFanInClients(tb testing.TB, subs int) []*net.UDPConn {
	tb.Helper()

	addrs := startFanInTunnel(tb, subs)

	clients := make([]*net.UDPConn, subs)
	for i, addr := range addrs {
		client, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			tb.Fatalf("dial subscriber %d: %v", i, err)
		}
		tb.Cleanup(func() { _ = client.Close() })

		_ = client.SetReadBuffer(clientSocketBufferSize)
		_ = client.SetWriteBuffer(clientSocketBufferSize)

		clients[i] = client
	}

	// Every subscriber has to be carrying traffic before any of them is
	// measured, or the early ones spend the run racing the late ones'
	// startup instead of contending for the publisher leg.
	for _, client := range clients {
		waitForRoundTrip(tb, client)
	}

	return clients
}

// startFanInTunnel brings up one relay and one share publishing an echo
// service, with subs listens all subscribed to it, and returns the local
// address a client writes to for each. Every component is torn down when
// tb finishes.
//
// It's startTunnel with the subscriber count lifted out: the point of the
// fan-in sweep is that all of these share a single publisher connection,
// so their traffic converges on one relay->share leg.
func startFanInTunnel(tb testing.TB, subs int) []*net.UDPAddr {
	tb.Helper()

	ctx, cancel := context.WithCancel(tb.Context())
	tb.Cleanup(cancel)

	pki := newTunnelPKI(tb)
	service := startEchoService(tb)
	relayAddr := loopbackHostPort(tb, freeLoopbackPort(tb))

	token, err := proto.NewToken()
	if err != nil {
		tb.Fatalf("generate token: %v", err)
	}

	go runUntilCanceled(ctx, func(runCtx context.Context) error {
		return relay.Run(runCtx, relay.Config{
			Listen:   relayAddr,
			CertFile: pki.relayCert,
			KeyFile:  pki.relayKey,
			CAFile:   pki.caFile,
			Logger:   slog.New(slog.DiscardHandler),
		})
	})

	go runUntilCanceled(ctx, func(runCtx context.Context) error {
		return share.Run(runCtx, share.Config{
			Server:   relayAddr,
			CertFile: pki.shareCert,
			KeyFile:  pki.shareKey,
			CAFile:   pki.caFile,
			Mode:     proto.ModeUDP,
			Addr:     service,
			Token:    token,
		})
	})

	addrs := make([]*net.UDPAddr, subs)
	for i := range subs {
		localPort := freeLoopbackPort(tb)
		go runUntilCanceled(ctx, func(runCtx context.Context) error {
			return listen.Run(runCtx, listen.Config{
				Server:   relayAddr,
				CertFile: pki.listenCert,
				KeyFile:  pki.listenKey,
				CAFile:   pki.caFile,
				Mode:     proto.ModeUDP,
				Addr:     loopbackRange(tb, localPort),
				Token:    token,
			})
		})

		addrs[i] = &net.UDPAddr{IP: net.ParseIP(loopbackHost), Port: localPort}
	}

	return addrs
}
