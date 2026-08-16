package listen_test

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
	"tornato.dev/ggrok/v2/internal/share"
)

// tunnelPayloadSizes are the local-datagram sizes BenchmarkUDPTunnel
// sweeps. They stay well under the ~1200-byte ceiling a QUIC DATAGRAM
// frame can carry, because anything above it is silently discarded rather
// than fragmented - see TestUDPTunnelDropsOversizedDatagram, which pins
// that behavior. The interesting end is the small one: a UDP tunnel's real
// workloads (game traffic, DNS, VoIP) are dominated by packets in the
// 64-512 byte range, where per-datagram cost, not bandwidth, is what
// bounds throughput.
var tunnelPayloadSizes = []int{64, 512, 1024}

// tunnelOfferedRates are the offered loads, in datagrams per second, that
// BenchmarkUDPTunnel sweeps at each payload size.
//
// The sweep exists because this tunnel does not have a single throughput
// number. Past a knee, goodput *falls* as offered load rises - every
// component drops datagrams only after paying to read, decode, re-frame
// and enqueue them, so overload converts throughput into wasted work
// (see BenchmarkUDPTunnel's doc comment). A single-point benchmark
// therefore measures whichever side of the knee it happens to land on.
//
// Keep the top of this range comfortably past the knee: the point of the
// sweep is to show where goodput peaks and how badly it degrades after,
// and both of those should move when the tunnel gets faster.
var tunnelOfferedRates = []int{5_000, 10_000, 20_000, 30_000, 40_000, 80_000}

const (
	// tunnelReadyTimeout bounds how long the harness waits for relay,
	// share and listen to converge into a path that actually carries a
	// datagram. Generous because it covers three mTLS handshakes, a QUIC
	// handshake, and however many retries the components need to find each
	// other in whatever order the scheduler starts them.
	tunnelReadyTimeout = 30 * time.Second

	// componentRetryDelay is how long a component waits before redialing
	// after a failed start, and doubles as the per-attempt read timeout
	// while waiting for the tunnel's first end-to-end round trip.
	componentRetryDelay = 20 * time.Millisecond

	// pacerTick is how often the load generator releases a burst. Fine
	// enough that a burst stays small (20 datagrams at 20k/s, well inside
	// the socket buffers on the path), coarse enough that Go's timer
	// granularity still delivers the rate accurately - check the reported
	// offered-pkt/s against the subtest name if that's ever in doubt.
	pacerTick = time.Millisecond

	// warmupDuration is how long the tunnel is driven at the measured rate
	// before the timer starts, and warmupMinPackets floors that for the
	// slowest rates. Warming up at the rate being measured, rather than
	// flooding, matters: a flood would leave QUIC's congestion controller
	// backed off at exactly the moment measurement begins.
	warmupDuration    = 200 * time.Millisecond
	warmupMinPackets  = 500
	warmupQuietPeriod = 100 * time.Millisecond

	// tunnelDrainWindow is how long the reader goroutine is given to
	// finish after the run ends. Deliveries counted here are *not* in the
	// reported numbers (those are snapshotted the moment the timer stops)
	// - this window exists only to let the reader exit cleanly.
	tunnelDrainWindow = 250 * time.Millisecond

	// clientSocketBufferSize sizes the load generator's own socket
	// buffers, so the benchmark measures the tunnel rather than the
	// harness's ability to keep up with it.
	clientSocketBufferSize = 8 * 1024 * 1024

	// tunnelClientReadBuffer is the read buffer for echoed datagrams -
	// larger than any payload this benchmark sends, so a reply is never
	// truncated.
	tunnelClientReadBuffer = 64 * 1024

	// maxTransientReadErrors bounds how many non-timeout read errors the
	// reader goroutine shrugs off before giving up. A connected UDP socket
	// surfaces ICMP port-unreachable as a read error on Linux, so a single
	// error doesn't mean the run is over - but a steady stream of them
	// does, and spinning on it would burn a core and corrupt the result.
	maxTransientReadErrors = 64

	// percent converts a ratio into the percentage ReportMetric prints,
	// and doubles as the denominator for p50/p99, the two round-trip
	// percentiles reported. p99 is the one that matters for real-time
	// traffic: a jitter buffer has to be sized for the tail, not the
	// median.
	percent = 100
	p50     = 50
	p99     = 99

	// timestampSize is how many leading payload bytes stampSentAt claims.
	// Every payload the benchmark sends is far larger, but a reply short
	// enough to lack one is still counted as delivered - it just can't be
	// timed.
	timestampSize = 8

	// loopbackHost is the address every component in the harness binds.
	loopbackHost = "127.0.0.1"
)

// BenchmarkUDPTunnel measures a complete UDP-mode ggrok tunnel -
// listen -> relay -> share -> service and all the way back - with every
// component running in this process, sweeping payload size against offered
// load.
//
// Read it as a curve, not a number. Goodput rises with offered load up to
// a knee and then *falls*: every stage of this tunnel drops datagrams only
// after paying to read, frame and enqueue them (listen's uplink channel,
// relay's udpSender queue, quic-go's own 32-deep send and 128-deep receive
// queues), so past saturation an ever-larger share of the CPU goes to
// packets that get thrown away. The two numbers worth tracking are where
// goodput peaks and how far it has fallen by the top of the sweep.
//
// Reported metrics:
//
//   - goodput-pkt/s: datagrams per second that survived the round trip.
//     The headline number.
//   - offered-pkt/s: what the generator actually pushed in, which should
//     track the rate in the subtest name. Worth keeping in view: without
//     it, a %loss figure can't be told apart from a pacer that fell short
//     of its target rate.
//   - %loss: the gap between the two.
//   - p50-us / p99-us: round-trip time through the whole path, in
//     microseconds. Reported per offered rate on purpose - what matters
//     for real-time traffic isn't latency at idle, it's how far the tail
//     stretches as the tunnel fills up, since that's what a jitter buffer
//     has to be sized for.
//   - allocs/pkt: heap allocations per offered datagram. Since relay,
//     share and listen all run in this process, this counts the whole
//     pipeline, not one component - which is exactly what's wanted when
//     the work is removing per-datagram allocations. Per *offered* rather
//     than per delivered datagram, because most allocations happen before
//     the drop decision, so charging them only to survivors would make the
//     number swing with loss instead of with allocation behavior.
//
// Compare allocs/pkt only at rates below the knee. Past it the number
// drops sharply, but that is not an improvement: a dropped datagram is
// simply cheaper than a delivered one, so heavy loss flatters the average.
// The rates where loss is ~0 are the ones that say what a round trip
// actually costs.
//
// BenchmarkUDPThroughput in udp_bench_test.go is this benchmark's ceiling:
// the same loopback datagrams with no tunnel in the path at all.
//
// Note that ns/op is just the pacing interval and carries no information;
// read the reported metrics instead.
func BenchmarkUDPTunnel(b *testing.B) {
	for _, payloadSize := range tunnelPayloadSizes {
		for _, rate := range tunnelOfferedRates {
			name := strconv.Itoa(payloadSize) + "B/" + strconv.Itoa(rate/1000) + "kpps"
			b.Run(name, func(b *testing.B) {
				benchmarkTunnelPayload(b, payloadSize, rate)
			})
		}
	}
}

// TestUDPTunnelDropsOversizedDatagram pins the ceiling tunnelPayloadSizes
// stays under: a local datagram too large for a QUIC DATAGRAM frame is
// silently discarded, because quic-go's SendDatagram rejects it and every
// call site drops that error. listen and share both read up to 64KiB off
// their local sockets, so nothing upstream of the send even notices.
//
// The test sends a small datagram, then an oversized one, then a small one
// again: the bracketing round trips prove the tunnel was healthy on either
// side, so the missing reply in the middle is the size limit and not a
// flaky path.
func TestUDPTunnelDropsOversizedDatagram(t *testing.T) {
	t.Parallel()

	const (
		smallPayload = 64
		hugePayload  = 4096
	)

	client := dialTunnelClient(t)
	waitForRoundTrip(t, client)

	if !echoes(t, client, smallPayload) {
		t.Fatal("small datagram did not round-trip through a healthy tunnel")
	}
	if echoes(t, client, hugePayload) {
		t.Errorf("a %d-byte datagram round-tripped; the QUIC DATAGRAM ceiling is far lower, "+
			"so either quic-go now fragments or the harness is measuring the wrong path", hugePayload)
	}
	if !echoes(t, client, smallPayload) {
		t.Error("tunnel stopped carrying small datagrams after an oversized one - " +
			"an oversized datagram should be dropped, not wedge the path")
	}
}

// benchmarkTunnelPayload runs one BenchmarkUDPTunnel case: it stands up a
// tunnel, warms it at the target rate, then offers payloadSize datagrams
// at that rate while a second goroutine counts what comes back.
func benchmarkTunnelPayload(b *testing.B, payloadSize, rate int) {
	b.Helper()

	client := dialTunnelClient(b)
	waitForRoundTrip(b, client)

	pace := newPacer(rate)
	defer pace.stop()

	payload := make([]byte, payloadSize)
	warmUpTunnel(client, payload, pace, rate)

	// Preallocated so recording a round-trip time never allocates inside
	// the measured window, where it would show up as the pipeline's own
	// allocation. The reader stops recording rather than growing it.
	echoes := &echoReader{base: time.Now(), rtts: make([]time.Duration, 0, b.N)}
	readerDone := make(chan struct{})
	go echoes.run(client, readerDone)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	b.ResetTimer()
	offered := pace.send(client, payload, b.N, echoes.base)
	b.StopTimer()

	// Snapshot before draining: everything below is measured over the
	// offered window alone, so the tail of in-flight replies can't inflate
	// the rate. That backlog is bounded by the pipeline's queue depths
	// (a few hundred datagrams), which is noise at benchmark scale.
	elapsed := b.Elapsed()
	echoed := echoes.delivered.Load()
	runtime.ReadMemStats(&after)

	_ = client.SetReadDeadline(time.Now().Add(tunnelDrainWindow))
	<-readerDone

	// Safe to touch rtts only now: the reader owns it until it's done, and
	// receiving on readerDone is what publishes its writes. Trimming to
	// echoed keeps the percentiles over the same window as everything else.
	reportTunnelMetrics(b, tunnelResult{
		offered: offered,
		echoed:  echoed,
		elapsed: elapsed,
		mallocs: after.Mallocs - before.Mallocs,
		rtts:    echoes.rtts[:min(int(echoed), len(echoes.rtts))],
	})
}

// tunnelResult is one measured run, kept as a struct so
// reportTunnelMetrics doesn't take five positional values.
type tunnelResult struct {
	offered int64
	echoed  int64
	elapsed time.Duration
	mallocs uint64
	rtts    []time.Duration
}

// reportTunnelMetrics turns a measured run into the metrics
// BenchmarkUDPTunnel's doc comment describes. It sorts rtts in place.
func reportTunnelMetrics(b *testing.B, r tunnelResult) {
	b.Helper()

	if r.offered == 0 || r.elapsed <= 0 {
		b.Fatal("no datagrams were offered to the tunnel")
	}

	seconds := r.elapsed.Seconds()
	b.ReportMetric(float64(r.echoed)/seconds, "goodput-pkt/s")
	b.ReportMetric(float64(r.offered)/seconds, "offered-pkt/s")
	b.ReportMetric(max(0, percent*float64(r.offered-r.echoed)/float64(r.offered)), "%loss")
	b.ReportMetric(float64(r.mallocs)/float64(r.offered), "allocs/pkt")

	slices.Sort(r.rtts)
	b.ReportMetric(microseconds(percentileAt(r.rtts, p50)), "p50-us")
	b.ReportMetric(microseconds(percentileAt(r.rtts, p99)), "p99-us")
}

// percentileAt returns the pct'th percentile of an already-sorted sample
// set by nearest rank, or zero if nothing was sampled.
func percentileAt(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}

	return sorted[(len(sorted)-1)*pct/percent]
}

// microseconds renders a duration for ReportMetric without truncating the
// sub-microsecond part the way Duration.Microseconds would.
func microseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Microsecond)
}

// pacer offers datagrams in small bursts on a fixed tick, so the benchmark
// can hold the tunnel at a chosen load instead of only ever flooding it.
type pacer struct {
	ticker  *time.Ticker
	perTick int
}

// newPacer builds a pacer for rate datagrams per second.
func newPacer(rate int) *pacer {
	return &pacer{
		ticker:  time.NewTicker(pacerTick),
		perTick: max(1, rate*int(pacerTick)/int(time.Second)),
	}
}

// send offers count datagrams at the pacer's rate and reports how many the
// socket accepted. A write can fail with ENOBUFS once the local send
// buffer fills; that datagram never entered the tunnel, so counting it
// would show up as loss the tunnel didn't cause.
//
// Each datagram is stamped with how long after base it was written, so the
// reader can subtract that from its own clock to get a round-trip time -
// see stampSentAt.
func (p *pacer) send(client *net.UDPConn, payload []byte, count int, base time.Time) int64 {
	var offered int64

	for sent := 0; sent < count; {
		<-p.ticker.C
		for range min(p.perTick, count-sent) {
			stampSentAt(payload, base)
			if _, err := client.Write(payload); err == nil {
				offered++
			}
			sent++
		}
	}

	return offered
}

// stampSentAt writes the moment a datagram is handed to the socket into
// its leading bytes. It's an offset from a benchmark-local reference
// rather than a wall-clock time, so the arithmetic on the way back runs on
// Go's monotonic clock and can't be skewed by the system clock moving.
func stampSentAt(payload []byte, base time.Time) {
	binary.BigEndian.PutUint64(payload, uint64(time.Since(base)))
}

// echoReader tallies datagrams coming back through the tunnel and records
// what each one's round trip cost.
//
// The echo service returns payloads untouched, so the stamp written by
// stampSentAt survives the trip and the difference against the same
// reference is the full path: client -> listen -> relay -> share ->
// service and all the way back.
type echoReader struct {
	delivered atomic.Int64

	// base is the reference stampSentAt measures from, and rtts collects
	// one sample per datagram that made it back. rtts belongs to the
	// reader goroutine until it closes its done channel; nothing else may
	// touch it before then.
	base time.Time
	rtts []time.Duration
}

// run reads echoes until the socket's read deadline expires or it closes.
func (e *echoReader) run(client *net.UDPConn, done chan<- struct{}) {
	defer close(done)

	buf := make([]byte, tunnelClientReadBuffer)
	var transient int
	for {
		n, err := client.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed) {
				return
			}
			if transient++; transient > maxTransientReadErrors {
				return
			}
			continue
		}

		e.delivered.Add(1)

		// Recording stops rather than growing the slice: an append past
		// capacity would allocate, and allocations inside the measured
		// window are supposed to be the tunnel's, not the harness's.
		if n >= timestampSize && len(e.rtts) < cap(e.rtts) {
			sentAt := time.Duration(binary.BigEndian.Uint64(buf))
			e.rtts = append(e.rtts, time.Since(e.base)-sentAt)
		}
	}
}

// stop releases the pacer's ticker.
func (p *pacer) stop() { p.ticker.Stop() }

// warmUpTunnel drives the tunnel at the rate about to be measured and then
// collects every reply. It exists to get three things out of the measured
// window: listen's flow-table entry and share's NAT entry for this client
// (each costs a local dial on first sight), and QUIC's congestion window,
// which starts small and would otherwise make the front of a run measure
// slow-start instead of steady state.
func warmUpTunnel(client *net.UDPConn, payload []byte, pace *pacer, rate int) {
	count := max(warmupMinPackets, rate*int(warmupDuration)/int(time.Second))
	pace.send(client, payload, count, time.Now()) // stamps go nowhere; nothing is timed yet

	buf := make([]byte, tunnelClientReadBuffer)
	for {
		_ = client.SetReadDeadline(time.Now().Add(warmupQuietPeriod))
		if _, err := client.Read(buf); err != nil {
			break
		}
	}
	_ = client.SetReadDeadline(time.Time{})
}

// waitForRoundTrip blocks until a datagram written to client comes back,
// which is the only honest signal that all three components have finished
// finding each other: relay accepting, share registered with its QUIC
// publisher connection attached, and listen subscribed with its own.
func waitForRoundTrip(tb testing.TB, client *net.UDPConn) {
	tb.Helper()

	probe := []byte("ggrok-tunnel-probe")
	buf := make([]byte, len(probe))

	deadline := time.Now().Add(tunnelReadyTimeout)
	for time.Now().Before(deadline) {
		if _, err := client.Write(probe); err != nil {
			time.Sleep(componentRetryDelay)
			continue
		}

		_ = client.SetReadDeadline(time.Now().Add(componentRetryDelay))
		if _, err := client.Read(buf); err == nil {
			_ = client.SetReadDeadline(time.Time{})
			return
		}
	}

	tb.Fatalf("tunnel carried no datagram end to end within %s", tunnelReadyTimeout)
}

// echoes reports whether a datagram of size bytes makes it through the
// tunnel and back within the round-trip window.
func echoes(tb testing.TB, client *net.UDPConn, size int) bool {
	tb.Helper()

	const echoWindow = 2 * time.Second

	if _, err := client.Write(make([]byte, size)); err != nil {
		tb.Fatalf("write %d-byte datagram: %v", size, err)
	}

	buf := make([]byte, tunnelClientReadBuffer)
	_ = client.SetReadDeadline(time.Now().Add(echoWindow))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()

	n, err := client.Read(buf)
	return err == nil && n == size
}

// dialTunnelClient stands up a tunnel and returns a UDP socket connected
// to its local end - the "client" of whatever service the share is
// forwarding.
func dialTunnelClient(tb testing.TB) *net.UDPConn {
	tb.Helper()

	client, err := net.DialUDP("udp", nil, startTunnel(tb))
	if err != nil {
		tb.Fatalf("dial tunnel: %v", err)
	}
	tb.Cleanup(func() { _ = client.Close() })

	_ = client.SetReadBuffer(clientSocketBufferSize)
	_ = client.SetWriteBuffer(clientSocketBufferSize)

	return client
}

// startTunnel brings up a complete UDP-mode ggrok tunnel in this process -
// a relay, a share publishing an echo service, and a listen subscribed to
// it - and returns the local address a client writes to. Every component
// is torn down when tb finishes.
//
// Each component runs under runUntilCanceled rather than being started
// once, because they have to be started in some order but can only
// succeed in another: listen's Subscribe fails until share has registered,
// and share's QUIC dial fails until relay's listener is up. Retrying is
// simpler, and more like the real deployment, than choreographing them.
func startTunnel(tb testing.TB) *net.UDPAddr {
	tb.Helper()

	ctx, cancel := context.WithCancel(tb.Context())
	tb.Cleanup(cancel)

	pki := newTunnelPKI(tb)
	service := startEchoService(tb)
	relayAddr := loopbackHostPort(tb, freeLoopbackPort(tb))
	localPort := freeLoopbackPort(tb)

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
			// relay's default handler writes every attach and detach to
			// stderr, which would bury the benchmark's own output.
			Logger: slog.New(slog.DiscardHandler),
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

	go runUntilCanceled(ctx, func(runCtx context.Context) error {
		return listen.Run(runCtx, listen.Config{
			Server:   relayAddr,
			CertFile: pki.listenCert,
			KeyFile:  pki.listenKey,
			CAFile:   pki.caFile,
			Mode:     proto.ModeUDP,
			// A fixed port rather than 0, so a listen that restarts while
			// converging comes back at the address the client is already
			// writing to.
			Addr:  loopbackHostPort(tb, localPort),
			Token: token,
		})
	})

	return &net.UDPAddr{IP: net.ParseIP(loopbackHost), Port: localPort}
}

// runUntilCanceled keeps run alive for as long as ctx does, restarting it
// after a failure. Errors are swallowed deliberately: during startup they
// are the expected "the other component isn't up yet" case, and after
// cancellation they are just the teardown.
func runUntilCanceled(ctx context.Context, run func(context.Context) error) {
	for ctx.Err() == nil {
		_ = run(ctx)
		if ctx.Err() != nil {
			return
		}
		time.Sleep(componentRetryDelay)
	}
}

// startEchoService runs the local service a share forwards to: a UDP
// socket that writes every datagram straight back where it came from. Its
// socket buffers are oversized so the service itself never becomes the
// bottleneck the benchmark ends up measuring.
func startEchoService(tb testing.TB) hostport.HostPort {
	tb.Helper()

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(loopbackHost)})
	if err != nil {
		tb.Fatalf("listen echo service: %v", err)
	}
	tb.Cleanup(func() { _ = socket.Close() })

	_ = socket.SetReadBuffer(clientSocketBufferSize)
	_ = socket.SetWriteBuffer(clientSocketBufferSize)

	go func() {
		buf := make([]byte, tunnelClientReadBuffer)
		for {
			n, from, readErr := socket.ReadFromUDPAddrPort(buf)
			if readErr != nil {
				return
			}
			_, _ = socket.WriteToUDPAddrPort(buf[:n], from)
		}
	}()

	return loopbackHostPort(tb, socket.LocalAddr().(*net.UDPAddr).Port)
}

// tunnelPKI is a throwaway CA and the three certificates a tunnel needs:
// one for relay (which also authenticates as a server) and one each for
// the share and listen peers. They're separate certs because relay pins a
// UDP data connection to the certificate its control connection
// authenticated with, per peer - sharing one would test less than the real
// thing does.
type tunnelPKI struct {
	caFile     string
	relayCert  string
	relayKey   string
	shareCert  string
	shareKey   string
	listenCert string
	listenKey  string
}

// newTunnelPKI generates a fresh CA and issues the tunnel's certificates
// into a temporary directory, since every component takes its credentials
// as file paths.
func newTunnelPKI(tb testing.TB) tunnelPKI {
	tb.Helper()

	root, err := ca.Init("ggrok-bench-ca", ca.DefaultCAValidity)
	if err != nil {
		tb.Fatalf("init ca: %v", err)
	}

	authority, err := ca.Load(root.CertPEM, root.KeyPEM)
	if err != nil {
		tb.Fatalf("load ca: %v", err)
	}

	dir := tb.TempDir()
	pki := tunnelPKI{
		caFile:     filepath.Join(dir, "ca.crt"),
		relayCert:  filepath.Join(dir, "relay.crt"),
		relayKey:   filepath.Join(dir, "relay.key"),
		shareCert:  filepath.Join(dir, "share.crt"),
		shareKey:   filepath.Join(dir, "share.key"),
		listenCert: filepath.Join(dir, "listen.crt"),
		listenKey:  filepath.Join(dir, "listen.key"),
	}
	writePEM(tb, pki.caFile, root.CertPEM)

	// relay needs a server certificate carrying the loopback IP, since its
	// peers dial it by address and verify the SAN like any TLS client.
	relayBundle := issue(tb, authority, ca.IssueRequest{
		CommonName: "relay",
		Validity:   ca.DefaultDeviceValidity,
		Server:     true,
		IPs:        []net.IP{net.ParseIP(loopbackHost)},
	})
	writePEM(tb, pki.relayCert, relayBundle.CertPEM)
	writePEM(tb, pki.relayKey, relayBundle.KeyPEM)

	shareBundle := issue(tb, authority, ca.IssueRequest{CommonName: "share", Validity: ca.DefaultDeviceValidity})
	writePEM(tb, pki.shareCert, shareBundle.CertPEM)
	writePEM(tb, pki.shareKey, shareBundle.KeyPEM)

	listenBundle := issue(tb, authority, ca.IssueRequest{CommonName: "listen", Validity: ca.DefaultDeviceValidity})
	writePEM(tb, pki.listenCert, listenBundle.CertPEM)
	writePEM(tb, pki.listenKey, listenBundle.KeyPEM)

	return pki
}

// issue signs one certificate or fails the test.
func issue(tb testing.TB, authority *ca.CA, request ca.IssueRequest) *ca.Bundle {
	tb.Helper()

	bundle, err := authority.Issue(request)
	if err != nil {
		tb.Fatalf("issue %s certificate: %v", request.CommonName, err)
	}

	return bundle
}

// writePEM writes one PEM file with key-appropriate permissions.
func writePEM(tb testing.TB, path string, pem []byte) {
	tb.Helper()

	if err := os.WriteFile(path, pem, 0o600); err != nil {
		tb.Fatalf("write %s: %v", path, err)
	}
}

// freeLoopbackPort finds a port free on both TCP and UDP - relay needs
// both at the same number, since it binds a TCP listener and a QUIC
// listener to the one address. There's an unavoidable race between
// releasing the probe sockets and the caller binding for real; retrying
// makes it vanishingly unlikely to matter.
func freeLoopbackPort(tb testing.TB) int {
	tb.Helper()

	const attempts = 20

	for range attempts {
		tcpProbe, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
		if err != nil {
			continue
		}

		port := tcpProbe.Addr().(*net.TCPAddr).Port
		udpProbe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(loopbackHost), Port: port})
		_ = tcpProbe.Close()
		if err != nil {
			continue
		}
		_ = udpProbe.Close()

		return port
	}

	tb.Fatalf("no port free on both tcp and udp after %d attempts", attempts)
	return 0
}

// loopbackHostPort builds the loopback address on port in the form every
// component's Config takes.
func loopbackHostPort(tb testing.TB, port int) hostport.HostPort {
	tb.Helper()

	pair, err := hostport.Parse(net.JoinHostPort(loopbackHost, strconv.Itoa(port)))
	if err != nil {
		tb.Fatalf("parse loopback address: %v", err)
	}

	return pair
}
