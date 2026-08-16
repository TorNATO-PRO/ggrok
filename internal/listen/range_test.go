package listen_test

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"testing"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
	"tornato.dev/ggrok/v2/internal/share"
)

// rangePorts is how many ports the range tests forward. Three is the
// smallest count that distinguishes a working index mapping from the two
// ways it goes wrong: everything landing on the first port, and the range
// being walked backwards.
const rangePorts = 3

// TestTCPPortRange forwards a range of TCP ports and checks each local
// port reaches the service behind the port at the same *index* of the
// publisher's range - not the same number. The two ranges deliberately use
// different numbers, since a mapping that quietly matched on port number
// would pass an equal-numbered test and fail every real one.
func TestTCPPortRange(t *testing.T) {
	t.Parallel()

	services := startTCPServices(t, rangePorts)
	local := startRangeTunnel(t, proto.ModeTCP, services)

	for i := range rangePorts {
		addr, ok := local.At(i)
		if !ok {
			t.Fatalf("local range has no port %d", i)
		}

		got := dialTCPUntilReady(t, addr.String())
		if want := serviceGreeting(i); got != want {
			t.Errorf("port index %d reached %q, want %q", i, got, want)
		}
	}
}

// TestUDPPortRange is TestTCPPortRange's UDP-mode counterpart. It's the
// more interesting of the two: TCP carries the port index once, in the
// Attach that sets a connection up, while UDP carries it in the header of
// every single datagram and relies on relay passing that header through
// untouched.
func TestUDPPortRange(t *testing.T) {
	t.Parallel()

	services := startUDPServices(t, rangePorts)
	local := startRangeTunnel(t, proto.ModeUDP, services)

	for i := range rangePorts {
		addr, ok := local.At(i)
		if !ok {
			t.Fatalf("local range has no port %d", i)
		}

		got := probeUDPUntilReady(t, addr.String())
		if want := serviceGreeting(i); got != want {
			t.Errorf("port index %d reached %q, want %q", i, got, want)
		}
	}
}

// serviceGreeting is what the service at index i answers with, so a reply
// names the port that produced it and a misrouted one is obvious.
func serviceGreeting(i int) string { return "service-" + strconv.Itoa(i) }

// startRangeTunnel brings up a relay, a share forwarding services, and a listen
// bound to a range of its own, then returns the local range listen bound.
// Every component runs until the test ends.
func startRangeTunnel(tb testing.TB, mode proto.Mode, services hostport.Range) hostport.Range {
	tb.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)

	pki := newTunnelPKI(tb)
	relayAddr := loopbackHostPort(tb, freeLoopbackPort(tb))
	local := freeLoopbackRange(tb, rangePorts)

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
			Mode:     mode,
			Addr:     services,
			Token:    token,
		})
	})

	go runUntilCanceled(ctx, func(runCtx context.Context) error {
		return listen.Run(runCtx, listen.Config{
			Server:   relayAddr,
			CertFile: pki.listenCert,
			KeyFile:  pki.listenKey,
			CAFile:   pki.caFile,
			Mode:     mode,
			Addr:     local,
			Token:    token,
		})
	})

	return local
}

// startTCPServices runs count TCP services on a contiguous range, each
// announcing its own index to whatever connects, and returns the range
// they occupy.
func startTCPServices(tb testing.TB, count int) hostport.Range {
	tb.Helper()

	services := freeLoopbackRange(tb, count)

	for i := range count {
		addr, _ := services.At(i)

		ln, err := net.Listen("tcp", addr.String())
		if err != nil {
			tb.Fatalf("listen service %d on %s: %v", i, addr, err)
		}
		tb.Cleanup(func() { _ = ln.Close() })

		go func() {
			for {
				conn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}

				_, _ = conn.Write([]byte(serviceGreeting(i)))
				_ = conn.Close()
			}
		}()
	}

	return services
}

// startUDPServices is startTCPServices' UDP counterpart: each service
// answers every datagram with its own index.
func startUDPServices(tb testing.TB, count int) hostport.Range {
	tb.Helper()

	services := freeLoopbackRange(tb, count)

	for i := range count {
		addr, _ := services.At(i)

		udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			tb.Fatalf("resolve service %d at %s: %v", i, addr, err)
		}

		socket, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			tb.Fatalf("listen service %d on %s: %v", i, addr, err)
		}
		tb.Cleanup(func() { _ = socket.Close() })

		go func() {
			buf := make([]byte, 512)
			for {
				_, from, readErr := socket.ReadFromUDPAddrPort(buf)
				if readErr != nil {
					return
				}

				_, _ = socket.WriteToUDPAddrPort([]byte(serviceGreeting(i)), from)
			}
		}()
	}

	return services
}

// dialTCPUntilReady connects to addr and returns what the far end sends,
// retrying until the tunnel has converged or tunnelReadyTimeout elapses -
// the three components start in whatever order the scheduler picks, so
// early attempts legitimately fail.
func dialTCPUntilReady(tb testing.TB, addr string) string {
	tb.Helper()

	deadline := time.Now().Add(tunnelReadyTimeout)
	var last error

	for time.Now().Before(deadline) {
		reply, err := readTCPGreeting(addr)
		if err == nil {
			return reply
		}

		last = err
		time.Sleep(componentRetryDelay)
	}

	tb.Fatalf("no reply from %s within %s: %v", addr, tunnelReadyTimeout, last)
	return ""
}

// readTCPGreeting is one attempt at dialing addr and reading its greeting.
func readTCPGreeting(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, componentRetryDelay)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(componentRetryDelay))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("empty reply from %s", addr)
	}

	return string(buf[:n]), nil
}

// probeUDPUntilReady is dialTCPUntilReady's UDP counterpart. Retrying
// matters more here: a datagram sent before the tunnel converges is simply
// lost, with nothing to report it, so the loop is the only thing that
// distinguishes "not up yet" from "broken".
func probeUDPUntilReady(tb testing.TB, addr string) string {
	tb.Helper()

	deadline := time.Now().Add(tunnelReadyTimeout)
	var last error

	for time.Now().Before(deadline) {
		reply, err := readUDPGreeting(addr)
		if err == nil {
			return reply
		}

		last = err
		time.Sleep(componentRetryDelay)
	}

	tb.Fatalf("no reply from %s within %s: %v", addr, tunnelReadyTimeout, last)
	return ""
}

// readUDPGreeting is one attempt at probing addr and reading its reply.
func readUDPGreeting(addr string) (string, error) {
	conn, err := net.DialTimeout("udp", addr, componentRetryDelay)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	if _, writeErr := conn.Write([]byte("ping")); writeErr != nil {
		return "", writeErr
	}

	_ = conn.SetReadDeadline(time.Now().Add(componentRetryDelay))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

// freeLoopbackRange finds count consecutive ports free on both TCP and
// UDP. It has the same unavoidable probe-then-bind race as
// freeLoopbackPort, but a worse exposure to it: a run has to stay free
// across every port at once, and these tests run in parallel with each
// other, each holding two runs of its own.
//
// So unlike freeLoopbackPort, bases aren't taken from the OS. Asking for
// port 0 lands in the ephemeral range, where the OS hands out neighbouring
// numbers to whatever asks next - including the other test doing this at
// the same moment, which is what made a plain retry loop here fail
// outright rather than occasionally. Drawing a random base from a band
// below that range avoids both: nothing is allocating there on its own,
// and two tests picking the same run at the same time is a coincidence
// rather than the default.
func freeLoopbackRange(tb testing.TB, count int) hostport.Range {
	tb.Helper()

	const (
		attempts = 50
		bandLow  = 20000
		bandHigh = 40000
	)

	for range attempts {
		base := bandLow + rand.IntN(bandHigh-bandLow-count)
		if !runIsFree(base, count) {
			continue
		}

		ports, err := hostport.ParseRange(
			net.JoinHostPort(loopbackHost, strconv.Itoa(base)+"-"+strconv.Itoa(base+count-1)),
		)
		if err != nil {
			tb.Fatalf("parse loopback range: %v", err)
		}

		return ports
	}

	tb.Fatalf("no run of %d consecutive free ports after %d attempts", count, attempts)
	return hostport.Range{}
}

// runIsFree reports whether every port in the run binds on both TCP and
// UDP, releasing each probe socket before returning.
func runIsFree(base, count int) bool {
	var probes []interface{ Close() error }
	defer func() {
		for _, probe := range probes {
			_ = probe.Close()
		}
	}()

	for i := range count {
		addr := net.JoinHostPort(loopbackHost, strconv.Itoa(base+i))

		tcpProbe, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		probes = append(probes, tcpProbe)

		udpProbe, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		probes = append(probes, udpProbe)
	}

	return true
}
