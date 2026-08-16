package relay //nolint:testpackage // in-package on purpose: this measures an unexported hot path against a replica of the implementation it replaced, and re-exporting the session's mutex and its map for the comparison would widen the package API more than the comparison is worth

import (
	"maps"
	"sync"
	"testing"

	"tornato.dev/ggrok/v2/internal/dgram"
	"tornato.dev/ggrok/v2/internal/proto"
)

// lockedSubscribers reproduces the shape session.udpSubscribers had before
// it became a copy-on-write atomic pointer: a plain map read under the
// session-wide mutex. It exists only so BenchmarkUDPSubscriberLookup can
// measure the two side by side.
type lockedSubscribers struct {
	mu      sync.Mutex
	senders map[proto.SubscriberID]*dgram.Sender
}

func (l *lockedSubscribers) get(id proto.SubscriberID) (*dgram.Sender, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sender, ok := l.senders[id]

	return sender, ok
}

// BenchmarkUDPSubscriberLookup measures the per-frame subscriber lookup in
// relay's fan-out path (see pumpPublisherDatagrams).
//
// Two cases per implementation. "solo" is one publisher pump walking
// frames with nothing else touching the session - the uncontended cost.
// "control" adds a goroutine doing the control-plane work that shares the
// same mutex, which is what the lock actually costs when a session is
// churning subscribers while carrying traffic.
func BenchmarkUDPSubscriberLookup(b *testing.B) {
	const subscribers = 16

	ids := make([]proto.SubscriberID, subscribers)
	senders := make(map[proto.SubscriberID]*dgram.Sender, subscribers)
	for i := range ids {
		ids[i] = proto.SubscriberID(i)
		senders[ids[i]] = &dgram.Sender{}
	}

	locked := &lockedSubscribers{senders: senders}

	sess := newSession(proto.ModeUDP, nil, nil)
	cow := maps.Clone(senders)
	sess.udpSubscribers.Store(&cow)

	cases := []struct {
		name string
		get  func(proto.SubscriberID) (*dgram.Sender, bool)
	}{
		{"locked", locked.get},
		{"atomic", sess.udpSubscriber},
	}

	for _, contended := range []bool{false, true} {
		label := "solo"
		if contended {
			label = "control"
		}

		for _, tc := range cases {
			b.Run(tc.name+"/"+label, func(b *testing.B) {
				stop := make(chan struct{})
				if contended {
					var wg sync.WaitGroup
					wg.Go(func() { churnControlPlane(sess, locked, stop) })
					defer func() { close(stop); wg.Wait() }()
				}

				b.ReportAllocs()
				b.ResetTimer()

				var sink *dgram.Sender
				for i := range b.N {
					sink, _ = tc.get(ids[i%subscribers])
				}
				runtimeSink = sink
			})
		}
	}
}

// churnControlPlane hammers whichever mutex the case under test shares
// with relay's control plane, standing in for subscribers attaching and
// detaching while the fan-out path carries traffic.
func churnControlPlane(sess *session, locked *lockedSubscribers, stop <-chan struct{}) {
	const churnID = proto.SubscriberID(9999)

	for {
		select {
		case <-stop:
			return
		default:
		}

		locked.mu.Lock()
		locked.senders[churnID] = nil
		delete(locked.senders, churnID)
		locked.mu.Unlock()

		sess.mu.Lock()
		sess.nextReqID++
		sess.mu.Unlock()
	}
}

// runtimeSink keeps the benchmarked lookups from being optimized away.
var runtimeSink *dgram.Sender
