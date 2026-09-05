package streamio_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/streamio"
)

// halfCloser adapts a [bytes.Buffer] pair into the [io.ReadWriteCloser] Splice
// wants. Close is a no-op because there is no transport underneath to release
// - the tests here are about byte accounting, not about teardown.
type halfCloser struct {
	io.Reader
	io.Writer
}

func (halfCloser) Close() error { return nil }

// TestSpliceCountedMatchesSplice pins the counter to the return values: the
// two accounts of the same copy must not be able to disagree, since the whole
// point of the counter is to be readable before the return values exist.
func TestSpliceCountedMatchesSplice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		intoA string
		intoB string
		wantA int64
		wantB int64
	}{
		{name: "both directions", intoA: "from b", intoB: "from a to b", wantA: 6, wantB: 11},
		{name: "one direction only", intoA: "", intoB: "only a speaks", wantA: 0, wantB: 13},
		{name: "silent", intoA: "", intoB: "", wantA: 0, wantB: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// a reads what b sends, and vice versa; each side's writes land
			// in the buffer the assertion reads.
			var sinkA, sinkB bytes.Buffer
			a := halfCloser{Reader: bytes.NewBufferString(tt.intoB), Writer: &sinkA}
			b := halfCloser{Reader: bytes.NewBufferString(tt.intoA), Writer: &sinkB}

			var counter streamio.Counter
			gotA, gotB := streamio.SpliceCounted(a, b, &counter)

			if gotA != tt.wantA || gotB != tt.wantB {
				t.Fatalf("returned (%d, %d), want (%d, %d)", gotA, gotB, tt.wantA, tt.wantB)
			}
			if counter.IntoA.Load() != gotA || counter.IntoB.Load() != gotB {
				t.Fatalf("counter (%d, %d) disagrees with return (%d, %d)",
					counter.IntoA.Load(), counter.IntoB.Load(), gotA, gotB)
			}
			if sinkA.String() != tt.intoA || sinkB.String() != tt.intoB {
				t.Fatalf("copied %q/%q, want %q/%q", sinkA.String(), sinkB.String(), tt.intoA, tt.intoB)
			}
		})
	}
}

// TestSpliceCountedObservableMidCopy is the property the type exists for. A
// long-lived tunnel never reaches Splice's return, so a counter only readable
// afterwards would be no account of anything.
func TestSpliceCountedObservableMidCopy(t *testing.T) {
	t.Parallel()

	aRead, aWrite := net.Pipe()
	bRead, bWrite := net.Pipe()
	t.Cleanup(func() {
		_ = aRead.Close()
		_ = aWrite.Close()
		_ = bRead.Close()
		_ = bWrite.Close()
	})

	var counter streamio.Counter
	spliced := make(chan struct{})
	go func() {
		defer close(spliced)
		streamio.SpliceCounted(aRead, bRead, &counter)
	}()

	// Drain what the splice forwards, so the writes below can complete.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, aWrite)
	}()

	const chunk = 512
	payload := make([]byte, chunk)
	if _, err := bWrite.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The write above returned, so the splice has read it; the copy into the
	// other leg is what we are waiting to observe.
	deadline := time.Now().Add(5 * time.Second)
	for counter.IntoA.Load() < chunk {
		if time.Now().After(deadline) {
			t.Fatalf("counter stuck at %d mid-copy, want %d", counter.IntoA.Load(), chunk)
		}
		time.Sleep(time.Millisecond)
	}

	_ = bWrite.Close()
	_ = aWrite.Close()
	<-drained
	<-spliced
}

// BenchmarkSpliceCounted mirrors BenchmarkSplice exactly so the two can be
// compared directly. The wrapper costs one atomic add per copyBufferSize
// moved on a pair that gets no ReaderFrom/WriterTo shortcut - which is what
// relay's tls.Conn legs are.
func BenchmarkSpliceCounted(b *testing.B) {
	const chunkSize = 1 << 20 // 1MB per b.N unit, matching BenchmarkSplice

	srcClient, srcServer := tcpPipe(b)
	defer func() { _ = srcClient.Close() }()
	sinkClient, sinkServer := tcpPipe(b)
	defer func() { _ = sinkClient.Close() }()

	var counter streamio.Counter

	done := make(chan struct{})
	go func() {
		defer close(done)
		streamio.SpliceCounted(plainConn{srcServer}, plainConn{sinkServer}, &counter)
	}()

	payload := make([]byte, chunkSize)

	drained := make(chan int64)
	go func() {
		n, _ := io.Copy(io.Discard, sinkClient)
		drained <- n
	}()

	b.SetBytes(chunkSize)

	for b.Loop() {
		if _, err := srcClient.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	_ = srcClient.Close()

	<-drained
	<-done
}
