// Package streamio pipes bytes between two full-duplex byte streams -
// shared by share (local TCP conn <-> QUIC stream), listen (same, other
// direction), and relay (subscriber stream <-> publisher stream).
package streamio

import (
	"io"
	"sync"
)

// directions is how many concurrent copy directions Splice runs - named so
// the WaitGroup count isn't a bare magic number.
const directions = 2

// copyBufferSize is the per-direction [io.Copy] buffer size. [io.Copy]'s
// built-in default is 32KiB; a larger buffer trades a bit of memory for
// fewer Read/Write calls per byte moved. This only takes effect on legs
// where neither side is a *[net.TCPConn] - relay's subscriber<->publisher
// QUIC streams (internal/relay/registry.go) - since *[net.TCPConn]
// implements [io.ReaderFrom]/io.WriterTo, which [io.CopyBuffer] detects and
// hands off to Go's own internal copy loop, silently ignoring this buffer.
// That's the case on both legs of listen's and share's local-conn<->QUIC
// splices, so this buffer is a no-op there. Benchmarked ~15% throughput
// gain on the QUIC-stream-to-QUIC-stream leg (BenchmarkSplice).
const copyBufferSize = 128 * 1024

// bufPool recycles copy buffers across Splice calls so each forwarded
// connection doesn't pay a fresh 128KiB allocation per direction.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

// Splice copies bytes between a and b in both directions until both
// directions have finished, closing each side once the direction reading
// into it is exhausted so a close on one leg propagates to the other
// instead of leaking a half-open connection.
//
// It returns how many bytes it wrote into each side - the only record of
// what a forwarded connection actually carried, since neither leg exists
// once this returns. Callers with nothing to report may ignore both.
func Splice(a, b io.ReadWriteCloser) (int64, int64) {
	var wg sync.WaitGroup
	wg.Add(directions)

	var intoA, intoB int64

	go func() {
		defer wg.Done()
		buf, _ := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		intoA, _ = io.CopyBuffer(a, b, *buf) // best-effort proxy; the Close below is what matters
		_ = a.Close()
	}()

	go func() {
		defer wg.Done()
		buf, _ := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		intoB, _ = io.CopyBuffer(b, a, *buf) // best-effort proxy; the Close below is what matters
		_ = b.Close()
	}()

	wg.Wait()

	return intoA, intoB
}
