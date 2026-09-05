// Package streamio pipes bytes between two full-duplex byte streams - shared
// by share (local service <-> encrypted tunnel), listen (local client <->
// encrypted tunnel), and relay (subscriber connection <-> publisher
// connection).
package streamio

import (
	"io"
	"sync"
	"sync/atomic"
)

// directions is how many concurrent copy directions Splice runs - named so
// the WaitGroup count isn't a bare magic number.
const directions = 2

// copyBufferSize is the per-direction [io.Copy] buffer size. [io.Copy]'s
// built-in default is 32KiB; a larger buffer trades a bit of memory for fewer
// Read/Write calls per byte moved.
//
// It only takes effect when neither source WriterTo nor destination ReaderFrom
// handles the copy. In particular, share/listen's TCP legs bypass this buffer;
// relay's TLS-to-TLS copies use it.
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
	return splice(a, b, nil)
}

// Counter accumulates bytes written into each side of a splice while the copy
// is still running. [Splice]'s own return values only arrive once both legs
// are closed, which for a tunnel that stays up for hours is far too late to be
// an account of anything.
//
// The two fields mirror [SpliceCounted]'s argument order: IntoA counts bytes
// written into a, IntoB into b. Both are safe to read from another goroutine
// while the copy runs.
type Counter struct {
	IntoA, IntoB atomic.Int64
}

// SpliceCounted is [Splice], additionally publishing progress into c as it
// goes.
//
// It is deliberately a separate entry point rather than an option on Splice:
// counting means wrapping each destination writer, and a wrapper hides
// whatever [io.ReaderFrom] the destination implements - exactly the fast path
// copyBufferSize's comment describes, which share and listen depend on because
// their legs are *[net.TCPConn]. Both of relay's legs are *tls.Conn, which
// implements neither ReaderFrom nor WriterTo, so relay pays nothing for the
// wrapper beyond one atomic add per copyBufferSize moved.
func SpliceCounted(a, b io.ReadWriteCloser, c *Counter) (int64, int64) {
	return splice(a, b, c)
}

// splice shares copy and close ownership between counted and uncounted streams.
// Only counted copies wrap writers; uncounted copies retain [io.ReaderFrom].
func splice(a, b io.ReadWriteCloser, c *Counter) (int64, int64) {
	var dstA, dstB io.Writer = a, b
	if c != nil {
		dstA = countingWriter{w: a, n: &c.IntoA}
		dstB = countingWriter{w: b, n: &c.IntoB}
	}

	var wg sync.WaitGroup
	wg.Add(directions)

	var intoA, intoB int64

	go func() {
		defer wg.Done()
		// best-effort proxy; the Close below is what matters
		intoA, _ = copyStream(dstA, b)
		_ = a.Close()
	}()

	go func() {
		defer wg.Done()
		// best-effort proxy; the Close below is what matters
		intoB, _ = copyStream(dstB, a)
		_ = b.Close()
	}()

	wg.Wait()

	return intoA, intoB
}

// countingWriter adds each successful write into n before returning. It is a
// value type wrapping only the writer half, so it deliberately satisfies
// neither [io.ReaderFrom] nor [io.Closer] - copyStream must fall through to the
// buffered path, and the Close in SpliceCounted must reach the underlying
// stream rather than this wrapper.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// copyStream borrows a buffer only when [io.Copy] will actually use it.
func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	buf, _ := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	return io.CopyBuffer(dst, src, *buf)
}
