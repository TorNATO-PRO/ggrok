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
		intoA, _ = io.Copy(a, b) // best-effort proxy; the Close below is what matters
		_ = a.Close()
	}()

	go func() {
		defer wg.Done()
		intoB, _ = io.Copy(b, a) // best-effort proxy; the Close below is what matters
		_ = b.Close()
	}()

	wg.Wait()

	return intoA, intoB
}
