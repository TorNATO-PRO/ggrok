package streamio_test

import (
	"fmt"
	"io"
	"net"
	"testing"

	"tornato.dev/ggrok/v2/internal/streamio"
)

// plainConn wraps a [net.Conn] behind the [net.Conn] interface alone, which
// only declares Read/Write/Close (among others) - not ReadFrom/WriteTo. So
// unlike the concrete *[net.TCPConn] underneath, plainConn doesn't promote
// those methods, and [io.Copy]'s type assertions for them fail. This mirrors
// what a quic.Stream looks like to [io.Copy]: no shortcut, so the caller's
// buffer is what actually moves the bytes.
type plainConn struct {
	net.Conn
}

// tcpPipe returns a connected pair of loopback TCP conns, so the benchmark
// exercises real syscalls rather than the in-memory [net.Pipe] fast path.
func tcpPipe(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	acceptedCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		acceptedCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}

	select {
	case server := <-acceptedCh:
		return client, server
	case err := <-errCh:
		b.Fatal(err)
		return nil, nil
	}
}

// BenchmarkCopyBufferSizes sweeps [io.CopyBuffer]'s buffer size across a
// single plainConn-wrapped TCP loopback leg (the shape of relay's
// subConn<->pubConn splice) to find where throughput stops improving.
// Run with: go test ./internal/streamio/... -run '^$' \
//
//	-bench BenchmarkCopyBufferSizes -benchtime 3s -count 3
func BenchmarkCopyBufferSizes(b *testing.B) {
	sizes := []int{4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
			const chunkSize = 1 << 20 // 1MB per b.N unit

			srcClient, srcServer := tcpPipe(b)
			defer func() { _ = srcClient.Close() }()
			sinkClient, sinkServer := tcpPipe(b)
			defer func() { _ = sinkClient.Close() }()

			buf := make([]byte, size)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.CopyBuffer(plainConn{sinkServer}, plainConn{srcServer}, buf)
				_ = sinkServer.Close()
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
		})
	}
}

// BenchmarkSplice pushes b.N megabytes through two spliced TCP loopback
// connections: a source pumps data into one leg, Splice forwards it across
// to the other leg's pair, and a sink drains it. This isolates the copy
// buffer's effect on throughput from QUIC/crypto overhead.
func BenchmarkSplice(b *testing.B) {
	const chunkSize = 1 << 20 // 1MB per b.N unit

	srcClient, srcServer := tcpPipe(b)
	defer func() { _ = srcClient.Close() }()
	sinkClient, sinkServer := tcpPipe(b)
	defer func() { _ = sinkClient.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// *net.TCPConn implements io.ReaderFrom/io.WriterTo, which makes
		// io.Copy bypass our buffer entirely in favor of its own internal
		// copy loop - exactly the fast path a *net.TCPConn gets in
		// production too. Wrapping to only expose Read/Write/Close mimics
		// the quic.Stream<->quic.Stream leg (relay/registry.go), which is
		// the one Splice call site where neither side gets that shortcut
		// and our buffer is actually the one doing the copying.
		streamio.Splice(plainConn{srcServer}, plainConn{sinkServer})
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
