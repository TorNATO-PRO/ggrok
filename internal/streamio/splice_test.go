package streamio //nolint:testpackage // Verifies private copy dispatch and buffer-pool usage.

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

type (
	readerOnly      struct{ io.Reader }
	writerOnly      struct{ io.Writer }
	failingWriterTo struct {
		io.Reader

		err error
	}
)

func (w failingWriterTo) WriteTo(io.Writer) (int64, error) { return 7, w.err }

func TestCopyStream(t *testing.T) { //nolint:paralleltest // Temporarily replaces the package buffer pool.
	// A buffer allocation here means the fast-path check happened too late.
	bufPool = sync.Pool{New: func() any { t.Fatal("fast path borrowed a buffer"); return nil }}
	defer func() { bufPool = sync.Pool{New: func() any { b := make([]byte, copyBufferSize); return &b }} }()
	for _, sourceFastPath := range []bool{true, false} {
		var dst bytes.Buffer
		var src io.Reader = bytes.NewBufferString("payload")
		if !sourceFastPath {
			src = readerOnly{src}
		}
		n, err := copyStream(&dst, src)
		if err != nil || n != 7 || dst.String() != "payload" {
			t.Fatalf("copy = %d, %v, %q", n, err, dst.String())
		}
	}
	wantErr := errors.New("copy failed")
	n, err := copyStream(io.Discard, failingWriterTo{err: wantErr})
	if n != 7 || !errors.Is(err, wantErr) {
		t.Fatalf("copy error = %d, %v", n, err)
	}
	allocated := 0
	bufPool = sync.Pool{New: func() any { allocated++; b := make([]byte, copyBufferSize); return &b }}
	var dst bytes.Buffer
	n, err = copyStream(writerOnly{&dst}, readerOnly{bytes.NewBufferString("fallback")})
	if err != nil || n != 8 || dst.String() != "fallback" || allocated != 1 {
		t.Fatalf("fallback = %d, %v, %q, allocations=%d", n, err, dst.String(), allocated)
	}
}
