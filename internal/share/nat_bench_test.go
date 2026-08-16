package share //nolint:testpackage // in-package on purpose: this measures an unexported hot path against a replica of the implementation it replaced, and re-exporting natEntry and natKey for the comparison would widen the package API more than the comparison is worth

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

// lockedEntry and lockedTable reproduce the shape natTable had before
// lastActive became atomic: an idle clock guarded by the table-wide mutex,
// refreshed through a keyed lookup. They exist only so BenchmarkNATTouch
// can measure the two side by side.
type lockedEntry struct {
	lastActive time.Time
}

type lockedTable struct {
	mu      sync.Mutex
	entries map[natKey]*lockedEntry
}

func (t *lockedTable) touch(key natKey) {
	t.mu.Lock()
	if entry, ok := t.entries[key]; ok {
		entry.lastActive = time.Now()
	}
	t.mu.Unlock()
}

// BenchmarkNATTouch measures marking a NAT entry active, the thing every
// reply packet does, with one goroutine per entry - the shape share is in
// when it fronts a busy service and many flows are live at once.
func BenchmarkNATTouch(b *testing.B) {
	for _, entries := range []int{1, 8, 64} {
		keys := make([]natKey, entries)
		for i := range keys {
			keys[i] = natKey{flow: proto.FlowID(i)}
		}

		b.Run("locked/"+strconv.Itoa(entries), func(b *testing.B) {
			table := &lockedTable{entries: make(map[natKey]*lockedEntry, entries)}
			for _, key := range keys {
				table.entries[key] = &lockedEntry{}
			}

			runTouch(b, entries, func(i int) { table.touch(keys[i]) })
		})

		b.Run("atomic/"+strconv.Itoa(entries), func(b *testing.B) {
			owned := make([]*natEntry, entries)
			for i := range owned {
				owned[i] = &natEntry{}
			}

			runTouch(b, entries, func(i int) { owned[i].touch() })
		})
	}
}

// runTouch runs touch concurrently from one goroutine per entry, each
// hitting only its own, for b.N iterations apiece.
func runTouch(b *testing.B, entries int, touch func(i int)) {
	b.Helper()
	b.ResetTimer()

	var wg sync.WaitGroup
	for i := range entries {
		wg.Go(func() {
			for range b.N {
				touch(i)
			}
		})
	}
	wg.Wait()

	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*entries), "ns/touch")
}
