package main

import (
	"testing"
	"time"
)

// TestMegabitsPerSecond pins the throughput column's arithmetic and, more
// importantly, its guards: the relay's clock supplies both timestamps, so a
// stream can legitimately report an age of zero or a snapshot taken a moment
// before it started. Neither may render as Inf, NaN or a negative rate.
func TestMegabitsPerSecond(t *testing.T) {
	t.Parallel()

	started := time.Unix(0, 0)

	tests := []struct {
		name      string
		byteCount int64
		now       time.Time
		want      string
	}{
		// 1 MB in 10s is 8 Mb in 10s: decimal megabits, not mebibits.
		{name: "steady rate", byteCount: 1_000_000, now: started.Add(10 * time.Second), want: "0.800"},
		{name: "sub-second stream", byteCount: 125_000, now: started.Add(100 * time.Millisecond), want: "10.000"},
		{name: "idle stream", byteCount: 0, now: started.Add(10 * time.Second), want: "0.000"},
		{name: "just started", byteCount: 4_000, now: started, want: "0.000"},
		{name: "clock skew", byteCount: 4_000, now: started.Add(-time.Second), want: "0.000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := megabitsPerSecond(tt.byteCount, tt.now, started); got != tt.want {
				t.Fatalf("megabitsPerSecond(%d) = %q, want %q", tt.byteCount, got, tt.want)
			}
		})
	}
}
