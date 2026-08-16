package hostport_test

import (
	"errors"
	"testing"

	hostport "tornato.dev/ggrok/v2/internal"
)

func TestParseRange(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
		count int
	}{
		{"single port", "127.0.0.1:8080", "127.0.0.1:8080", 1},
		{"span", "127.0.0.1:8000-8010", "127.0.0.1:8000-8010", 11},
		{"span of one", "127.0.0.1:8000-8000", "127.0.0.1:8000", 1},
		{"dns name", "example.com:5000-5001", "example.com:5000-5001", 2},
		{"ipv6", "[::1]:9000-9002", "[::1]:9000-9002", 3},
		{"port zero", "127.0.0.1:0", "127.0.0.1:0", 1},
		{"largest allowed span", "127.0.0.1:2000-3023", "127.0.0.1:2000-3023", hostport.MaxPorts},
		{"up to the last port", "127.0.0.1:65534-65535", "127.0.0.1:65534-65535", 2},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, err := hostport.ParseRange(c.input)
			if err != nil {
				t.Fatalf("ParseRange(%q): %v", c.input, err)
			}
			if got.Len() != c.count {
				t.Errorf("Len() = %d, want %d", got.Len(), c.count)
			}
			if got.String() != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseRangeRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{"inverted", "127.0.0.1:9000-8000"},
		{"starts at zero", "127.0.0.1:0-10"},
		{"one past the cap", "127.0.0.1:2000-3024"},
		{"whole port space", "127.0.0.1:1-65535"},
		{"non-numeric first", "127.0.0.1:http-8010"},
		{"non-numeric last", "127.0.0.1:8000-http"},
		{"empty last", "127.0.0.1:8000-"},
		{"past 65535", "127.0.0.1:65535-65536"},
		{"no port at all", "127.0.0.1"},
		{"empty host", ":8000-8010"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got, err := hostport.ParseRange(c.input); err == nil {
				t.Errorf("ParseRange(%q) = %v, want an error", c.input, got)
			}
		})
	}
}

// TestParseRangeOversizedErrIs pins that an oversized or inverted span
// reports ErrInvalidRange specifically - it's the one failure mode a
// caller might want to tell apart from a plain malformed address, since
// the fix is different (shrink the range, not correct the syntax).
func TestParseRangeOversizedErrIs(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"127.0.0.1:1-65535", "127.0.0.1:9000-8000", "127.0.0.1:0-10"} {
		_, err := hostport.ParseRange(input)
		if !errors.Is(err, hostport.ErrInvalidRange) {
			t.Errorf("ParseRange(%q) = %v, want it to wrap ErrInvalidRange", input, err)
		}
	}
}

// TestRangeAt walks a range end to end, since At is what every port index
// arriving over the wire is resolved through - including the indexes that
// name nothing, which must be refused rather than wrap around or panic.
func TestRangeAt(t *testing.T) {
	t.Parallel()

	ports, err := hostport.ParseRange("127.0.0.1:8000-8002")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"127.0.0.1:8000", "127.0.0.1:8001", "127.0.0.1:8002"}
	for i, w := range want {
		got, ok := ports.At(i)
		if !ok {
			t.Fatalf("At(%d) not ok, want %q", i, w)
		}
		if got.String() != w {
			t.Errorf("At(%d) = %q, want %q", i, got, w)
		}
	}

	for _, i := range []int{-1, len(want), len(want) + 1, 1 << 16} {
		if got, ok := ports.At(i); ok {
			t.Errorf("At(%d) = %q, want not ok", i, got)
		}
	}
}

// TestRangeTextRoundTrip covers the [encoding.TextMarshaler] pair, which is
// what lets a Range drop into a config file as a plain string.
func TestRangeTextRoundTrip(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"127.0.0.1:8080", "example.com:8000-8010", "[::1]:9000-9002"} {
		want, err := hostport.ParseRange(input)
		if err != nil {
			t.Fatal(err)
		}

		text, err := want.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}

		var got hostport.Range
		if err := got.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if got != want {
			t.Errorf("round trip of %q gave %q", input, got)
		}
	}
}
