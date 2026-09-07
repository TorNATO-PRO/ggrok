package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
)

func TestTerminalText(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"node", "café", "a\tb\n", "\x1b]52;c;payload\x07", "left\u202eright", "\r\x00\x7f"} {
		got := terminalText(text)
		if strings.ContainsAny(got, "\x1b\x07\t\n\r\x00\x7f\u202e") {
			t.Fatalf("unsafe output: %q", got)
		}
		if (text == "node" || text == "café") && got != text {
			t.Fatalf("changed readable name: %q", got)
		}
	}
}

func TestSnapshotEscapesUntrustedFields(t *testing.T) {
	t.Parallel()
	file, err := os.Create(filepath.Join(t.TempDir(), "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	injected := "name\x1b[2J\nforged\trow\u202e"
	peer := proto.PeerSummary{CN: injected, Serial: injected, Addr: injected}
	snapshot := proto.Snapshot{Sessions: []proto.SessionSummary{{
		Tag: injected, Mode: injected, Publisher: peer, Subscribers: []proto.PeerSummary{peer},
	}}}
	if printErr := printSnapshot(file, palette{}, snapshot); printErr != nil {
		t.Fatal(printErr)
	}
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if strings.ContainsAny(output, "\x1b\u202e") || strings.Contains(output, "\nforged") {
		t.Fatalf("injected terminal text: %q", output)
	}
	if strings.Count(output, terminalText(injected)) != 8 {
		t.Fatalf("not all peer fields were escaped: %q", output)
	}
}
