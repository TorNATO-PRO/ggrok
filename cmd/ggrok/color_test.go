package main

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// sgrPattern matches one Select Graphic Rendition sequence, so a styled
// rendering can be compared against the plain one it has to match underneath.
var sgrPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestTableStylingPreservesAlignment is the reason table exists at all.
//
// [text/tabwriter] measures a cell in runes and cannot be told that an escape
// sequence occupies no columns, so a table colored cell by cell is padded as
// though its escapes were printable: every colored column comes out short by
// exactly their width, and only for the rows that happened to be colored.
// Coloring whole lines after the layout is fixed is what avoids that, and the
// property worth pinning is that stripping the escapes back out returns the
// plain table byte for byte.
func TestTableStylingPreservesAlignment(t *testing.T) {
	t.Parallel()

	render := func(p palette) string {
		tbl := newTable()
		tbl.rowf(p.bold, "COMMON NAME\tSERIAL\tSTATUS\tEXPIRES\n")
		tbl.rowf(nil, "%s\t%s\t%s\t%s\n", "a-very-long-common-name", "01", "issued", "2027-01-01T00:00:00Z")
		tbl.rowf(p.red, "%s\t%s\t%s\t%s\n", "short", "02", "revoked", "2026-01-01T00:00:00Z")
		tbl.rowf(p.yellow, "%s\t%s\t%s\t%s\n", "medium-name", "03", "expired", "2025-01-01T00:00:00Z")

		var buf bytes.Buffer
		if err := tbl.flush(&buf); err != nil {
			t.Fatalf("flush: %v", err)
		}

		return buf.String()
	}

	plain := render(palette{})
	styled := render(palette{on: true})

	if !strings.Contains(styled, "\x1b[") {
		t.Fatal("styled table carries no escape sequences at all")
	}

	if got := sgrPattern.ReplaceAllString(styled, ""); got != plain {
		t.Fatalf("styling moved the columns:\n got %q\nwant %q", got, plain)
	}
}

// TestTableStylesRowsPositionally checks that a row's style lands on that row
// rather than on its neighbor, since flush pairs the two up by position.
func TestTableStylesRowsPositionally(t *testing.T) {
	t.Parallel()

	p := palette{on: true}
	tbl := newTable()
	tbl.rowf(nil, "first\n")
	tbl.rowf(p.red, "second\n")
	tbl.rowf(nil, "third\n")

	var buf bytes.Buffer
	if err := tbl.flush(&buf); err != nil {
		t.Fatalf("flush: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), buf.String())
	}
	if strings.Contains(lines[0], "\x1b[") || strings.Contains(lines[2], "\x1b[") {
		t.Fatalf("unstyled rows were colored: %q", buf.String())
	}
	if want := p.red("second"); lines[1] != want {
		t.Fatalf("styled row = %q, want %q", lines[1], want)
	}
}

// TestPaletteOffWritesPlainText pins the promise the whole feature rests on:
// without -color, every call site's output is unchanged.
func TestPaletteOffWritesPlainText(t *testing.T) {
	t.Parallel()

	var off palette
	for _, style := range []func(string) string{off.bold, off.dim, off.red, off.green, off.yellow, off.cyan, off.highlight} {
		if got := style("text"); got != "text" {
			t.Fatalf("palette with color off returned %q", got)
		}
	}

	// An empty field would otherwise become an escape sequence wrapped around
	// nothing, which is invisible in a terminal and noise everywhere else.
	on := palette{on: true}
	if got := on.bold(""); got != "" {
		t.Fatalf("painted empty text as %q", got)
	}
}

// TestParseColorMode covers the spellings a flag value and GGROK_COLOR may
// each arrive in, including the "true" the flag package hands a bare -color.
func TestParseColorMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    colorMode
		wantErr bool
	}{
		{name: "bare flag", in: "true", want: colorAuto},
		{name: "auto", in: "auto", want: colorAuto},
		{name: "always", in: "always", want: colorAlways},
		{name: "never", in: "never", want: colorNever},
		{name: "uppercase", in: "ALWAYS", want: colorAlways},
		{name: "padded", in: " never ", want: colorNever},
		{name: "env truth", in: "1", want: colorAuto},
		{name: "env falsehood", in: "0", want: colorNever},
		{name: "nonsense", in: "chartreuse", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseColorMode(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseColorMode(%q) = %v, want an error", tt.in, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseColorMode(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseColorMode(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestColorFlagIsBoolLike ensures a bare color flag does not consume a token.
func TestColorFlagIsBoolLike(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		want     colorMode
		wantArgs []string
	}{
		{name: "bare", args: []string{"-color"}, want: colorAuto, wantArgs: nil},
		{name: "bare before an argument", args: []string{"-color", "tok"}, want: colorAuto, wantArgs: []string{"tok"}},
		{name: "always", args: []string{"-color=always"}, want: colorAlways, wantArgs: nil},
		{name: "never", args: []string{"-color=never"}, want: colorNever, wantArgs: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mode := colorNever
			cmd := &cobra.Command{Use: "color", Run: func(*cobra.Command, []string) {}}
			fs := cmd.Flags()
			fs.SetOutput(io.Discard)
			registerColorFlag(fs, &mode)

			if err := fs.Parse(normalizeLegacyFlags(cmd, tt.args)); err != nil {
				t.Fatalf("parse %v: %v", tt.args, err)
			}
			if mode != tt.want {
				t.Fatalf("mode = %v, want %v", mode, tt.want)
			}
			if got := fs.Args(); len(got) != len(tt.wantArgs) {
				t.Fatalf("leftover args = %v, want %v", got, tt.wantArgs)
			}
		})
	}
}

// TestColorModeEnabled checks what each mode decides for a stream that is not
// a terminal, which a pipe stands in for.
func TestColorModeEnabled(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	always := colorAlways
	if !always.enabled(writer) {
		t.Error("always did not style a pipe")
	}

	// The whole point of auto: a token, a table, or a bound address on its way
	// into a file or a log gets no escape sequences written into it.
	auto := colorAuto
	if auto.enabled(writer) {
		t.Error("auto styled a pipe")
	}

	never := colorNever
	if never.enabled(writer) {
		t.Error("never styled a pipe")
	}
}
