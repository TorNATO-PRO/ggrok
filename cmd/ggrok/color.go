// color.go holds -color and the ANSI styling every command writes through.
//
// Color is opt-in. Without the flag ggrok writes exactly the bytes it always
// has, so anything already parsing this output keeps working. `-color` turns
// it on for streams that are terminals, `-color=always` forces it on for the
// case where the reader is a pager rather than a terminal, and `-color=never`
// turns it back off for a script that inherited GGROK_COLOR from somewhere
// else.
//
// Styling is applied to whole lines rather than to individual table cells.
// [text/tabwriter] measures a cell in runes and has no notion of a zero-width
// escape sequence, so a colored cell is padded as though its escapes were
// printable and its column comes out short by exactly their width. The table
// type below therefore lays a table out in plain text first and colors the
// finished lines, which cannot be misaligned by construction.
//
// What -color deliberately does not reach is relay's own log. Those lines are
// logfmt, written for whatever collects them rather than for someone watching
// a terminal, and escape sequences in a log line are something a parser has to
// cope with forever after. Relay still honors the flag for the one line main
// prints if it fails to start.

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

// colorMode says when a stream should carry ANSI styling.
type colorMode int

const (
	colorAutoName  = "auto"
	colorNeverName = "never"
)

const (
	// colorNever writes plain text whatever the stream is. It is the zero
	// value and the default, so output is unchanged unless color is asked for.
	colorNever colorMode = iota

	// colorAuto styles a stream that is a terminal and leaves a file, a pipe,
	// or a CI log alone. This is what a bare -color selects.
	colorAuto

	// colorAlways styles unconditionally, for output piped to something that
	// renders escapes itself - `less -R`, or a terminal multiplexer's log.
	colorAlways
)

// colorFlagHelp is the -color description every command registers it with.
// The value is optional because the flag is bool-like: -color on its own means
// auto. A value has to be attached with "=", since a bool-like flag never
// consumes the argument that follows it.
const colorFlagHelp = "style output with ANSI color: -color (auto), " +
	"-color=always, or -color=never (env GGROK_COLOR)"

// Select Graphic Rendition parameters, and the reset that ends them. Only the
// eight-color codes are used: they are the ones a user's terminal theme gets
// to reinterpret, so ggrok's output stays legible on a light background, a
// dark one, and whatever someone has remapped their palette to.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "1"
	sgrDim    = "2"
	sgrRed    = "31"
	sgrGreen  = "32"
	sgrYellow = "33"
	sgrCyan   = "36"
)

// colorFlag is the mode every command's -color writes into, and the one every
// palette is resolved from. It is package-level because main reports a
// command's error after that command's flag set has gone out of scope, and
// that final line is exactly the one worth coloring.
var colorFlag = colorModeFromEnv()

// parseColorMode maps what a -color value or GGROK_COLOR may say to a mode.
// The bool-ish spellings are accepted because the flag is bool-like: the flag
// package hands a bare -color the string "true", and an environment variable
// is just as likely to be set to 1 or 0 as to auto or never.
func parseColorMode(s string) (colorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", colorAutoName, "true", "1", "yes", "on":
		return colorAuto, nil
	case "always", "force":
		return colorAlways, nil
	case colorNeverName, "false", "0", "no", "off":
		return colorNever, nil
	default:
		return colorNever, fmt.Errorf("invalid color mode %q (want auto, always, or never)", s)
	}
}

// colorModeFromEnv reads GGROK_COLOR, which is where someone who wants color
// every time puts it rather than typing -color into every invocation.
//
// A value that parses to nothing is ignored rather than fatal. Color is
// decoration, and refusing to run because a shell profile exports something
// unexpected would be wildly out of proportion to what is at stake.
func colorModeFromEnv() colorMode {
	raw := os.Getenv("GGROK_COLOR")
	if raw == "" {
		return colorNever
	}

	mode, err := parseColorMode(raw)
	if err != nil {
		return colorNever
	}

	return mode
}

// registerColorFlag registers the inherited color option with an optional value.
func registerColorFlag(fs *pflag.FlagSet, mode *colorMode) {
	fs.Var(mode, "color", colorFlagHelp)
	fs.Lookup("color").NoOptDefVal = colorAutoName
}

// stdoutColors resolves the palette for stdout, which carries what a command
// produces: tables, tokens, bound addresses.
func stdoutColors() palette {
	return palette{on: colorFlag.enabled(os.Stdout)}
}

// stderrColors resolves the palette for stderr, which carries what a command
// has to say about itself: errors, warnings, and connection narration.
func stderrColors() palette {
	return palette{on: colorFlag.enabled(os.Stderr)}
}

// String renders the mode as the flag value that selects it, which is what
// [pflag.PrintDefaults] shows when GGROK_COLOR has already set one.
func (m *colorMode) String() string {
	if m == nil {
		return colorNeverName
	}

	switch *m {
	case colorAuto:
		return colorAutoName
	case colorAlways:
		return "always"
	case colorNever:
		return colorNeverName
	}

	return colorNeverName
}

// Set parses one -color value.
func (m *colorMode) Set(s string) error {
	mode, err := parseColorMode(s)
	if err != nil {
		return err
	}

	*m = mode

	return nil
}

// enabled reports whether f should carry ANSI styling under this mode.
//
// Auto asks three questions, and any one of them settles it: NO_COLOR is the
// cross-tool convention (https://no-color.org) for a user who never wants
// color from anything, TERM=dumb is a terminal saying it cannot render
// escapes, and a stream that is not a character device is a file or a pipe
// that would only be handed escape sequences to store.
func (m *colorMode) enabled(f *os.File) bool {
	switch *m {
	case colorAlways:
		return true
	case colorAuto:
		return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && isTerminal(f)
	case colorNever:
		return false
	}

	return false
}

// palette styles text for one stream. The zero value writes plain text, so a
// call site can style unconditionally and leave the decision here.
type palette struct {
	// on reports whether this stream renders escape sequences, decided once
	// from the -color mode rather than per call.
	on bool
}

// paint wraps text in the given SGR parameters. Empty text is left alone, so
// a blank field never turns into an escape sequence wrapped around nothing.
func (p palette) paint(text string, codes ...string) string {
	if !p.on || text == "" {
		return text
	}

	return "\x1b[" + strings.Join(codes, ";") + "m" + text + sgrReset
}

// bold marks a heading or a value worth finding at a glance.
func (p palette) bold(text string) string {
	return p.paint(text, sgrBold)
}

// dim renders something that is present but not what the reader came for.
func (p palette) dim(text string) string {
	return p.paint(text, sgrDim)
}

// red marks a failure, or a certificate that has been revoked.
func (p palette) red(text string) string {
	return p.paint(text, sgrRed)
}

// green marks something that succeeded.
func (p palette) green(text string) string {
	return p.paint(text, sgrGreen)
}

// yellow marks a warning, or a state that is neither working nor broken -
// a stream still waiting on a publisher, a certificate that has expired.
func (p palette) yellow(text string) string {
	return p.paint(text, sgrYellow)
}

// cyan marks an address or a command meant to be read as one unit.
func (p palette) cyan(text string) string {
	return p.paint(text, sgrCyan)
}

// highlight marks the one value on the screen the reader is there for: the
// subscriber token, or the session a block of output describes.
func (p palette) highlight(text string) string {
	return p.paint(text, sgrBold, sgrCyan)
}

// table renders an aligned table whose rows are colored after the columns are
// laid out. See the file comment for why this cannot happen cell by cell.
type table struct {
	// buf holds the plain, aligned table until flush colors it.
	buf bytes.Buffer

	// w lays the rows out into buf.
	w *tabwriter.Writer

	// styles holds one style per row, in the order the rows were added.
	styles []func(string) string
}

// newTable returns a table using the column spacing every ggrok table shares.
func newTable() *table {
	t := &table{}
	t.w = tabwriter.NewWriter(&t.buf, 0, tableTabWidth, tableColumnPadding, ' ', 0)

	return t
}

// rowf appends one row, whose cells are separated by tabs. format must render
// exactly one line and end in a newline, since flush pairs styles to lines
// positionally. style is applied to the whole finished line once every
// column's width is known; a nil style leaves the line plain.
func (t *table) rowf(style func(string) string, format string, args ...any) {
	fmt.Fprintf(t.w, format, args...)
	t.styles = append(t.styles, style)
}

// flush lays the table out, styles each row, and writes the result to out.
func (t *table) flush(out io.Writer) error {
	if err := t.w.Flush(); err != nil {
		return err
	}
	if t.buf.Len() == 0 {
		return nil
	}

	var styled strings.Builder
	for i, line := range strings.Split(strings.TrimSuffix(t.buf.String(), "\n"), "\n") {
		if i < len(t.styles) && t.styles[i] != nil {
			line = t.styles[i](line)
		}
		styled.WriteString(line)
		styled.WriteString("\n")
	}

	_, err := io.WriteString(out, styled.String())

	return err
}

// Type names the color value in generated command help.
func (m *colorMode) Type() string { return "mode" }
