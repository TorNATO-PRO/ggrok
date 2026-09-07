package main

import "strconv"

// terminalText keeps peer-controlled text on one line and renders control
// characters as visible escapes, including ANSI sequences and bidi controls.
func terminalText(s string) string {
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
}
