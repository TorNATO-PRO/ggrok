// Command ggrok forwards one or more local TCP/UDP ports through a relay
// to any number of subscribers holding the session's token, for the full
// lifecycle of the process.
//
// The relay only ever learns that a token maps to a given session, and is
// the sole authority of the aforesaid. Traffic is encrypted up until the
// TLS termination boundary. At that point, all bets are off. I recommend
// using Caddy or something along those lines as a reverse proxy and for
// automated certificate management and such. A relay can only ever ask
// "open a connection for token X" - it can never induce this process to
// reach an address of the relay's choosing, since the local addresses are
// fixed by the flags this process was started with. Additionally, the
// relay must authenticate itself and prove provenance with a certificate
// issued by our CA.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
)

// a usage string to describe how the CLI utility is meant to be used.
const usage = `ggrok: forward local TCP/UDP ports through a relay you run yourself.

Usage:
  ggrok share -tcp|-udp <addr> [flags]
  ggrok listen -tcp|-udp <addr> [flags] <token>
  ggrok relay [flags]
  ggrok ca <init|issue|list|revoke> [flags]

An <addr> is host:port, or host:first-last for a range of ports.
The share stays alive until this process exits.

Run a command with -h for its own flags.
`

// errUsage marks a failure the flag package has already written to stderr,
// together with the usage text. Returning it lets main exit non-zero without
// printing a second, redundant description of the same problem.
var errUsage = errors.New("invalid flags")

// errUnknownCommand marks a verb passed by the user that no command map
// recognizes, whether at the top level (e.g. `ggrok bogus`) or within a
// space that has its own sub-verbs (e.g. `ggrok ca bogus`).
var errUnknownCommand = errors.New("unknown command")

// exitUsageError is the conventional Unix exit code for a command invoked
// with invalid arguments, as opposed to exitFailure for everything else.
const exitUsageError = 2

// dispatch looks up args[0] in cmds and invokes it with the remaining
// arguments. When args is empty, or its first element is a help flag,
// fallback is invoked instead (if non-nil) - this lets a bare `ggrok` or
// `ggrok -h` print the top-level usage, and a bare/`-h`'d `ggrok ca` print
// its own usage instead of being treated as an unrecognized sub-verb.
func dispatch(cmds map[string]func(args []string) error, args []string, fallback func(args []string) error) error {
	isHelp := len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help")
	if len(args) > 0 && !isHelp {
		if cmd, ok := cmds[args[0]]; ok {
			return cmd(args[1:])
		}

		return fmt.Errorf("%w: %q", errUnknownCommand, args[0])
	}

	if fallback != nil {
		return fallback(args)
	}

	return fmt.Errorf("%w: no command given", errUnknownCommand)
}

// parseFlags parses args and collapses the two outcomes the flag package
// reports itself: -h, which is not a failure, and a malformed flag, which
// needs no further explanation from the caller.
func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
		return flag.ErrHelp
	default:
		return errUsage
	}
}

// commands defines a mapping from verbs to a function that
// accepts as a list of argument strings as an input.
var commands = map[string]func(args []string) error{
	"share":  runShare,
	"listen": runListen,
	"relay":  runRelay,
	"ca":     runCA,
}

// runUsage prints the top-level usage and reports it as a help request,
// which main treats as a clean exit. It's what a bare `ggrok` and `ggrok
// -h` get: every command needs a verb and an explicit address, so there's
// nothing sensible to guess at when given neither.
func runUsage([]string) error {
	fmt.Fprint(os.Stderr, usage)
	return flag.ErrHelp
}

// run runs a command over arguments passed by a user, dispatching to the
// proper command or printing usage when no command is given.
func run(args []string) error {
	return dispatch(commands, args, runUsage)
}

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, flag.ErrHelp):
		return
	case errors.Is(err, errUsage):
		// The flag package already described the problem and printed usage.
		os.Exit(exitUsageError)
	default:
		fmt.Fprintf(os.Stderr, "ggrok: %v\n", err)
		os.Exit(1)
	}
}
