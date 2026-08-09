// Command ggrok publishes one local file at a public URL for the
// full lifecycle of the process.
//
// We maintain the invariant that the file is never uploaded. The relay
// will only learn that a token maps to a given session, and is the sole
// authority of the aforesaid. Additionally, all traffic is encrypted up
// until the TLS termination boundary. At that point, all bets are off.
// I recommend using Caddy or something along those lines as a reverse proxy
// and for automated certificate management and such. A relay can only ever
// ask "send the file for token X" - it can never induce this process to read
// a path of the relay's choosing. Additionally, the relay must authenticate itself
// and prove provenance with a certificate issued by our CA.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
)

// a usage string to describe how the CLI utility is meant to be used.
const usage = `ggrok: share and receive one local file at a public URL.

Usage:
  ggrok share [flags] <file>
  ggrok share -tcp|-udp <addr> [flags]
  ggrok listen -tcp|-udp <addr> [flags] <token>
  ggrok relay [flags]
  ggrok ca <init|issue|list|revoke> [flags]

The share stays alive until either this process exists, or the TTL elapses.

Flags:
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
// fallback is invoked instead (if non-nil) - this lets a bare `ggrok`
// default to share, `ggrok -h` fall through to share's own usage, and a
// bare/`-h`'d `ggrok ca` print its own usage instead of being treated as
// an unrecognized sub-verb.
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
// accepts as a list of argument strings as an input. When no command
// is provided, we default to the share functionality.
var commands = map[string]func(args []string) error{
	"share":  runShare,
	"listen": runListen,
	"relay":  runRelay,
	"ca":     runCA,
}

// run runs a command over arguments passed by a user. It will
// dispatch to the proper command, but default to `share` whenever
// a command is not provided.
func run(args []string) error {
	return dispatch(commands, args, runShare)
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
