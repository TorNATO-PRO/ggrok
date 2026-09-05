// The listen subcommand creates a control connection to the relay server and
// subscribes to a share's session by token, then binds one local port per
// port the share forwards. Every local connection accepted dials a fresh data
// connection to relay, attached to the session and tagged with the port it
// arrived on, and is spliced to whatever share pairs it with.
//
// listen is a persistent local listener rather than a one-shot transfer -
// forwarding a TCP service is inherently repeatable.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
)

// listenConfig is the parsed and validated input to a listen.
type listenConfig struct {
	nodeConnConfig

	// addr is the local address listen binds - a TCP listener, one per port in the range.
	addr hostport.Range

	// token identifies which publisher's session to subscribe to.
	token proto.SubscriberToken
}

// listenUsage marks the usage string for the listen subcommand.
const listenUsage = `ggrok listen - subscribe to a share's session and forward it to local ports

Usage:
  ggrok listen -tcp <addr> -token-file <file> [flags]

An <addr> is host:port, or host:first-last to bind a whole range of ports
at once. The range must be the same size as the one the share forwards;
the two are matched port for port from the start of each range.

The subscriber token comes from -token-file (or "-" for stdin), the
GGROK_TOKEN environment variable, or -token. It is still accepted as a
positional argument, which is deprecated: an argument is visible to every
local user through ps and is kept in shell history.

Flags:
`

// parseListenFlags parses the flags and positional token argument for the
// listen command into a validated listenConfig struct.
//
// server, cert-file, key-file and ca-file follow the same precedence chain
// as share: an explicit flag, an environment variable, or configDir's
// config.json, with cert-file/key-file/ca-file additionally falling back
// to a well-known path inside configDir.
func parseListenFlags(args []string) (listenConfig, error) {
	configDir, err := defaultConfigDir()
	if err != nil {
		return listenConfig{}, err
	}

	fileCfg, err := loadNodeFileConfig(configDir)
	if err != nil {
		return listenConfig{}, err
	}

	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, listenUsage)
		fs.PrintDefaults()
	}

	var cfg listenConfig
	finishConn := registerConnFlags(fs, configDir, fileCfg, &cfg.nodeConnConfig)

	fs.Func(
		"tcp",
		"local address or range to bind, forwarding each connection through the tunnel",
		func(addr string) error {
			ports, parseErr := hostport.ParseRange(addr)
			if parseErr != nil {
				return parseErr
			}
			cfg.addr = ports
			return nil
		},
	)

	// Registered after parsing rather than as flag defaults, so
	// PrintDefaults never echoes the token into usage or flag-error output.
	var tokenStr, tokenFile string
	fs.StringVar(&tokenStr, "token", "",
		"the subscriber token to join (env GGROK_TOKEN; prefer -token-file)")
	fs.StringVar(&tokenFile, "token-file", "",
		"read the subscriber token from this file instead of -token or the environment (\"-\" for stdin)")

	if err = parseFlags(fs, args); err != nil {
		return listenConfig{}, err
	}

	if err = finishConn(); err != nil {
		return listenConfig{}, err
	}

	if cfg.addr.Len() == 0 {
		fs.Usage()
		return listenConfig{}, fmt.Errorf("-tcp <addr> is required")
	}

	tokenStr, err = resolveSubscriberToken(fs, tokenStr, tokenFile)
	if err != nil {
		return listenConfig{}, err
	}

	token, err := proto.ParseSubscriberToken(tokenStr)
	if err != nil {
		return listenConfig{}, fmt.Errorf("invalid subscriber token: %w", err)
	}
	cfg.token = token

	return cfg, nil
}

// resolveSubscriberToken picks the token out of the sources listen accepts,
// in descending order of how well each keeps it out of view: a file, an
// explicit flag, the environment, and finally the positional argument.
//
// The positional form is deprecated rather than removed - it is what every
// existing script and every README predating -token-file passes - so it still
// works and says why it shouldn't.
func resolveSubscriberToken(fs *flag.FlagSet, tokenStr, tokenFile string) (string, error) {
	if fs.NArg() > 1 {
		fs.Usage()
		return "", fmt.Errorf("at most one token argument is accepted")
	}

	switch {
	case tokenFile != "":
		return readSecretFile(tokenFile)
	case tokenStr != "":
		return tokenStr, nil
	case os.Getenv("GGROK_TOKEN") != "":
		return os.Getenv("GGROK_TOKEN"), nil
	case fs.NArg() == 1:
		fmt.Fprintln(os.Stderr,
			"warning: passing the subscriber token as an argument is deprecated - "+
				"it is visible in process listings and shell history; use -token-file or GGROK_TOKEN")
		return fs.Arg(0), nil
	default:
		fs.Usage()
		return "", fmt.Errorf("a subscriber token is required (-token-file, -token, or GGROK_TOKEN)")
	}
}

// runListen runs the listen command, subscribing to a share's session by
// token and forwarding its local port through the tunnel until the
// process exits.
func runListen(args []string) error {
	cfg, err := parseListenFlags(args)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return listen.Run(ctx, listen.Config{
		Server:   cfg.server,
		CertFile: cfg.certFile,
		KeyFile:  cfg.keyFile,
		CAFile:   cfg.caFile,
		Mode:     proto.ModeTCP,
		Addr:     cfg.addr,
		Token:    cfg.token,
		OnListen: func(addr net.Addr) {
			fmt.Fprintf(os.Stdout, "listening on %s\n", addr)
		},
		OnDisconnect: reportDisconnect,
		OnReconnect:  reportReconnect,
	})
}
