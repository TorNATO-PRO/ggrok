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
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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

	// wait permits starting listen before the relay or publisher is available.
	wait bool
}

// newListenCommand registers options without loading local configuration.
func newListenCommand() (*cobra.Command, *listenConfig) {
	cmd := newCommand("listen [token]", "Listen locally for connections to a shared service")
	cmd.Long = cmd.Short + ".\n\nAddresses accept host:port or host:first-last. Ports are matched by position.\nThe positional token is deprecated; prefer --token-file or GGROK_TOKEN."
	cmd.Example = "  ggrok listen --tcp 127.0.0.1:9090 --token-file token.txt"
	cmd.Args = cobra.MaximumNArgs(1)
	fs := cmd.Flags()

	var cfg listenConfig
	finishConn := registerConnFlags(fs, &cfg.nodeConnConfig)
	fs.BoolVar(&cfg.wait, "wait", false, "wait for relay and publisher at startup; Ctrl+C cancels")

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

	// Resolved after parsing rather than as flag defaults, so
	// PrintDefaults never echoes the token into usage or flag-error output.
	var tokenStr, tokenFile string
	fs.StringVar(&tokenStr, "token", "",
		"the subscriber token to join (env GGROK_TOKEN; prefer -token-file)")
	fs.StringVar(&tokenFile, "token-file", "",
		"read the subscriber token from this file instead of -token or the environment (\"-\" for stdin)")

	cmd.PreRunE = func(_ *cobra.Command, _ []string) error {
		var err error

		if err = finishConn(); err != nil {
			return err
		}

		if cfg.addr.Len() == 0 {
			return fmt.Errorf("-tcp <addr> is required")
		}

		tokenStr, err = resolveSubscriberToken(fs, tokenStr, tokenFile)
		if err != nil {
			return err
		}

		token, err := proto.ParseSubscriberToken(tokenStr)
		if err != nil {
			return fmt.Errorf("invalid subscriber token: %w", err)
		}
		cfg.token = token

		return nil
	}
	cmd.RunE = func(_ *cobra.Command, _ []string) error { return runListen(cfg) }
	return cmd, &cfg
}

// resolveSubscriberToken picks the token out of the sources listen accepts,
// in descending order of how well each keeps it out of view: a file, an
// explicit flag, the environment, and finally the positional argument.
//
// The positional form is deprecated rather than removed - it is what every
// existing script and every README predating -token-file passes - so it still
// works and says why it shouldn't.
func resolveSubscriberToken(fs *pflag.FlagSet, tokenStr, tokenFile string) (string, error) {
	if fs.NArg() > 1 {
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
		fmt.Fprintln(os.Stderr, stderrColors().yellow(
			"warning: passing the subscriber token as an argument is deprecated - "+
				"it is visible in process listings and shell history; use -token-file or GGROK_TOKEN",
		))
		return fs.Arg(0), nil
	default:
		return "", fmt.Errorf("a subscriber token is required (-token-file, -token, or GGROK_TOKEN)")
	}
}

// runListen runs the listen command, subscribing to a share's session by
// token and forwarding its local port through the tunnel until the
// process exits.
func runListen(cfg listenConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	p := stdoutColors()
	var addresses []net.Addr
	reportConnecting(cfg.server)

	err := listen.Run(ctx, listen.Config{
		Server:   cfg.server,
		CertFile: cfg.certFile,
		KeyFile:  cfg.keyFile,
		CAFile:   cfg.caFile,
		Mode:     proto.ModeTCP,
		Addr:     cfg.addr,
		Token:    cfg.token,
		Wait:     cfg.wait,
		OnListen: func(addr net.Addr) {
			addresses = append(addresses, addr)
		},
		OnReady: func() error {
			for _, addr := range addresses {
				fmt.Fprintf(os.Stdout, "%s %s\n", p.green("listening on"), p.bold(addr.String()))
			}
			fmt.Fprintln(os.Stderr, stderrColors().green("ready: connected to publisher through "+cfg.server.String()))
			return nil
		},
		OnWaiting:      reportWaiting,
		OnForwardError: newForwardErrorReporter(os.Stderr),
		OnDisconnect:   reportDisconnect,
		OnReconnect:    reportReconnect,
	})
	return explainSessionError(err)
}
