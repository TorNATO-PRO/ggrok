// The listen subcommand creates a control connection to the relay server
// and subscribes to a share's session by token, then binds a local port
// per port the share forwards: for -tcp, every local connection accepted
// dials a fresh data connection to relay, attached to the session by token
// and tagged with the port it arrived on; for -udp, every local client's
// datagrams are forwarded the same way, framed with a FlowID so relay can
// route replies back to the right local client of the right listen
// subscriber.
//
// listen is a persistent local listener rather than a one-shot transfer -
// forwarding a TCP/UDP service is inherently repeatable.

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
	token proto.Token
}

// listenUsage marks the usage string for the listen subcommand.
const listenUsage = `ggrok listen - subscribe to a share's session and forward it to local ports

Usage:
  ggrok listen -tcp <addr> [flags] <token>

An <addr> is host:port, or host:first-last to bind a whole range of ports
at once. The range must be the same size as the one the share forwards;
the two are matched port for port from the start of each range.

The token may instead be supplied via the GGROK_TOKEN environment
variable, which keeps it out of process listings and shell history.

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

	tokenStr := os.Getenv("GGROK_TOKEN")
	switch {
	case fs.NArg() == 1:
		tokenStr = fs.Arg(0)
	case fs.NArg() != 0 || tokenStr == "":
		fs.Usage()
		return listenConfig{}, fmt.Errorf("exactly one token argument (or GGROK_TOKEN) is required")
	}

	token, err := proto.ParseToken(tokenStr)
	if err != nil {
		return listenConfig{}, fmt.Errorf("invalid token: %w", err)
	}
	cfg.token = token

	return cfg, nil
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
	})
}
