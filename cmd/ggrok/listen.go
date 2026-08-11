// The listen subcommand creates a control connection to the relay server
// and subscribes to a share's session by token, then binds a local port:
// for -tcp, every local connection accepted dials a fresh data connection
// to relay, attached to the session by token; for -udp, every local
// client's datagrams are forwarded the same way, framed with a FlowID so
// relay can route replies back to the right local client of the right
// listen subscriber.
//
// Unlike get, which pulls one file and exits, listen is a persistent local
// listener - forwarding a TCP/UDP service is inherently repeatable, not a
// one-shot transfer.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/listen"
	"tornato.dev/ggrok/v2/internal/proto"
)

// listenConfig is the parsed and validated input to a listen.
type listenConfig struct {
	nodeConnConfig

	// mode is proto.ModeTCP or proto.ModeUDP, set by whichever of -tcp/-udp
	// was given; exactly one is required.
	mode proto.Mode

	// addr is the local address listen binds - a TCP listener or a UDP
	// socket, per mode.
	addr hostport.HostPort

	// token identifies which publisher's session to subscribe to.
	token proto.Token
}

// listenUsage marks the usage string for the listen subcommand.
const listenUsage = `ggrok listen - subscribe to a share's session and forward it to a local port

Usage:
  ggrok listen [flags] <token>

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

	var addrSet bool
	setMode := func(m proto.Mode) func(string) error {
		return func(addr string) error {
			if addrSet {
				return fmt.Errorf("-tcp and -udp are mutually exclusive")
			}

			pair, parseErr := hostport.Parse(addr)
			if parseErr != nil {
				return parseErr
			}

			cfg.addr = pair
			cfg.mode = m
			addrSet = true
			return nil
		}
	}
	fs.Func(
		"tcp",
		"local address to bind, forwarding each connection through the tunnel (mutually exclusive with -udp)",
		setMode(proto.ModeTCP),
	)
	fs.Func(
		"udp",
		"local address to bind, forwarding each client's datagrams through the tunnel (mutually exclusive with -tcp)",
		setMode(proto.ModeUDP),
	)

	if err = parseFlags(fs, args); err != nil {
		return listenConfig{}, err
	}

	if err = finishConn(); err != nil {
		return listenConfig{}, err
	}

	if !addrSet {
		fs.Usage()
		return listenConfig{}, fmt.Errorf("exactly one of -tcp or -udp is required")
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return listenConfig{}, fmt.Errorf("exactly one token argument is required")
	}

	token, err := proto.ParseToken(fs.Arg(0))
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
		Mode:     cfg.mode,
		Addr:     cfg.addr,
		Token:    cfg.token,
	})
}
