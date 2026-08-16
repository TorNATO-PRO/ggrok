// The share subcommand creates a TCP+mTLS connection to the relay server
// and forwards a local TCP or UDP service through the tunnel to any number
// of concurrent listen subscribers holding the session's token.
//
// Either flag takes a single host:port or a host:first-last range, in
// which case every port in the range is forwarded and each subscriber
// binds a range of its own of the same size.
//
// UDP is forwarded over a dedicated QUIC connection's unreliable datagram
// extension (RFC 9221), so it keeps UDP's unordered, unreliable delivery
// semantics - and gets QUIC's congestion control on that connection for
// free - rather than being flattened into an ordered, retransmitted
// stream.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/share"
)

// shareConfig is the parsed and validated input to a share.
type shareConfig struct {
	nodeConnConfig

	// mode is proto.ModeTCP or proto.ModeUDP, set by whichever of
	// -tcp/-udp was given; exactly one is required. Its zero value doubles
	// as the "no mode flag seen yet" sentinel while parsing.
	mode proto.Mode

	// addr is the local TCP/UDP service being forwarded, set together
	// with mode - one port, or a whole range of them.
	addr hostport.Range

	// token scopes which listen subscribers may reach this session. nil
	// means -token was omitted, so runShare generates one and prints it.
	token *proto.Token
}

// shareUsage marks the usage string for the share subcommand.
const shareUsage = `ggrok share - forward a local TCP or UDP service through a relay

Usage:
  ggrok share -tcp|-udp <addr> [flags]

An <addr> is host:port, or host:first-last to forward a whole range of
ports at once. Subscribers bind a range of the same size, matched port
for port from the start of each range.

Flags:
`

// registerModeFlags registers -tcp and -udp on fs, both writing into cfg.
// cfg.mode's own zero value is the "no mode flag seen yet" sentinel,
// checked at the point each flag is parsed. That makes a conflicting
// second flag an immediate error instead of two independent bools that
// could disagree with each other and with cfg.mode.
func registerModeFlags(fs *flag.FlagSet, cfg *shareConfig) {
	setMode := func(m proto.Mode) func(string) error {
		return func(addr string) error {
			if cfg.mode != 0 {
				return fmt.Errorf("-tcp and -udp are mutually exclusive")
			}

			ports, err := hostport.ParseRange(addr)
			if err != nil {
				return err
			}

			cfg.addr = ports
			cfg.mode = m
			return nil
		}
	}
	fs.Func(
		"tcp",
		"local TCP service to forward, e.g. 127.0.0.1:5432 or 127.0.0.1:8000-8010 (mutually exclusive with -udp)",
		setMode(proto.ModeTCP),
	)
	fs.Func(
		"udp",
		"local UDP service to forward, e.g. 127.0.0.1:53 or 127.0.0.1:6000-6010 (mutually exclusive with -tcp)",
		setMode(proto.ModeUDP),
	)
}

// parseShareFlags parses the flags for the share command
// into a validated shareConfig struct. It can fail, however,
// and when it does so an error is returned.
//
// server, cert-file, key-file and ca-file may each come from, in order of
// precedence: an explicit flag, an environment variable, or configDir's
// config.json. cert-file, key-file and ca-file additionally fall back to a
// well-known path inside configDir, since that's where we tell people to
// keep them; server has no such fallback and is required from one of the
// three sources.
func parseShareFlags(args []string) (shareConfig, error) {
	configDir, err := defaultConfigDir()
	if err != nil {
		return shareConfig{}, err
	}

	fileCfg, err := loadNodeFileConfig(configDir)
	if err != nil {
		return shareConfig{}, err
	}

	fs := flag.NewFlagSet("share", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, shareUsage)
		fs.PrintDefaults()
	}

	var cfg shareConfig
	finishConn := registerConnFlags(fs, configDir, fileCfg, &cfg.nodeConnConfig)
	registerModeFlags(fs, &cfg)

	// The env var fallback keeps the bearer token off the command line,
	// where it would be visible to every local user via ps and persisted
	// in shell history. It's applied after parsing rather than as the
	// flag's default so PrintDefaults never echoes the secret into usage
	// or flag-error output.
	var tokenStr string
	fs.StringVar(&tokenStr, "token", "",
		"token that scopes which listen subscribers may reach this session "+
			"(env GGROK_TOKEN; generated and printed if omitted)")

	if err := parseFlags(fs, args); err != nil {
		return shareConfig{}, err
	}

	if tokenStr == "" {
		tokenStr = os.Getenv("GGROK_TOKEN")
	}

	if err := finishConn(); err != nil {
		return shareConfig{}, err
	}

	if cfg.mode == 0 {
		fs.Usage()
		return shareConfig{}, fmt.Errorf("exactly one of -tcp or -udp is required")
	}

	if tokenStr != "" {
		token, err := proto.ParseToken(tokenStr)
		if err != nil {
			return shareConfig{}, fmt.Errorf("invalid -token: %w", err)
		}

		cfg.token = &token
	}

	return cfg, nil
}

// runShare creates a control connection to the relay server, and creates
// a unique token to address it. Terminating this connection will
// terminate the share. Additionally, post quantum encryption is enabled
// on top of classical encryption for the key exchange.
func runShare(args []string) error {
	cfg, err := parseShareFlags(args)
	if err != nil {
		return err
	}

	if cfg.token == nil {
		token, err := proto.NewToken()
		if err != nil {
			return fmt.Errorf("generate token: %w", err)
		}

		cfg.token = &token
	}

	fmt.Fprintf(
		os.Stdout,
		"token: %s\n\nTo connect from another machine, run:\n  ggrok listen -%s %s -server %s %s\n\n",
		*cfg.token, cfg.mode, suggestedListenAddr(cfg.addr), cfg.server, *cfg.token,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return share.Run(ctx, share.Config{
		Server:   cfg.server,
		CertFile: cfg.certFile,
		KeyFile:  cfg.keyFile,
		CAFile:   cfg.caFile,
		Mode:     cfg.mode,
		Addr:     cfg.addr,
		Token:    *cfg.token,
	})
}

// suggestedListenAddr is the local address the printed listen command
// suggests for addr. A single shared port suggests port 0, since the
// subscriber has no reason to care which local port it gets and asking the
// OS never collides with something already running. A range can't do that
// - its ports have to be contiguous, which port 0 can't promise - so it
// suggests the publisher's own numbers, which at least line up with what
// the far side is serving.
func suggestedListenAddr(addr hostport.Range) string {
	if addr.Len() <= 1 {
		return "127.0.0.1:0"
	}

	_, ports, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return net.JoinHostPort("127.0.0.1", ports)
}
