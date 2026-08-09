// The share subcommand creates a QUIC connection to the relay server in which a file
// hosted on your device may be relayed to a downstream consumer.
//
// With -tcp or -udp, share instead forwards a local TCP or UDP service through the
// tunnel to any number of concurrent listen subscribers holding the session's token,
// instead of sharing a file. UDP is forwarded using QUIC's unreliable datagram
// extension (RFC 9221), so it keeps UDP's unordered, unreliable delivery semantics
// rather than being flattened into an ordered, retransmitted stream.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/share"
)

// shareConfig is the parsed and validated input to a share.
type shareConfig struct {
	nodeConnConfig

	// mode is proto.ModeTCP or proto.ModeUDP when -tcp/-udp switches share
	// out of its default file-sharing mode into forwarding a local
	// service through the tunnel; its zero value means file-sharing mode.
	mode proto.Mode

	// addr is the local TCP/UDP service being forwarded, set together
	// with mode. Meaningless in file-sharing mode.
	addr hostport.HostPort

	// token scopes which listen subscribers may reach this session. Set
	// together with mode. nil means -token was omitted, so runShare
	// generates one and prints it.
	token *proto.Token
}

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

			pair, err := hostport.Parse(addr)
			if err != nil {
				return err
			}

			cfg.addr = pair
			cfg.mode = m
			return nil
		}
	}
	fs.Func(
		"tcp",
		"local TCP service to forward, e.g. 127.0.0.1:5432 (mutually exclusive with -udp)",
		setMode(proto.ModeTCP),
	)
	fs.Func(
		"udp",
		"local UDP service to forward, e.g. 127.0.0.1:53 (mutually exclusive with -tcp)",
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
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}

	var cfg shareConfig
	finishConn := registerConnFlags(fs, configDir, fileCfg, &cfg.nodeConnConfig)
	registerModeFlags(fs, &cfg)

	var tokenStr string
	fs.StringVar(&tokenStr, "token", "",
		"token that scopes which listen subscribers may reach this session (generated and printed if omitted)")

	if err := parseFlags(fs, args); err != nil {
		return shareConfig{}, err
	}

	if err := finishConn(); err != nil {
		return shareConfig{}, err
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

// runShare creates a QUIC connection to the relay server, and creates a unique
// token to address the QUIC connection. Terminating this connection will terminate
// the share. Additionally, post quantum encryption is enabled on top of classical
// encryption for they key exchange.
func runShare(args []string) error {
	cfg, err := parseShareFlags(args)
	if err != nil {
		return err
	}

	if cfg.mode == 0 {
		// Neither -tcp nor -udp was given: file-sharing mode.
		// TODO: unimplemented
		return nil
	}

	if cfg.token == nil {
		token, err := proto.NewToken()
		if err != nil {
			return fmt.Errorf("generate token: %w", err)
		}

		cfg.token = &token
		fmt.Fprintf(os.Stdout, "token: %s\n", token)
	}

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
