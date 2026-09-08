// The share subcommand creates a TCP+mTLS connection to the relay server and
// forwards a local TCP service through the tunnel to any number of concurrent
// listen subscribers holding the session's subscriber token.
//
// -tcp takes a single host:port or a host:first-last range, in which case
// every port in the range is forwarded and each subscriber binds a range of
// its own of the same size.
//
// share holds two different secrets and they are not interchangeable. The
// session key is the root secret: it stays here, and anyone who has it can
// publish this session. The subscriber token is derived from it and is what
// gets handed out - it can join the session and read its traffic, and it
// cannot publish.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/share"
)

// shareConfig is the parsed and validated input to a share.
type shareConfig struct {
	nodeConnConfig

	// addr is the local TCP service being forwarded - one port or a range.
	addr hostport.Range

	// sessionKey is this session's root secret. nil means no key was
	// supplied by any source, so runShare generates one.
	sessionKey *proto.SessionKey

	// tokenOut is where the subscriber token is written. Empty means print
	// it to stdout, which runShare permits only when stdout is a terminal.
	tokenOut string
}

// registerModeFlags registers -tcp on fs, writing into cfg.
func registerModeFlags(fs *pflag.FlagSet, cfg *shareConfig) {
	fs.Func(
		"tcp",
		"local TCP service to forward, e.g. 127.0.0.1:5432 or 127.0.0.1:8000-8010",
		func(addr string) error {
			ports, err := hostport.ParseRange(addr)
			if err != nil {
				return err
			}
			cfg.addr = ports
			return nil
		},
	)
}

// newShareCommand registers options without loading local configuration.
func newShareCommand() (*cobra.Command, *shareConfig) {
	cmd := newCommand("share", "Forward a local TCP service through a relay")
	cmd.Long = cmd.Short + ".\n\nAddresses accept host:port or host:first-last. Subscribers bind a range of the same size.\nKeep the session key private; only the subscriber token is meant to be handed out."
	cmd.Example = "  ggrok share --tcp 127.0.0.1:8080 --token-out token.txt"
	fs := cmd.Flags()

	var cfg shareConfig
	finishConn := registerConnFlags(fs, &cfg.nodeConnConfig)
	registerModeFlags(fs, &cfg)

	// -session-key-file is the documented way in and -session-key is kept
	// for the case where the secret is already in hand; the env var sits
	// between them. See secrets.go for why the file wins. They are named
	// apart from -key-file, which is this node's TLS private key and an
	// entirely different secret. Both are resolved after parsing rather
	// than as a flag default so PrintDefaults never echoes the secret into
	// usage or flag-error output.
	var keyStr, keyFile string
	fs.StringVar(&keyStr, "session-key", "",
		"this session's key, reused to keep the same subscriber token across restarts "+
			"(env GGROK_SESSION_KEY; prefer -session-key-file; generated if omitted)")
	fs.StringVar(&keyFile, "session-key-file", "",
		"read the session key from this file instead of -session-key or the environment (\"-\" for stdin)")
	fs.StringVar(&cfg.tokenOut, "token-out", "",
		"write the subscriber token to this file instead of stdout (\"-\" forces stdout)")

	cmd.PreRunE = func(_ *cobra.Command, _ []string) error {
		var err error

		if keyFile != "" {
			keyStr, err = readSecretFile(keyFile)
			if err != nil {
				return err
			}
		}

		if keyStr == "" {
			keyStr = os.Getenv("GGROK_SESSION_KEY")
		}

		if err = finishConn(); err != nil {
			return err
		}

		if cfg.addr.Len() == 0 {
			return fmt.Errorf("-tcp <addr> is required")
		}

		if keyStr != "" {
			key, parseErr := proto.ParseSessionKey(keyStr)
			if parseErr != nil {
				return fmt.Errorf("invalid session key: %w", parseErr)
			}

			cfg.sessionKey = &key
		}

		return nil
	}
	cmd.RunE = func(_ *cobra.Command, _ []string) error { return runShare(cfg) }
	return cmd, &cfg
}

// runShare creates a control connection to the relay server under a session
// key that only this process holds, and reports the subscriber token derived
// from it. Terminating this connection will terminate the share.
// Additionally, post quantum encryption is enabled on top of classical
// encryption for the key exchange.
func runShare(cfg shareConfig) error {
	if cfg.sessionKey == nil {
		key, keyErr := proto.NewSessionKey()
		if keyErr != nil {
			return keyErr
		}

		cfg.sessionKey = &key
	}

	creds, err := cfg.sessionKey.Credentials()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	reportConnecting(cfg.server)
	err = share.Run(ctx, share.Config{
		Server:     cfg.server,
		CertFile:   cfg.certFile,
		KeyFile:    cfg.keyFile,
		CAFile:     cfg.caFile,
		Mode:       proto.ModeTCP,
		Addr:       cfg.addr,
		SessionKey: *cfg.sessionKey,
		OnReady: func() error {
			if tokenErr := reportToken(cfg, creds.SubscriberToken()); tokenErr != nil {
				return tokenErr
			}
			fmt.Fprintln(os.Stderr, stderrColors().green(
				"ready: sharing TCP "+cfg.addr.String()+" through "+cfg.server.String(),
			))
			return nil
		},
		OnForwardError: newForwardErrorReporter(os.Stderr),

		OnDisconnect: reportDisconnect,
		OnReconnect:  reportReconnect,
	})
	return explainSessionError(err)
}

// reportToken hands the subscriber token to whoever started this share:
// to -token-out if one was given, and otherwise to stdout - but only when
// stdout is a terminal.
//
// Refusing the non-terminal case is the point rather than an inconvenience.
// A share whose stdout is a pipe, a log file, or a CI job's output is a share
// whose token is about to be written somewhere durable and readable, which is
// exactly how bearer secrets leak. -token-out names a file created 0600
// instead, and "-token-out -" is there for someone who has weighed that and
// wants the pipe anyway.
func reportToken(cfg shareConfig, token proto.SubscriberToken) error {
	if cfg.tokenOut != "" {
		if err := writeSecretFile(cfg.tokenOut, token.String()); err != nil {
			return err
		}

		if cfg.tokenOut != stdioPath {
			fmt.Fprintf(os.Stderr, "subscriber token written to %s\n", stderrColors().bold(cfg.tokenOut))
		}

		return nil
	}

	if !stdoutIsTerminal() {
		return fmt.Errorf(
			"refusing to print the subscriber token to a non-terminal stdout: " +
				"pass -token-out <file>, or -token-out - to print it anyway",
		)
	}

	// The suggested command passes the token through the environment rather
	// than as an argument. A ready-to-paste command with the secret in argv
	// would teach exactly the exposure -token-file exists to avoid, and the
	// tool printing it is what makes people do it.
	p := stdoutColors()
	fmt.Fprintf(
		os.Stdout,
		"subscriber token: %s\n\nTo connect from another machine, run:\n  %s\n\n",
		p.highlight(token.String()),
		p.cyan(fmt.Sprintf("GGROK_TOKEN=%s ggrok listen -tcp %s -server %s",
			token, suggestedListenAddr(cfg.addr), cfg.server)),
	)

	return nil
}

// reportDisconnect and reportReconnect narrate what share and listen do
// when relay goes away, which is to keep redialing it. They write to stderr
// rather than stdout: stdout carries the token and the bound addresses,
// which people pipe into other things, and a tunnel that flaps for an hour
// shouldn't append an hour of commentary to that.
func reportDisconnect(err error, retryIn time.Duration) {
	fmt.Fprintln(os.Stderr, stderrColors().yellow(fmt.Sprintf(
		"connection interrupted: %s; retrying in %s",
		terminalText(err.Error()), retryIn.Round(time.Millisecond),
	)))
}

// reportReconnect notes that a session came back, which is the only signal
// that the gap reportDisconnect announced is over.
func reportReconnect() {
	fmt.Fprintln(os.Stderr, stderrColors().green("ready: reconnected to relay"))
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
