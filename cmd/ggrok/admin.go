// The admin subcommand is an operator's view of a running relay: which
// sessions exist, who is attached to each, and what their forwarded
// connections are currently carrying.
//
// It speaks to relay's ordinary listener over the same mTLS as every other
// peer - there is no second port and no HTTP server - and is refused unless
// two independent gates are open: the relay was started with -admin, and this
// client's certificate was issued with `ggrok ca issue -admin`.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"text/tabwriter"
	"time"

	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
)

// adminUsage marks the usage string for the admin command space.
const adminUsage = `ggrok admin - inspect and manage a running relay

Usage:
  ggrok admin ls         [flags]
  ggrok admin kick       -serial <serial> [flags]
  ggrok admin reload-crl [flags]

Requires a certificate issued with ` + "`ggrok ca issue -admin`" + `, and a relay
started with -admin.
`

// adminDialTimeout bounds connecting and completing the admin handshake.
// An operator running this interactively should not wait on a relay that is
// not answering.
const adminDialTimeout = 10 * time.Second

// adminCommands maps an admin sub-verb to the function that handles it.
var adminCommands = map[string]func(args []string) error{
	"ls":         runAdminList,
	"kick":       runAdminKick,
	"reload-crl": runAdminReloadCRL,
}

// runAdmin dispatches to the proper admin sub-verb.
func runAdmin(args []string) error {
	return dispatch(adminCommands, args, runAdminUsage)
}

// runAdminUsage prints the admin command space's usage and reports it as a
// usage error, since a bare `ggrok admin` isn't a valid invocation.
func runAdminUsage(_ []string) error {
	fmt.Fprint(os.Stderr, adminUsage)
	return errUsage
}

// parseAdminFlags parses the connection flags shared by every admin sub-verb,
// following the same precedence chain as share and listen: an explicit flag,
// an environment variable, or configDir's config.json.
func parseAdminFlags(name, usage string, args []string, extra func(*flag.FlagSet)) (nodeConnConfig, error) {
	configDir, err := defaultConfigDir()
	if err != nil {
		return nodeConnConfig{}, err
	}

	fileCfg, err := loadNodeFileConfig(configDir)
	if err != nil {
		return nodeConnConfig{}, err
	}

	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}

	var cfg nodeConnConfig
	finishConn := registerConnFlags(fs, configDir, fileCfg, &cfg)
	if extra != nil {
		extra(fs)
	}

	if err := parseFlags(fs, args); err != nil {
		return nodeConnConfig{}, err
	}

	if err := finishConn(); err != nil {
		return nodeConnConfig{}, err
	}

	return cfg, nil
}

// dialAdmin opens an admin connection to relay and completes the hello/ack
// exchange, so every caller starts from a connection whose role relay has
// already accepted. The caller owns closing the returned connection.
func dialAdmin(ctx context.Context, cfg nodeConnConfig) (*tls.Conn, error) {
	tlsConf, err := mtls.LoadConfig(cfg.certFile, cfg.keyFile, cfg.caFile, false, nil)
	if err != nil {
		return nil, err
	}

	dialer := tls.Dialer{Config: tlsConf}
	dialCtx, cancel := context.WithTimeout(ctx, adminDialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", cfg.server.String())
	if err != nil {
		return nil, fmt.Errorf("connect to relay %s: %w", cfg.server, err)
	}
	tlsConn, _ := conn.(*tls.Conn)

	// Close the connection if ctx ends while a read or write is parked on
	// it - the same unblock idiom the peer package uses, since a blocking
	// socket call does not observe a context on its own.
	stop := context.AfterFunc(ctx, func() { _ = tlsConn.Close() })
	defer stop()

	if err := adminHandshake(tlsConn); err != nil {
		_ = tlsConn.Close()

		return nil, err
	}

	return tlsConn, nil
}

// adminHandshake sends the version probe and reads relay's verdict. A relay
// that refuses the role answers rather than closing, so the error here says
// what is actually wrong.
func adminHandshake(conn *tls.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(adminDialTimeout))

	if err := proto.WriteAdminHello(conn, proto.AdminHelloPayload{
		Version: proto.AdminVersion,
	}); err != nil {
		return err
	}

	typ, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		return fmt.Errorf("relay did not answer the admin handshake "+
			"(is it running with -admin?): %w", err)
	}
	if typ != proto.AdminAck {
		return fmt.Errorf("relay answered the admin handshake with %s", typ)
	}

	var ack proto.AdminAckPayload
	if err := proto.DecodeAdminPayload(body, &ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("relay refused this client: %s", ack.Err)
	}

	_ = conn.SetDeadline(time.Time{})

	return nil
}

// adminListUsage marks the usage string for `ggrok admin ls`.
const adminListUsage = `ggrok admin ls - list what a relay is currently carrying

Usage:
  ggrok admin ls [flags]

Flags:
`

// runAdminList prints one snapshot of relay's live sessions.
func runAdminList(args []string) error {
	cfg, err := parseAdminFlags("admin ls", adminListUsage, args, nil)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conn, err := dialAdmin(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	snapshot, err := requestSnapshot(ctx, conn)
	if err != nil {
		return err
	}

	return printSnapshot(os.Stdout, snapshot)
}

// adminKickUsage marks the usage string for `ggrok admin kick`.
const adminKickUsage = `ggrok admin kick - drop every live connection for one certificate

Usage:
  ggrok admin kick -serial <serial> [flags]

The serial is the one ` + "`ggrok admin ls`" + ` and ` + "`ggrok ca list`" + ` both show. This
closes connections; it does not revoke the certificate, so the peer may
reconnect immediately. To keep it out, revoke it and reload:

  ggrok ca revoke -common-name <name>
  ggrok ca crl -out <revoked-file>
  ggrok admin reload-crl

Flags:
`

// runAdminKick closes every live connection belonging to one serial.
func runAdminKick(args []string) error {
	var serial string
	cfg, err := parseAdminFlags("admin kick", adminKickUsage, args, func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "",
			"the certificate serial to drop, as shown by `ggrok admin ls`")
	})
	if err != nil {
		return err
	}
	if serial == "" {
		return fmt.Errorf("-serial is required")
	}

	return runAdminMutation(cfg, proto.AdminKick, proto.AdminKickPayload{Serial: serial})
}

// adminReloadCRLUsage marks the usage string for `ggrok admin reload-crl`.
const adminReloadCRLUsage = `ggrok admin reload-crl - re-read the revoked-serial list and enforce it

Usage:
  ggrok admin reload-crl [flags]

Relay re-reads the -revoked-file it was started with, then closes every live
connection the new list now covers. Without this, ` + "`ggrok ca revoke`" + ` affects
no connection - live or new - until relay is restarted.

Flags:
`

// runAdminReloadCRL asks relay to re-read its revoked-serial file.
func runAdminReloadCRL(args []string) error {
	cfg, err := parseAdminFlags("admin reload-crl", adminReloadCRLUsage, args, nil)
	if err != nil {
		return err
	}

	return runAdminMutation(cfg, proto.AdminReloadCRL, nil)
}

// runAdminMutation sends one mutating request and reports relay's verdict.
// A refusal is relay's answer, not a transport failure, so it becomes a
// non-zero exit with relay's own explanation rather than a generic error.
func runAdminMutation(cfg nodeConnConfig, typ proto.AdminType, payload any) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conn, err := dialAdmin(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	result, err := requestMutation(ctx, conn, typ, payload)
	if err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("relay refused: %s", result.Detail)
	}

	fmt.Fprintln(os.Stdout, result.Detail)

	return nil
}

// requestMutation sends one mutating request and decodes the result frame.
func requestMutation(
	ctx context.Context,
	conn *tls.Conn,
	typ proto.AdminType,
	payload any,
) (proto.AdminResultPayload, error) {
	return requestAdmin[proto.AdminResultPayload](ctx, conn, typ, proto.AdminResult, payload)
}

// requestSnapshot asks for and decodes one snapshot.
func requestSnapshot(ctx context.Context, conn *tls.Conn) (proto.Snapshot, error) {
	return requestAdmin[proto.Snapshot](ctx, conn, proto.AdminList, proto.AdminSnapshot, nil)
}

// requestAdmin owns deadlines, cancellation, and response validation for one exchange.
func requestAdmin[T any](ctx context.Context, conn *tls.Conn, typ, expected proto.AdminType, payload any) (T, error) {
	var zero T
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(adminDialTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if err := proto.WriteAdminFrame(conn, typ, payload); err != nil {
		return zero, err
	}
	got, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		return zero, err
	}
	if got != expected {
		return zero, fmt.Errorf("relay answered a %s with %s", typ, got)
	}

	var result T
	if err := proto.DecodeAdminPayload(body, &result); err != nil {
		return zero, err
	}
	return result, nil
}

// printSnapshot renders a snapshot as one block per session. Sessions are
// sorted by tag so consecutive runs are diffable rather than reordered by
// whatever the relay's map iteration happened to produce.
func printSnapshot(out *os.File, snapshot proto.Snapshot) error {
	if len(snapshot.Sessions) == 0 {
		fmt.Fprintln(out, "no active sessions")
		return nil
	}

	sessions := snapshot.Sessions
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Tag < sessions[j].Tag })

	for i, sess := range sessions {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "session %s  %s  %d port(s)  up %s\n",
			sess.Tag, sess.Mode, sess.Ports, roundedSince(snapshot.Now, sess.Since))

		w := tabwriter.NewWriter(out, 0, tableTabWidth, tableColumnPadding, ' ', 0)
		fmt.Fprintln(w, "  ROLE\tCOMMON NAME\tSERIAL\tADDRESS\tUP")
		fmt.Fprintf(w, "  publisher\t%s\t%s\t%s\t%s\n",
			dash(sess.Publisher.CN), dash(sess.Publisher.Serial), dash(sess.Publisher.Addr),
			roundedSince(snapshot.Now, sess.Publisher.Since))
		for _, sub := range sess.Subscribers {
			fmt.Fprintf(w, "  subscriber\t%s\t%s\t%s\t%s\n",
				dash(sub.CN), dash(sub.Serial), dash(sub.Addr), roundedSince(snapshot.Now, sub.Since))
		}
		if err := w.Flush(); err != nil {
			return err
		}

		printStreams(out, snapshot.Now, sess)
	}

	return nil
}

// printStreams renders one session's live and pending streams.
func printStreams(out *os.File, now time.Time, sess proto.SessionSummary) {
	if len(sess.Streams) == 0 && len(sess.Pending) == 0 {
		fmt.Fprintln(out, "  (no streams)")
		return
	}

	streams := sess.Streams
	sort.Slice(streams, func(i, j int) bool { return streams[i].ReqID < streams[j].ReqID })

	w := tabwriter.NewWriter(out, 0, tableTabWidth, tableColumnPadding, ' ', 0)
	fmt.Fprintln(w, "  STREAM\tPORT\tAGE\tTO SUBSCRIBER\tTO PUBLISHER")
	for _, str := range streams {
		fmt.Fprintf(w, "  %d\t%d\t%s\t%d\t%d\n",
			str.ReqID, str.Port, roundedSince(now, str.Started), str.BytesToSub, str.BytesToPub)
	}
	// A pending request is a subscriber waiting on a publisher that has not
	// answered yet. Showing it separately is the point: a tunnel that is
	// stuck looks entirely different from one that is merely quiet.
	for _, req := range sess.Pending {
		fmt.Fprintf(w, "  %d\t%d\t%s\tpending\tpending\n",
			req.ReqID, req.Port, roundedSince(now, req.Since))
	}
	_ = w.Flush()
}

// roundedSince renders how long ago t was, relative to the snapshot's own
// clock rather than this machine's - the two need not agree, and the relay's
// is the one the timestamps came from.
func roundedSince(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	// Clamped because the relay's clock and this one need not agree, and a
	// negative age reads as a bug rather than as clock skew.
	d := max(now.Sub(t), 0)

	return d.Round(time.Second).String()
}

// dash renders an empty field as "-" so a column never looks like it is
// missing rather than empty.
func dash(s string) string {
	if s == "" {
		return "-"
	}

	return s
}
