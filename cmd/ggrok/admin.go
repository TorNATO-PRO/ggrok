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
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"tornato.dev/ggrok/v2/internal/mtls"
	"tornato.dev/ggrok/v2/internal/proto"
)

// adminDialTimeout bounds connecting and completing the admin handshake.
// An operator running this interactively should not wait on a relay that is
// not answering.
const adminDialTimeout = 10 * time.Second

// newAdminPeerCommand shares connection options across admin operations.
func newAdminPeerCommand(use, short string) (*cobra.Command, *nodeConnConfig) {
	cmd := newCommand(use, short)
	var cfg nodeConnConfig
	finish := registerConnFlags(cmd.Flags(), &cfg)
	cmd.PreRunE = func(*cobra.Command, []string) error { return finish() }
	return cmd, &cfg
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

// newAdminListCommand prints one snapshot of relay's live sessions.
func newAdminListCommand() *cobra.Command {
	cmd, cfg := newAdminPeerCommand("ls", "List live sessions and connections")
	cmd.RunE = func(*cobra.Command, []string) error { return runAdminList(*cfg) }
	return cmd
}

func runAdminList(cfg nodeConnConfig) error {
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

	return printSnapshot(os.Stdout, stdoutColors(), snapshot)
}

// newAdminKickCommand closes every live connection belonging to one serial.
func newAdminKickCommand() *cobra.Command {
	cmd, cfg := newAdminPeerCommand("kick", "Disconnect every connection for a certificate")
	cmd.Long = cmd.Short + ".\n\nThis does not revoke the certificate; the peer may reconnect. To prevent that,\nrevoke its certificate and reload the relay's revoked certificate list."
	var serial string
	cmd.Flags().StringVar(&serial, "serial", "", "certificate serial shown by ggrok admin ls")
	cmd.RunE = func(*cobra.Command, []string) error {
		if serial == "" {
			return fmt.Errorf("--serial is required")
		}
		return runAdminMutation(*cfg, proto.AdminKick, proto.AdminKickPayload{Serial: serial})
	}
	return cmd
}

// newAdminReloadCRLCommand asks relay to re-read its revoked-serial file.
func newAdminReloadCRLCommand() *cobra.Command {
	cmd, cfg := newAdminPeerCommand("reload-crl", "Reload and enforce the relay's revoked certificate list")
	cmd.RunE = func(*cobra.Command, []string) error { return runAdminMutation(*cfg, proto.AdminReloadCRL, nil) }
	return cmd
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

	fmt.Fprintln(os.Stdout, stdoutColors().green(terminalText(result.Detail)))

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
func printSnapshot(out io.Writer, p palette, snapshot proto.Snapshot) error {
	if len(snapshot.Sessions) == 0 {
		fmt.Fprintln(out, p.dim("no active sessions"))
		return nil
	}

	sessions := snapshot.Sessions
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Tag < sessions[j].Tag })

	for i, sess := range sessions {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "%s %s  %s  %d port(s)  up %s\n",
			p.dim("session"), p.highlight(terminalText(sess.Tag)), terminalText(sess.Mode),
			sess.Ports, roundedSince(snapshot.Now, sess.Since))

		t := newTable()
		t.rowf(p.bold, "  ROLE\tCOMMON NAME\tSERIAL\tADDRESS\tUP\n")
		t.rowf(nil, "  publisher\t%s\t%s\t%s\t%s\n",
			dash(sess.Publisher.CN), dash(sess.Publisher.Serial), dash(sess.Publisher.Addr),
			roundedSince(snapshot.Now, sess.Publisher.Since))
		for _, sub := range sess.Subscribers {
			t.rowf(nil, "  subscriber\t%s\t%s\t%s\t%s\n",
				dash(sub.CN), dash(sub.Serial), dash(sub.Addr), roundedSince(snapshot.Now, sub.Since))
		}
		if err := t.flush(out); err != nil {
			return err
		}

		printStreams(out, p, snapshot.Now, sess)
	}

	return nil
}

// printStreams renders one session's live and pending streams.
func printStreams(out io.Writer, p palette, now time.Time, sess proto.SessionSummary) {
	if len(sess.Streams) == 0 && len(sess.Pending) == 0 {
		fmt.Fprintln(out, p.dim("  (no streams)"))
		return
	}

	streams := sess.Streams
	sort.Slice(streams, func(i, j int) bool { return streams[i].ReqID < streams[j].ReqID })

	t := newTable()
	t.rowf(p.bold, "  STREAM\tPORT\tAGE\tTO SUBSCRIBER\tMb/s\tTO PUBLISHER\tMb/s\n")
	for _, str := range streams {
		t.rowf(nil, "  %d\t%d\t%s\t%d\t%s\t%d\t%s\n",
			str.ReqID, str.Port, roundedSince(now, str.Started),
			str.BytesToSub, megabitsPerSecond(str.BytesToSub, now, str.Started),
			str.BytesToPub, megabitsPerSecond(str.BytesToPub, now, str.Started))
	}
	// A pending request is a subscriber waiting on a publisher that has not
	// answered yet. Showing it separately is the point: a tunnel that is
	// stuck looks entirely different from one that is merely quiet - which is
	// also why the whole row is yellow rather than the four columns that have
	// no number to show yet.
	for _, req := range sess.Pending {
		t.rowf(p.yellow, "  %d\t%d\t%s\tpending\tpending\tpending\tpending\n",
			req.ReqID, req.Port, roundedSince(now, req.Since))
	}
	_ = t.flush(out)
}

// bitsPerByte and bitsPerMegabit convert a byte count into the decimal
// megabits network throughput is conventionally quoted in - decimal, so a
// megabit is 10^6 bits and not 2^20.
const (
	bitsPerByte    = 8
	bitsPerMegabit = 1_000_000
)

// megabitsPerSecond renders the average decimal megabits per second since a
// stream started. A one-shot snapshot cannot measure a recent window without
// retaining state between admin commands, while this average remains useful
// and deterministic for every invocation.
func megabitsPerSecond(byteCount int64, now, started time.Time) string {
	seconds := now.Sub(started).Seconds()
	if byteCount <= 0 || seconds <= 0 {
		return "0.000"
	}

	return fmt.Sprintf("%.3f", float64(byteCount)*bitsPerByte/(seconds*bitsPerMegabit))
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

	return terminalText(s)
}
