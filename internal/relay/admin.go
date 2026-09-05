package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"tornato.dev/ggrok/v2/internal/ca"
	"tornato.dev/ggrok/v2/internal/proto"
)

// adminIdleTimeout bounds how long an admin connection may sit without
// sending a frame. An operator's client is interactive and either asks
// something promptly or goes away; this is what stops an authenticated but
// idle admin connection from holding one of relay's bounded sockets open
// indefinitely.
const adminIdleTimeout = 5 * time.Minute

// Snapshot returns everything relay is currently carrying, as one consistent-
// enough picture: sessions are collected under the registry lock, then each
// session's own contents under its lock. The two locks are never held at
// once, so a snapshot can never block a session that is busy pairing streams.
//
// "Consistent-enough" is the deliberate bar. A session that registers or
// leaves while this runs may or may not appear, and its stream counters are
// read at slightly different instants from one another. Making that airtight
// would mean stopping the relay to describe it, which is a far worse trade
// than an operator occasionally seeing a stream that ended a millisecond ago.
func (r *Registry) Snapshot() proto.Snapshot {
	r.mu.Lock()
	sessions := make(map[proto.SessionID]*session, len(r.sessions))
	maps.Copy(sessions, r.sessions)
	r.mu.Unlock()

	out := proto.Snapshot{Now: time.Now(), Sessions: make([]proto.SessionSummary, 0, len(sessions))}
	for id, sess := range sessions {
		out.Sessions = append(out.Sessions, sess.summarize(id))
	}

	return out
}

// summarize renders one session for an admin snapshot.
func (s *session) summarize(id proto.SessionID) proto.SessionSummary {
	summary := proto.SessionSummary{
		Tag:       id.LogTag(),
		Mode:      s.mode.String(),
		Ports:     s.ports,
		Since:     s.since,
		Publisher: s.publisherPeer.summary(s.since),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	summary.Subscribers = make([]proto.PeerSummary, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		summary.Subscribers = append(summary.Subscribers, sub.peer.summary(sub.since))
	}

	summary.Streams = make([]proto.StreamSummary, 0, len(s.streams))
	for reqID, str := range s.streams {
		summary.Streams = append(summary.Streams, proto.StreamSummary{
			ReqID:      reqID,
			Port:       uint16(str.port),
			Started:    str.started,
			BytesToSub: str.counter.IntoA.Load(),
			BytesToPub: str.counter.IntoB.Load(),
		})
	}

	for reqID, req := range s.pending {
		entry := proto.PendingSummary{ReqID: reqID, Port: uint16(req.port), Since: req.since}
		if addr := req.conn.RemoteAddr(); addr != nil {
			entry.Address = addr.String()
		}
		summary.Pending = append(summary.Pending, entry)
	}

	return summary
}

// summary renders an identity for the wire. since is passed in rather than
// stored on peerIdentity because the publisher's "since" is the session's,
// and duplicating it would let the two drift.
func (p peerIdentity) summary(since time.Time) proto.PeerSummary {
	return proto.PeerSummary{CN: p.cn, Serial: p.serial, Addr: p.addr, Since: since}
}

// handleAdminConn serves one operator's admin connection: it checks the
// certificate's role, answers with an ack either way, and then serves
// requests until the peer goes away, errors, goes idle for longer than
// adminIdleTimeout, or ctx is canceled. It always closes conn.
//
// A caller whose certificate lacks the role gets a refusal frame rather than
// a bare close, so an operator holding the wrong bundle learns that rather
// than debugging a connection that dies silently. The refusal is the only
// thing such a caller ever gets: no snapshot, no relay state, nothing that
// distinguishes a busy relay from an empty one.
func (s *server) handleAdminConn(ctx context.Context, conn *tls.Conn) {
	defer func() { _ = conn.Close() }()

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	// The helloTimeout deadline set by handleConn is still live and bounds
	// this first read.
	typ, body, err := proto.ReadAdminFrame(conn)
	if err != nil {
		s.logger.WarnContext(ctx, "read admin hello", peerAttr(conn), slog.Any("err", err))
		return
	}
	if typ != proto.AdminHello {
		s.logger.WarnContext(ctx, "admin connection did not open with a hello",
			peerAttr(conn), slog.String("type", typ.String()))
		_ = proto.WriteAdminFrame(conn, proto.AdminAck, proto.AdminAckPayload{
			Err: fmt.Sprintf("expected hello, got %s", typ), Version: proto.AdminVersion,
		})

		return
	}

	var hello proto.AdminHelloPayload
	if decodeErr := proto.DecodeAdminPayload(body, &hello); decodeErr != nil {
		s.logger.WarnContext(ctx, "decode admin hello", peerAttr(conn), slog.Any("err", decodeErr))
		return
	}

	cert, err := peerLeafCert(conn)
	if err != nil || !ca.HasAdminEKU(cert) {
		s.logger.WarnContext(ctx, "admin connection refused: certificate lacks the admin role", peerAttr(conn))
		_ = proto.WriteAdminFrame(conn, proto.AdminAck, proto.AdminAckPayload{
			Err:     "certificate does not carry the admin role",
			Version: proto.AdminVersion,
		})

		return
	}

	if err := proto.WriteAdminFrame(conn, proto.AdminAck, proto.AdminAckPayload{
		OK: true, Version: proto.AdminVersion,
	}); err != nil {
		return
	}

	s.logger.InfoContext(ctx, "admin connected", peerAttr(conn), slog.Int("admin_version", hello.Version))
	defer s.logger.InfoContext(ctx, "admin disconnected", peerAttr(conn))

	s.serveAdmin(ctx, conn)
}

// serveAdmin is the request loop, entered only once the caller's role is
// established.
func (s *server) serveAdmin(ctx context.Context, conn *tls.Conn) {
	for ctx.Err() == nil {
		_ = conn.SetDeadline(time.Now().Add(adminIdleTimeout))

		typ, body, err := proto.ReadAdminFrame(conn)
		if err != nil {
			return
		}

		if err := s.serveAdminRequest(ctx, conn, typ, body); err != nil {
			return
		}
	}
}

// serveAdminRequest answers one request. A non-nil error means the connection
// is finished, not that the request was refused - a refusal is itself an
// answer, written and then waited on for the next request.
func (s *server) serveAdminRequest(
	ctx context.Context,
	conn *tls.Conn,
	typ proto.AdminType,
	body []byte,
) error {
	switch typ {
	case proto.AdminList:
		return proto.WriteAdminFrame(conn, proto.AdminSnapshot, s.registry.Snapshot())

	case proto.AdminKick:
		return s.serveKick(ctx, conn, body)

	case proto.AdminReloadCRL:
		return s.serveReloadCRL(ctx, conn)

	case proto.AdminHello, proto.AdminAck, proto.AdminSnapshot, proto.AdminResult:
		return s.refuseAdminRequest(ctx, conn, typ)

	default:
		return s.refuseAdminRequest(ctx, conn, typ)
	}
}

// serveKick drops every live connection belonging to one certificate serial.
//
// It does not consult the revocation set: kicking and revoking are separate
// decisions. Revoking without kicking leaves an authenticated peer connected
// (see connectionSet.closeMatching), and kicking without revoking is a legitimate thing to
// want on its own - evicting a misbehaving but still-trusted peer, which
// reconnects immediately. An operator who wants the peer gone for good runs
// ca revoke, ca crl, and then reload-crl, which does both.
func (s *server) serveKick(ctx context.Context, conn *tls.Conn, body []byte) error {
	var req proto.AdminKickPayload
	if err := proto.DecodeAdminPayload(body, &req); err != nil {
		return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
			Detail: fmt.Sprintf("malformed kick request: %v", err),
		})
	}
	if req.Serial == "" {
		return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
			Detail: "kick requires a certificate serial",
		})
	}

	closed := s.connections.closeMatching(func(serial string) bool { return serial == req.Serial })
	s.logger.InfoContext(ctx, "admin kicked a serial", peerAttr(conn),
		slog.String("serial", req.Serial), slog.Int("connections_closed", closed))

	return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
		OK:       true,
		Detail:   fmt.Sprintf("closed %d connection(s) for serial %s", closed, req.Serial),
		Affected: closed,
	})
}

// serveReloadCRL re-reads the revoked-serial file and then closes whatever
// the new list covers.
//
// The kick is not a separate courtesy: reloading alone only affects the next
// handshake, so a peer that authenticated before the revocation would stay
// connected indefinitely. Doing both here is what turns ca revoke from
// bookkeeping into enforcement, which is the whole reason this request
// exists.
//
// Reloads are serialized, and every revoked serial is enforced against the
// transport set, including admin sockets and streams from retired sessions.
func (s *server) serveReloadCRL(ctx context.Context, conn *tls.Conn) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if s.revokedFile == "" {
		return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
			Detail: "relay was started without -revoked-file, so there is nothing to reload",
		})
	}

	serials, err := loadRevokedSerials(s.revokedFile)
	if err != nil {
		s.logger.WarnContext(ctx, "admin crl reload failed", peerAttr(conn), slog.Any("err", err))

		return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
			Detail: fmt.Sprintf("reload %s: %v", s.revokedFile, err),
		})
	}

	// Collect the additions before the swap: afterwards there is no record
	// of what the previous set held.
	added := 0
	for serial := range serials {
		if !s.revoked.Contains(serial) {
			added++
		}
	}
	s.revoked.Replace(serials)

	closed := s.connections.closeMatching(s.revoked.Contains)

	s.logger.InfoContext(ctx, "admin reloaded the revocation list", peerAttr(conn),
		slog.Int("revoked_serials", len(serials)), slog.Int("newly_revoked", added),
		slog.Int("connections_closed", closed))

	return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
		OK: true,
		Detail: fmt.Sprintf("%d serial(s) revoked, %d newly so; closed %d connection(s)",
			len(serials), added, closed),
		Affected: closed,
	})
}

// refuseAdminRequest answers a request this relay does not serve. It is an
// answer rather than a dropped connection because the admin client and relay
// can be different builds, and the self-describing schema exists so that
// mismatch is a conversation instead of a hang.
func (s *server) refuseAdminRequest(ctx context.Context, conn *tls.Conn, typ proto.AdminType) error {
	s.logger.WarnContext(ctx, "unsupported admin request", peerAttr(conn), slog.String("type", typ.String()))

	return proto.WriteAdminFrame(conn, proto.AdminResult, proto.AdminResultPayload{
		Detail: fmt.Sprintf("unsupported request %s", typ),
	})
}
