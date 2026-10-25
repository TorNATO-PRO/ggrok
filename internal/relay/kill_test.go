package relay_test

import (
	"context"
	"errors"
	"testing"

	"tornato.dev/ggrok/v2/internal/proto"
	"tornato.dev/ggrok/v2/internal/relay"
)

// TestKillOutlastsTheReconnect is the whole reason kill exists.
//
// A publisher whose connection merely drops comes straight back: share cannot
// tell a closed connection from a flapped one, and retrying through the latter
// is what its reconnect loop is for. So ending a share cannot be done by
// closing connections alone - that is all the retired admin kick did, and the
// peer undid it in a fraction of a second. A killed session is refused with
// AckDenied instead, which peer.retryable treats as terminal, so the publisher
// exits rather than reappearing under the same tag.
func TestKillOutlastsTheReconnect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		kill bool
		// wantErr is what the publisher's second registration should get:
		// nil when it may return, ErrDenied when it may not.
		wantErr error
	}{
		{name: "dropped publisher may return", kill: false, wantErr: nil},
		{name: "killed publisher may not", kill: true, wantErr: proto.ErrDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			addr, root, registry := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})
			clientCfg := testTLSConfig(t, root, false)
			pub, _ := newSession(t)

			control := registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)

			if tt.kill {
				admin, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
				if err != nil || !ack.OK {
					t.Fatalf("admin refused: %v %+v", err, ack)
				}
				result := requestMutation(t, admin, proto.AdminKill,
					proto.AdminKillPayload{Tag: pub.SessionID().LogTag()})
				if !result.OK {
					t.Fatalf("relay refused the kill: %s", result.Detail)
				}
			} else {
				_ = control.Close()
			}

			// Either way the session ends on the relay's handler goroutine a
			// moment later. Waiting for that is also what keeps the dropped
			// arm from racing its own re-registration into AckPublisherExists.
			waitForNoSessions(t, registry)

			_, err := dialControl(t, addr.String(), clientCfg, pub, proto.RolePublish)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("second registration = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestKillIsScopedToOneSession covers the granularity nothing else has: one
// certificate publishing several sessions, of which exactly one should stop.
// Revocation works on the certificate and would have taken all three.
func TestKillIsScopedToOneSession(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})

	// One identity, three sessions - the shape an operator actually sees when
	// a single laptop is sharing more than one service.
	clientCfg := testTLSConfig(t, root, false)
	const sessions = 3
	creds := make([]proto.Credentials, 0, sessions)
	for range sessions {
		pub, _ := newSession(t)
		registerControl(t, addr.String(), clientCfg, pub, proto.RolePublish)
		creds = append(creds, pub)
	}

	admin, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	doomed := creds[1]
	result := requestMutation(t, admin, proto.AdminKill,
		proto.AdminKillPayload{Tag: doomed.SessionID().LogTag()})
	if !result.OK {
		t.Fatalf("relay refused the kill: %s", result.Detail)
	}

	snapshot := requestSnapshot(t, admin)
	if len(snapshot.Sessions) != sessions-1 {
		t.Fatalf("snapshot has %d sessions, want %d", len(snapshot.Sessions), sessions-1)
	}
	for _, sess := range snapshot.Sessions {
		if sess.Tag == doomed.SessionID().LogTag() {
			t.Fatalf("the killed session is still listed: %+v", sess)
		}
	}

	// The survivors are untouched: still registered, and still able to
	// re-register, which is what says they were not banned along the way.
	for i, cred := range creds {
		if i == 1 {
			continue
		}
		if _, err := dialControl(t, addr.String(), clientCfg, cred, proto.RolePublish); !errors.Is(
			err, proto.ErrPublisherExists,
		) {
			t.Fatalf("session %d = %v, want ErrPublisherExists (still live and unbanned)", i, err)
		}
	}
}

// TestKillRejectsATagItCannotResolve keeps a typo an answer rather than a
// dropped admin connection - an operator retypes a tag off a listing by hand,
// and getting nothing back is indistinguishable from the relay dying.
func TestKillRejectsATagItCannotResolve(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr, root, _ := adminRelay(ctx, t, relay.TestServerConfig{Admin: true})

	admin, ack, err := dialAdmin(t, addr.String(), roleTLSConfig(t, root, true))
	if err != nil || !ack.OK {
		t.Fatalf("admin refused: %v %+v", err, ack)
	}

	for _, tag := range []string{"", "deadbeefdead"} {
		result := requestMutation(t, admin, proto.AdminKill, proto.AdminKillPayload{Tag: tag})
		if result.OK {
			t.Fatalf("relay accepted a kill for tag %q", tag)
		}
		if result.Detail == "" {
			t.Fatalf("refusing tag %q carried no reason", tag)
		}
	}
}
