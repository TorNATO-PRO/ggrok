package peer

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"tornato.dev/ggrok/v2/internal/proto"
)

// heartbeatInterval is how often a peer sends a ControlPing on its control
// connection to relay. heartbeatSilenceTimeout bounds how long it waits
// without receiving anything at all before treating relay as dead - the
// same window relay itself uses to notice a dead/hung peer, so either side
// detects the other within a comparable amount of time.
const (
	heartbeatInterval       = 10 * time.Second
	heartbeatSilenceTimeout = 30 * time.Second
)

// ControlHandler is called for every frame [RunControlLoop] reads, in the
// read loop's own goroutine - anything slow enough to stall the next read
// belongs in a goroutine of the handler's own.
//
// Returning a non-nil error ends the loop, and that error is what
// RunControlLoop returns: it's how a handler that recognizes a frame as the
// end of the session reports it as something better than an I/O failure. A
// frame the handler has no use for - and every peer ignores most of them,
// since reading one at all is the liveness signal that matters - is a nil
// return.
type ControlHandler func(typ proto.ControlType, payload []byte) error

// RunControlLoop sends a ControlPing on control every heartbeatInterval and
// passes every frame it reads to handle, until ctx is canceled, control
// errors, relay goes silent for longer than heartbeatSilenceTimeout, or
// handle reports the session over.
func RunControlLoop(ctx context.Context, control *tls.Conn, handle ControlHandler) error {
	stop := make(chan struct{})
	defer close(stop)
	go sendPings(control, stop)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_ = control.SetReadDeadline(time.Now().Add(heartbeatSilenceTimeout))

		typ, payload, err := proto.ReadControlFrame(control)
		if err != nil {
			// A canceled ctx means control was closed out from under this
			// read deliberately - a clean shutdown, which ctx.Err() says far
			// more usefully than the "use of closed network connection" the
			// read produced as a side effect of it.
			if ctx.Err() != nil {
				return ctx.Err()
			}

			return fmt.Errorf("read control frame: %w", err)
		}

		if err := handle(typ, payload); err != nil {
			return err
		}
	}
}

// sendPings writes a ControlPing on control every heartbeatInterval until
// stop is closed. A failed write just ends the pinger silently -
// RunControlLoop's own read deadline is what surfaces a dead connection as
// an error.
func sendPings(control *tls.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := proto.WriteControlFrame(control, proto.ControlPing, nil); err != nil {
				return
			}
		}
	}
}
