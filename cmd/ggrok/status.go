package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	hostport "tornato.dev/ggrok/v2/internal"
	"tornato.dev/ggrok/v2/internal/proto"
)

func reportConnecting(server hostport.HostPort) {
	fmt.Fprintln(os.Stderr, stderrColors().dim("connecting to relay "+server.String()+"..."))
}

func reportWaiting(err error, retryIn time.Duration) {
	state := "waiting for relay"
	if errors.Is(err, proto.ErrNoSuchSession) {
		state = "waiting for publisher; start share with this token's session key"
	}
	fmt.Fprintln(os.Stderr, stderrColors().yellow(fmt.Sprintf("%s: %s; retrying in %s (Ctrl+C cancels)",
		state, terminalText(err.Error()), retryIn.Round(time.Millisecond))))
}

// explainSessionError adds a next step while preserving the underlying error
// for exit handling, including a clean exit on cancellation.
func explainSessionError(err error) error {
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, proto.ErrNoSuchSession):
		return fmt.Errorf("%w; check the subscriber token and start share, or use listen --wait", err)
	case errors.Is(err, proto.ErrPortsMismatch):
		return fmt.Errorf("%w; use TCP ranges with the same number of ports on share and listen", err)
	case errors.Is(err, proto.ErrModeMismatch):
		return fmt.Errorf("%w; use the same forwarding mode on share and listen", err)
	case errors.Is(err, proto.ErrPublisherExists):
		return fmt.Errorf("%w; stop the other share or wait for its old connection to expire", err)
	case errors.As(err, &certErr):
		return fmt.Errorf("%w; check the relay hostname, CA file, and certificate validity", err)
	default:
		return err
	}
}

// forwardErrorInterval bounds terminal noise from concurrent failed clients.
const forwardErrorInterval = 5 * time.Second

type forwardErrorReporter struct {
	mu         sync.Mutex
	out        io.Writer
	last       time.Time
	suppressed uint64
}

func newForwardErrorReporter(out io.Writer) func(error) {
	r := &forwardErrorReporter{out: out}
	return func(err error) { r.report(err, time.Now()) }
}

func (r *forwardErrorReporter) report(err error, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.last.IsZero() && now.Sub(r.last) < forwardErrorInterval {
		r.suppressed++
		return
	}
	message := "forwarding failed: " + terminalText(err.Error())
	if r.suppressed > 0 {
		message += fmt.Sprintf(" (%d additional failures suppressed)", r.suppressed)
	}
	fmt.Fprintln(r.out, stderrColors().yellow(message))
	r.last = now
	r.suppressed = 0
}
