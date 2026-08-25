package peer

import (
	"context"
	"time"
)

// This file exposes the reconnect internals the tests make assertions
// about, so those tests can live in the external peer_test package and
// still reach decisions a caller never makes directly.

// Retryable and RetryDelay are the two halves of Serve's reconnect
// behaviour: whether to redial at all, and how long to wait first.
var (
	Retryable  = retryable
	RetryDelay = retryDelay
)

// The reconnect pacing constants, so the tests assert against the policy
// rather than restating its numbers.
const (
	ReconnectMinDelay  = reconnectMinDelay
	ReconnectMaxDelay  = reconnectMaxDelay
	ReconnectJitterDiv = reconnectJitterDiv
)

// Wait is Serve's cancelable backoff sleep.
func Wait(ctx context.Context, d time.Duration) error { return wait(ctx, d) }
