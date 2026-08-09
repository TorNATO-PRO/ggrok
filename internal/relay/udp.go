package relay

import (
	"context"
	"fmt"

	"github.com/quic-go/quic-go"

	"tornato.dev/ggrok/v2/internal/proto"
)

// pumpPublisherDatagrams reads datagrams off the session's publisher
// connection, decodes the (SubscriberID, FlowID) header, and forwards each
// to the live subscriber it names - the publisher-to-subscribers direction
// of UDP fan-out. It exits when ctx is canceled (the last subscriber left)
// or the publisher's connection errors.
func (s *session) pumpPublisherDatagrams(ctx context.Context) {
	for {
		data, err := s.publisher.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		sub, flow, payload, err := proto.DecodePublisherFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving peer; drop it
		}

		s.mu.Lock()
		subConn, ok := s.subscribers[sub]
		s.mu.Unlock()
		if !ok {
			continue // that subscriber has already left; drop it
		}

		_ = subConn.SendDatagram(proto.EncodeSubscriberFrame(flow, payload))
	}
}

// bridgeUDP reads datagrams off subscriberConn, tags them with subID, and
// forwards each to the session's publisher - the subscriber-to-publisher
// direction of UDP fan-out. It runs until ctx is done or subscriberConn
// errors.
func (s *session) bridgeUDP(ctx context.Context, subID proto.SubscriberID, subscriberConn *quic.Conn) error {
	for {
		data, err := subscriberConn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive subscriber datagram: %w", err)
		}

		flow, payload, err := proto.DecodeSubscriberFrame(data)
		if err != nil {
			continue // malformed frame from a misbehaving peer; drop it
		}

		if err := s.publisher.SendDatagram(proto.EncodePublisherFrame(subID, flow, payload)); err != nil {
			return fmt.Errorf("send publisher datagram: %w", err)
		}
	}
}
