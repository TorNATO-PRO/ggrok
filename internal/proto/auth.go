package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const challengeSize = 32

// NewAuthenticatedConn proves token possession before returning a data stream.
// Both peers contribute fresh challenges; the transcript binds their roles,
// the protocol version, and the requested port. Its derived stream secret
// prevents a relay from replaying ciphertext into another connection, even
// when the same session token is reused. The caller must set an I/O deadline.
func NewAuthenticatedConn(conn io.ReadWriteCloser, token Token, role Role, port PortIndex) (*EncryptedConn, error) {
	if role != RolePublish && role != RoleSubscribe {
		return nil, fmt.Errorf("authenticate tunnel: invalid role %d", role)
	}

	pub, sub, err := exchangeChallenges(conn, role)
	if err != nil {
		return nil, fmt.Errorf("exchange tunnel challenges: %w", err)
	}

	transcript := append([]byte(ALPN), sub[:]...)
	transcript = append(transcript, pub[:]...)
	transcript = binary.BigEndian.AppendUint16(transcript, uint16(port))
	pubProof := tunnelMAC(token, "publisher proof", transcript)
	subProof := tunnelMAC(token, "subscriber proof", transcript)

	if role == RolePublish {
		err = writeFull(conn, pubProof)
		if err == nil {
			err = verifyProof(conn, subProof)
		}
	} else {
		err = verifyProof(conn, pubProof)
		if err == nil {
			err = writeFull(conn, subProof)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("authenticate tunnel: %w", err)
	}

	var streamToken Token
	copy(streamToken[:], tunnelMAC(token, "stream secret", transcript))
	return NewEncryptedConn(conn, streamToken, role)
}

// exchangeChallenges orders I/O so even an unbuffered transport cannot deadlock.
func exchangeChallenges(conn io.ReadWriter, role Role) ([challengeSize]byte, [challengeSize]byte, error) {
	var local, remote [challengeSize]byte
	if _, err := rand.Read(local[:]); err != nil {
		return local, remote, err
	}
	if role == RoleSubscribe {
		if err := writeFull(conn, local[:]); err != nil {
			return remote, local, err
		}
		_, err := io.ReadFull(conn, remote[:])
		return remote, local, err
	}
	if _, err := io.ReadFull(conn, remote[:]); err != nil {
		return local, remote, err
	}
	return local, remote, writeFull(conn, local[:])
}

// tunnelMAC uses independent keys for the two proofs and the stream secret.
func tunnelMAC(token Token, purpose string, transcript []byte) []byte {
	var key [sha256.Size]byte
	deriveKey(token, "ggrok tunnel "+purpose, key[:])
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(transcript)
	return mac.Sum(nil)
}

func verifyProof(r io.Reader, expected []byte) error {
	var proof [sha256.Size]byte
	if _, err := io.ReadFull(r, proof[:]); err != nil {
		return err
	}
	if !hmac.Equal(proof[:], expected) {
		return fmt.Errorf("invalid token proof or port binding")
	}
	return nil
}

// writeFull rejects a writer that silently drops part of a wire message.
func writeFull(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}
