package proto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// frameLenSize is the width of the length prefix in front of every encrypted
// frame. It counts the ciphertext, tag included, so a reader knows exactly
// how many bytes to pull off the wire before it can authenticate anything.
const frameLenSize = 2

// noncePrefixSize is the width of the random per-stream value each writer
// sends once, ahead of its first frame, and prepends to every nonce it
// builds from there (see nonce).
//
// The data keys are a pure function of the session's token, so every stream
// in a session shares them - and every stream numbers its frames from zero.
// Without something to separate them, two streams in the same direction seal
// their first frames under the same key and the same nonce, which is
// keystream reuse across streams exactly as a shared key would be across
// directions. The prefix is what makes each stream's nonce sequence its own.
//
// 16 bytes is drawn from crypto/rand per stream, so the chance any two
// streams in a session collide stays negligible for far more streams than a
// relay will ever carry.
const noncePrefixSize = 16

// maxFramePlaintext is the most plaintext one frame can carry: whatever is
// left of the length prefix's range once the tag is accounted for. A Write
// larger than this is split across consecutive frames.
const maxFramePlaintext = math.MaxUint16 - chacha20poly1305.Overhead

// EncryptedConn wraps a relay-facing connection so everything crossing it is
// sealed with XChaCha20-Poly1305 under a key derived from the session's token.
// relay holds no token, so it splices ciphertext it cannot read - the tunnel
// is end-to-end encrypted between share and listen, on top of the mTLS that
// already protects each leg separately.
//
// Each direction has its own key, and each stream within a direction has its
// own random nonce prefix (see noncePrefixSize), so no two frames anywhere in
// a session are ever sealed under the same key and nonce. A writer sends its
// prefix once, in the clear, ahead of its first frame; everything after that
// is frames.
//
// The counter half of the nonce never travels: the reader knows how many
// frames it has read, and a frame that arrives out of order, duplicated, or
// altered simply fails to authenticate. The prefix is unauthenticated in
// transit, but relay can only make frames undecryptable by touching it - it
// cannot induce a nonce it did not choose, since each writer draws its own
// prefix locally and never takes one from its peer.
type EncryptedConn struct {
	conn io.ReadWriteCloser

	// Splice drives one goroutine per direction, so the two halves below are
	// independent and never contend. Each is still guarded, because a
	// counter that drifts from the order frames actually hit the wire
	// desynchronizes the peer permanently rather than corrupting one frame.
	writeMu     sync.Mutex
	writeAEAD   cipher.AEAD
	writeSeq    uint64
	writeBuf    []byte
	writePrefix [noncePrefixSize]byte
	prefixSent  bool

	readMu     sync.Mutex
	readAEAD   cipher.AEAD
	readSeq    uint64
	readPrefix [noncePrefixSize]byte
	prefixSeen bool
	readBuf    []byte // ciphertext staging, reused per frame
	plainBuf   []byte // decrypted frame, reused per frame
	plain      []byte // the part of plainBuf not yet handed to a Read
}

// NewEncryptedConn wraps conn for role's side of token's session. role picks
// which of the two directional keys this peer writes with and which it reads
// with; the two ends of a connection must pass opposite roles or neither can
// decrypt the other.
func NewEncryptedConn(conn io.ReadWriteCloser, token Token, role Role) (*EncryptedConn, error) {
	pubToSub, subToPub := deriveDataKeys(token)

	writeKey, readKey := pubToSub, subToPub
	if role == RoleSubscribe {
		writeKey, readKey = subToPub, pubToSub
	}

	writeAEAD, err := chacha20poly1305.NewX(writeKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypted conn: %w", err)
	}

	readAEAD, err := chacha20poly1305.NewX(readKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypted conn: %w", err)
	}

	c := &EncryptedConn{conn: conn, writeAEAD: writeAEAD, readAEAD: readAEAD}

	// Drawn here rather than on the first Write so a stream that cannot get
	// randomness fails before it has carried anything, not midway through.
	if _, err := rand.Read(c.writePrefix[:]); err != nil {
		return nil, fmt.Errorf("encrypted conn: draw nonce prefix: %w", err)
	}

	return c, nil
}

// nonce renders a stream's prefix and a frame counter as an
// XChaCha20-Poly1305 nonce. The pair is unique per key by construction: the
// prefix separates streams sharing a key, and within one stream the counter
// only ever increments.
func nonce(prefix [noncePrefixSize]byte, seq uint64) [chacha20poly1305.NonceSizeX]byte {
	var n [chacha20poly1305.NonceSizeX]byte
	copy(n[:], prefix[:])
	binary.BigEndian.PutUint64(n[noncePrefixSize:], seq)
	return n
}

// Write seals p and sends it, splitting it across frames if it exceeds
// maxFramePlaintext. It does not buffer: the caller is [io.Copy], so p is
// already "everything that was available to read", which makes it the natural
// frame boundary - batching past it would only add latency, since Copy has
// nothing more to hand over until this returns.
func (c *EncryptedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for {
		chunk := p[written:]
		if len(chunk) > maxFramePlaintext {
			chunk = chunk[:maxFramePlaintext]
		}

		// The stream's nonce prefix rides in front of the first frame, in the
		// same buffer and so the same write: a prefix that reached the peer
		// without the frame behind it would leave the stream looking started
		// when nothing had been sealed yet.
		c.writeBuf = c.writeBuf[:0]
		if !c.prefixSent {
			c.writeBuf = append(c.writeBuf, c.writePrefix[:]...)
		}

		lenAt := len(c.writeBuf)
		c.writeBuf = append(c.writeBuf, 0, 0)

		seal := nonce(c.writePrefix, c.writeSeq)
		c.writeBuf = c.writeAEAD.Seal(c.writeBuf, seal[:], chunk, nil)
		//nolint:gosec // chunk is capped at maxFramePlaintext, so the sealed
		// frame minus its prefix is at most math.MaxUint16 by construction.
		binary.BigEndian.PutUint16(c.writeBuf[lenAt:], uint16(len(c.writeBuf)-lenAt-frameLenSize))
		c.writeSeq++

		if _, err := c.conn.Write(c.writeBuf); err != nil {
			return written, fmt.Errorf("write frame: %w", err)
		}
		c.prefixSent = true

		written += len(chunk)
		if written == len(p) {
			return written, nil
		}
	}
}

// Read returns plaintext from the next frame, buffering whatever does not fit
// in p for the reads that follow.
func (c *EncryptedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	// A peer that sends empty frames would otherwise have Read return
	// (0, nil) forever, which io.Copy spins on rather than treating as EOF.
	for len(c.plain) == 0 {
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}

	n := copy(p, c.plain)
	c.plain = c.plain[n:]

	return n, nil
}

// readFrame pulls one frame off the wire and opens it into plainBuf. Callers
// must hold readMu.
func (c *EncryptedConn) readFrame() error {
	// The peer's nonce prefix comes once, ahead of its first frame. An EOF
	// here is a peer that closed without ever sending one - nothing was
	// forwarded, which is a clean end of stream rather than a failure.
	if !c.prefixSeen {
		if _, err := io.ReadFull(c.conn, c.readPrefix[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return io.EOF
			}
			return fmt.Errorf("read nonce prefix: %w", err)
		}
		c.prefixSeen = true
	}

	var lenBuf [frameLenSize]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		// io.EOF here is the peer closing cleanly on a frame boundary, which
		// is how a forwarded connection is supposed to end - pass it through
		// untouched so io.Copy stops rather than reporting a failure.
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("read frame header: %w", err)
	}

	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size < chacha20poly1305.Overhead {
		return fmt.Errorf("read frame: %d bytes cannot hold a tag", size)
	}

	if cap(c.readBuf) < size {
		c.readBuf = make([]byte, size)
	}
	c.readBuf = c.readBuf[:size]

	if _, err := io.ReadFull(c.conn, c.readBuf); err != nil {
		return fmt.Errorf("read frame body: %w", err)
	}

	open := nonce(c.readPrefix, c.readSeq)
	plain, err := c.readAEAD.Open(c.plainBuf[:0], open[:], c.readBuf, nil)
	if err != nil {
		return fmt.Errorf("decrypt frame %d: %w", c.readSeq, err)
	}
	c.readSeq++

	c.plainBuf = plain
	c.plain = plain

	return nil
}

// Close closes the underlying connection. Nothing is buffered on the write
// side, so there is never unsent plaintext to flush first.
func (c *EncryptedConn) Close() error {
	return c.conn.Close()
}
