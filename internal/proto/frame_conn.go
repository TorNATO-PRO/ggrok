package proto

import (
	"crypto/cipher"
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

// maxFramePlaintext is the most plaintext one frame can carry: whatever is
// left of the length prefix's range once the tag is accounted for. A Write
// larger than this is split across consecutive frames.
const maxFramePlaintext = math.MaxUint16 - chacha20poly1305.Overhead

// EncryptedConn wraps a relay-facing connection so everything crossing it is
// sealed with ChaCha20-Poly1305 under a key derived from the session's token.
// relay holds no token, so it splices ciphertext it cannot read - the tunnel
// is end-to-end encrypted between share and listen, on top of the mTLS that
// already protects each leg separately.
//
// Each direction has its own key and its own frame counter, used directly as
// the nonce. Nothing about the counter travels on the wire: the reader knows
// how many frames it has read, and a frame that arrives out of order or
// altered simply fails to authenticate.
type EncryptedConn struct {
	conn io.ReadWriteCloser

	// Splice drives one goroutine per direction, so the two halves below are
	// independent and never contend. Each is still guarded, because a
	// counter that drifts from the order frames actually hit the wire
	// desynchronizes the peer permanently rather than corrupting one frame.
	writeMu   sync.Mutex
	writeAEAD cipher.AEAD
	writeSeq  uint64
	writeBuf  []byte

	readMu   sync.Mutex
	readAEAD cipher.AEAD
	readSeq  uint64
	readBuf  []byte // ciphertext staging, reused per frame
	plainBuf []byte // decrypted frame, reused per frame
	plain    []byte // the part of plainBuf not yet handed to a Read
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

	writeAEAD, err := chacha20poly1305.New(writeKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypted conn: %w", err)
	}

	readAEAD, err := chacha20poly1305.New(readKey[:])
	if err != nil {
		return nil, fmt.Errorf("encrypted conn: %w", err)
	}

	return &EncryptedConn{conn: conn, writeAEAD: writeAEAD, readAEAD: readAEAD}, nil
}

// nonce renders a frame counter as a ChaCha20-Poly1305 nonce. The counter is
// unique per key by construction - it only ever increments, and the two
// directions use different keys - which is exactly what the nonce has to be.
func nonce(seq uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[chacha20poly1305.NonceSize-8:], seq)
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

		seal := nonce(c.writeSeq)
		c.writeBuf = append(c.writeBuf[:0], 0, 0)
		c.writeBuf = c.writeAEAD.Seal(c.writeBuf, seal[:], chunk, nil)
		//nolint:gosec // chunk is capped at maxFramePlaintext, so the sealed
		// frame minus its prefix is at most math.MaxUint16 by construction.
		binary.BigEndian.PutUint16(c.writeBuf, uint16(len(c.writeBuf)-frameLenSize))
		c.writeSeq++

		if _, err := c.conn.Write(c.writeBuf); err != nil {
			return written, fmt.Errorf("write frame: %w", err)
		}

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

	open := nonce(c.readSeq)
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
