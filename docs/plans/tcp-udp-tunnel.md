# TCP/UDP tunnel mode: mTLS-gated `share -tcp/-udp`, new `listen` command, byte-relaying `relay`

## Context

`ggrok` currently has CLI scaffolding for `share`, `get`, `relay`, and `ca`, but
`runShare`/`runRelay`/`runGet` are all `TODO: unimplemented` — there is no
networking code at all yet, and no dependency on `quic-go` even though the
README already commits to it. `internal/ca` is the one fully-built piece: a
private mTLS certificate authority.

The design goal (from conversation) is a second data path alongside the
existing file-download story, for forwarding a local TCP or UDP service
through the tunnel to **multiple concurrent listeners**:

- **Publishers (`share`) and subscribers (`listen`) both authenticate via
  mTLS** against the private CA — this is the "are you a provisioned device
  at all" gate, enforced by the QUIC/TLS handshake itself.
- **A subscriber additionally needs a specific token** to reach a specific
  share's stream — this is the "are you authorized for *this* stream" gate,
  independent of identity. Any provisioned device holds an equally-trusted
  cert (see `ca.go:189-191`'s comment), so the token is what scopes access to
  one session.
- **`get` (one-shot HTTP file download) is untouched.** The new command is
  `listen`, because unlike a file pull, forwarding a TCP/UDP service is
  inherently a persistent local listener: it binds locally and, for every new
  local connection/datagram, opens a new logical flow through the tunnel.
- **One publisher, many subscribers per token.** A single share can be
  fronted by multiple concurrent `listen` processes.

Researched `quic-go` (`github.com/quic-go/quic-go`, current latest `v0.61.0`,
no `/v2` in the import path) API to ground this plan:
- ALPN (`tls.Config.NextProtos`) is mandatory on both dial and listen sides.
- `*quic.Conn` has `OpenStreamSync(ctx)` / `AcceptStream(ctx)`; `*quic.Stream`
  structurally satisfies `io.Reader`/`io.Writer` so `io.Copy` works directly;
  `stream.Close()` half-closes (send side only). Opening/accepting streams
  concurrently from multiple goroutines on the same `*quic.Conn` is safe —
  this is what makes TCP-mode fan-out simple (see below).
- Datagrams (RFC 9221) need `quic.Config.EnableDatagrams: true` on both
  peers; `conn.SendDatagram([]byte)` / `conn.ReceiveDatagram(ctx)`; no
  fragmentation (oversized payload errors). Datagrams carry **no built-in
  flow/connection identity** beyond "which QUIC connection they arrived on" —
  this is the crux of the UDP fan-out design below.
- `quic.Config.KeepAlivePeriod` defaults to 0 (disabled) — must be set
  explicitly for long-idle tunnels, or `MaxIdleTimeout` (default 30s) closes
  them. `MaxIncomingStreams` defaults to 100 — relay should raise it since it
  multiplexes many logical connections per QUIC connection.
- Peer identity after handshake: `conn.ConnectionState().TLS.PeerCertificates[0]`.

## Fan-out design

**TCP is naturally multi-subscriber already.** Each subscriber's local
`Accept()` is an independent flow that becomes its own QUIC stream, gets its
own freshly-opened stream on the publisher's connection, and replies route
back on that same stream pair. Supporting N concurrent `listen` processes
just means relay runs one independent splice-loop per subscriber connection,
all reading from the same publisher connection's `OpenStreamSync` — no
shared state needed beyond "who is the current publisher for this token."

**UDP needs a per-flow NAT, and it costs relay its "dumb pipe" purity.**
Once more than one subscriber's traffic lands on the *one* publisher
connection, a bare datagram payload no longer says whose traffic it is or
which local client it came from — so a small header has to travel with each
datagram, and relay has to read (and partially rewrite) it in order to route
replies to the right subscriber. This is the deliberate choice made in
answering the "per-flow NAT vs. broadcast" question: each subscriber's local
UDP clients should look like independent peers to the shared service (same
request/reply semantics TCP mode gets for free), not a broadcast copy.

- `listen` (UDP mode) binds one local UDP socket. Each distinct local
  `remoteAddr` it observes via `ReadFromUDP` is assigned a `FlowID` (uint16,
  scoped to that subscriber's own connection — subscribers number their own
  flows independently starting from 0), tracked in a `map[FlowID]net.Addr`
  so replies can be written back to the right local peer. Datagrams sent to
  relay are framed `[2-byte FlowID][payload]`.
- `relay` assigns each subscriber connection a `SubscriberID` (uint16) when
  it registers. Forwarding subscriber → publisher, relay rewrites the frame
  to `[2-byte SubscriberID][2-byte FlowID][payload]` before calling
  `publisherConn.SendDatagram`. Forwarding publisher → subscriber, relay
  reads that 4-byte header off `publisherConn.ReceiveDatagram`, looks up the
  live subscriber connection by `SubscriberID`, strips the `SubscriberID`
  back off, and sends `[FlowID][payload]` on to that specific subscriber.
  (4 bytes of header overhead total — negligible against the no-fragmentation
  datagram size limit.)
- `share` (UDP mode, publisher side) maintains a NAT table
  `map[(SubscriberID, FlowID)]net.Conn`: on the first datagram seen for a new
  key, it dials a **new** local UDP socket to the target address (so the
  real service sees a genuinely distinct source port per virtual remote
  client, exactly like a real NAT gateway) and starts a reader goroutine that
  tags replies with the same `(SubscriberID, FlowID)` header before sending
  them back through the publisher's connection. Idle entries (no traffic for
  e.g. 2 minutes) are evicted and their local socket closed, since this is
  otherwise an unbounded per-client resource leak for a long-lived share.

TCP mode needs none of this — no header, no NAT table, relay stays a pure
byte-splicer there.

## New packages

**`internal/mtls`** — one shared TLS config builder for `share`, `listen`,
and `relay` (they currently each declare their own `certFile`/`keyFile`/
`caFile` fields but no loading logic exists anywhere yet):
```go
func LoadConfig(certFile, keyFile, caFile string, server bool) (*tls.Config, error)
```
Loads the cert/key pair (`tls.LoadX509KeyPair`) and CA pool, sets `NextProtos`
to a shared ALPN constant, and — server side —
`ClientAuth: tls.RequireAndVerifyClientCert` + `ClientCAs`; client side —
`RootCAs` (to verify relay's server cert against our own CA, no
`InsecureSkipVerify`).

**`internal/proto`** — the tiny control-plane wire format, shared by all
three commands:
- `Token` type: 16 random bytes (`crypto/rand`), text-encoded for CLI/URL use
  (`NewToken() (Token, error)`, `(Token) String() string`,
  `ParseToken(string) (Token, error)`).
- `Role` (`RolePublish`/`RoleSubscribe`) and `Mode` (`ModeTCP`/`ModeUDP`)
  small enums.
- `Hello{Role, Mode, Token}` — fixed 18-byte wire encoding (1+1+16 bytes, no
  length-prefix needed), written/read once on the first stream a peer opens
  against relay: `WriteHello(io.Writer, Hello) error`,
  `ReadHello(io.Reader) (Hello, error)`.
- A 1-byte ack/status response from relay after `Hello` (ok / no such token /
  mode mismatch / token already has an active publisher), so `share`/`listen`
  fail fast with a clear error instead of hanging.
- `SubscriberID`/`FlowID` (both `uint16`) and the datagram framing helpers
  described above: `EncodeSubscriberFrame(FlowID, payload) []byte` /
  `DecodeSubscriberFrame([]byte) (FlowID, payload, error)` (2-byte header,
  used on the `listen`↔`relay` leg) and `EncodePublisherFrame(SubscriberID,
  FlowID, payload) []byte` / `DecodePublisherFrame(...)` (4-byte header, used
  on the `relay`↔`share` leg).

**`internal/relay`** — the actual relay/fan-out logic, used only by
`cmd/ggrok/relay.go`:
- `Registry` holds `token → *session` behind a mutex.
- `session` holds `publisher *quic.Conn`, `mode proto.Mode`, and
  `subscribers map[proto.SubscriberID]*quic.Conn` (also mutex-guarded — this
  map changes as `listen` processes come and go).
- `Register(token, mode, conn) (unregister func(), err error)` — called when
  an accepted connection's `Hello.Role == RolePublish`; errors if the token
  already has an active publisher. `unregister` runs when `conn.Context()` is
  done, and also tears down the session's UDP demux goroutine if one is
  running.
- `Bridge(ctx, token, mode, subscriberConn) error` — called when
  `Hello.Role == RoleSubscribe`; looks up the session, checks mode matches,
  allocates a `SubscriberID`, registers `subscriberConn` in the session's
  subscriber map, and:
  - **TCP**: loop `subscriberConn.AcceptStream(ctx)`; for each, open a new
    stream on `publisherConn` via `OpenStreamSync`, then splice
    (`go io.Copy` both directions; propagate close so one side's EOF calls
    `Close()`/`CancelWrite` on the other stream, not `CloseWithError` on the
    whole connection). Runs independently per subscriber — no shared state
    with other subscribers.
  - **UDP**: a per-session singleton goroutine (started on the first
    subscriber, stopped when the last one leaves or the publisher goes away)
    reads `publisherConn.ReceiveDatagram`, decodes the 4-byte header, looks
    the target subscriber up in `subscribers`, and forwards. Each
    subscriber's own goroutine reads `subscriberConn.ReceiveDatagram`,
    encodes the 4-byte header with its `SubscriberID`, and forwards to
    `publisherConn.SendDatagram`.
  - Removes the subscriber from the session's map and releases its
    `SubscriberID` when `subscriberConn.Context()` is done.

## Changes to existing files

**`cmd/ggrok/config.go` (new)** — pull `firstNonEmpty`, and a generalized
version of `share.go`'s `shareFileConfig`/`loadShareFileConfig` (rename to
e.g. `nodeFileConfig`/`loadNodeFileConfig`), out of `share.go` so `listen.go`
can reuse the same server/cert/key/ca precedence chain (flag → env →
`config.json` → default path under `configDir`) without duplication.

**`cmd/ggrok/share.go`**:
- Replace the bare `-udp` `BoolVar` with two mutually-exclusive address-value
  flags, `-tcp <addr>` and `-udp <addr>` (same `fs.Func` + `hostport.Parse`
  pattern already used for `-server` at `share.go:143-152`) — the local
  service `share` will dial into on each new stream/flow.
- Add an optional `-token` flag; if empty, `runShare` generates one via
  `proto.NewToken()` and prints it to stdout so the operator can hand it to
  `listen` operators out of band.
- `runShare`, in tcp/udp mode: `internal/mtls.LoadConfig(..., server=false)`
  → `quic.DialAddr` to `cfg.server` → open first stream, `proto.WriteHello`
  with `RolePublish`.
  - TCP: loop `conn.AcceptStream(ctx)`; per stream, `net.Dial("tcp", addr)`,
    splice both directions, close both ends together. Naturally handles any
    number of concurrent streams from any number of subscribers.
  - UDP: run the NAT table described above — per `(SubscriberID, FlowID)`,
    dial a fresh local UDP socket to `addr`, pump target replies back tagged
    with the same header, evict idle entries.
- File-sharing mode (`share <file>`, no `-tcp`/`-udp`) is untouched — still
  out of scope, stays `TODO: unimplemented`.

**`cmd/ggrok/listen.go` (new)** — mirrors `share.go`'s flag/config precedence
via the shared helpers in `config.go`:
- Flags: `-tcp <bind-addr>` / `-udp <bind-addr>` (mutually exclusive, same
  pattern), `-cert-file`/`-key-file`/`-ca-file`, `-server`. Positional arg:
  the token (parsed with `proto.ParseToken`), mirroring how `get.go` takes
  its URL positionally.
- `runListen`: `internal/mtls.LoadConfig(..., server=false)` → `quic.DialAddr`
  → `proto.WriteHello` with `RoleSubscribe`.
  - TCP: `net.Listen("tcp", bindAddr)`; per `Accept()`, `conn.OpenStreamSync`
    on the QUIC connection, splice both directions.
  - UDP: `net.ListenUDP` on `bindAddr`; maintain the `FlowID ↔ remoteAddr`
    table described above; pump local reads → `SendDatagram` (2-byte
    `FlowID` header), and `ReceiveDatagram` → decode `FlowID` → write back to
    the remembered `remoteAddr`.

**`cmd/ggrok/relay.go`**: `runRelay` builds the server-side `tls.Config` via
`internal/mtls.LoadConfig(..., server=true)`, a `quic.Config` with
`EnableDatagrams: true`, a raised `MaxIncomingStreams`, and a
`KeepAlivePeriod`; `quic.ListenAddr`; accept loop that reads `Hello` off each
connection's first stream and dispatches to `Registry.Register` or
`Registry.Bridge`.

**`cmd/ggrok/ca.go`**: `ggrok ca issue` currently has no way to request a
server-auth cert (`caIssueConfig` / `runCAIssue` at `ca.go:180-263`), but
`relay` needs `ExtKeyUsageServerAuth` on its own cert for TLS client-side
verification to succeed (`ca.IssueRequest.Server`, already supported by
`internal/ca` — just not exposed on the CLI). Add a `-server` bool flag to
`ggrok ca issue` that sets `IssueRequest.Server`. Small, necessary fix,
otherwise there is no way to actually provision a relay identity end-to-end.

**`cmd/ggrok/main.go`**: register `"listen": runListen` in the `commands`
map; add `ggrok listen [flags] <token>` to the top-level `usage` string.

**`go.mod`/`go.sum`**: `go get github.com/quic-go/quic-go@latest`.

## Verification

1. `go build ./...` and `go vet ./...`.
2. End-to-end smoke test by hand (no existing test infra to hook into):
   - `ggrok ca init`
   - `ggrok ca issue -common-name relay -server -out /tmp/relay-id`
   - `ggrok ca issue -common-name share1 -out /tmp/share-id`
   - `ggrok ca issue -common-name listen1 -out /tmp/listen1-id`
   - `ggrok ca issue -common-name listen2 -out /tmp/listen2-id`
   - Start a trivial local TCP service, e.g. `nc -l 127.0.0.1 5432`.
   - `ggrok relay -listen 127.0.0.1:9443 -cert-file /tmp/relay-id/cert.pem -key-file /tmp/relay-id/key.pem -ca-file /tmp/relay-id/ca.pem`
   - `ggrok share -tcp 127.0.0.1:5432 -server 127.0.0.1:9443 -cert-file /tmp/share-id/cert.pem -key-file /tmp/share-id/key.pem -ca-file /tmp/share-id/ca.pem` (note the printed token)
   - `ggrok listen -tcp 127.0.0.1:2345 -server 127.0.0.1:9443 -cert-file /tmp/listen1-id/cert.pem ... <token>` and a second `ggrok listen -tcp 127.0.0.1:2346 ... /tmp/listen2-id ... <token>` — confirm **both** can independently connect through to the one `nc -l` service at the same time (multi-subscriber TCP fan-out).
   - Negative cases: wrong/unregistered token (clean rejection, not a hang); a cert not issued by this CA (TLS handshake failure).
   - Repeat with `-udp` and two `listen -udp` processes, each with `nc -u` from more than one local source: confirm replies from the shared UDP service land back at the correct originating local client on the correct subscriber (validates the `SubscriberID`/`FlowID` NAT), and that one subscriber's local clients never see another subscriber's traffic.

## Future idea (not in scope): friendly DNS name for a `listen` bind address

Raised in conversation, not designed or committed to yet: instead of a
consumer connecting to `listen`'s bare `127.0.0.1:<port>`, give that local
bind address a memorable DNS name (e.g. `mydb.ggrok.local:5432`). Options
worth weighing when this gets picked up:

- **Edit the OS hosts file** (`/etc/hosts`, or the Windows equivalent):
  conceptually simplest, but needs elevated privileges, is a systemwide side
  effect that has to be reliably cleaned up when `listen` exits (including on
  crash), and only maps name → IP — the port still has to be remembered
  separately.
- **mDNS (multicast DNS) advertisement**: register `<name>.local` resolving
  to `127.0.0.1`. No root/admin needed, `.local` resolution works out of the
  box on macOS (Bonjour) and Linux with Avahi (Windows needs Bonjour
  installed separately), and the name disappears automatically when the
  advertising process exits — no stale entries to clean up. Likely the more
  interesting direction since it avoids privilege escalation entirely.
- **Just print a suggested hosts-file line** for the user to add by hand: no
  automatic system modification at all, safest but least convenient.

Worth revisiting once the core tunnel above is built and there's an actual
`listen` bind address to attach a name to.
