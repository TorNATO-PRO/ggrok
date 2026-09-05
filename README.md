## GGrok

Have you ever developed a web service and wanted to share it with someone else, securely and reliably so that only they may access it? This is the problem that `ggrok` solves.

GGrok is a TCP tunneling tool. It operates at OSI level 4.

Using `ggrok share -tcp`, you may share a local TCP service - or a whole contiguous
range of ports - through the tunnel to any number of concurrent `listen` subscribers holding the
session's subscriber token.
`relay` terminates each peer's transport TLS connection and forwards a separate end-to-end encrypted stream. Each
node is mutually authenticated by a private CA you run yourself!

Every connection is TLS 1.3 mTLS against that same CA: both the control connection and the data
connections dial relay directly over TCP+TLS 1.3, with a post-quantum hybrid key exchange. On top of
that, the data plane is sealed end-to-end - relay routes a session by an identifier derived from the
publisher's session key and cannot decrypt a byte of what passes through it.

## Install

Clone the repo and install with the Go toolchain:

```bash
git clone https://github.com/TorNATO-PRO/ggrok
cd ggrok
go install ./cmd/ggrok
```

That drops a `ggrok` binary in `$(go env GOPATH)/bin` - make sure it's on your `PATH`. `go install
tornato.dev/ggrok/v2/cmd/ggrok@latest` (the module's declared import path) doesn't work yet, since
that domain isn't wired up to redirect here - clone-and-install is the supported path for now.

Cross-compiled binaries for Linux/macOS/Windows on amd64/arm64 can be built in one shot with `just
build-all` (see the `justfile`), landing in `dist/`.

### Docker, if you'd rather

There's a `Dockerfile` too - it's `scratch` plus the static binary and nothing else, so the image is
essentially just the binary (`docker images` reports ~9 MB). `relay` is the natural thing to run this
way:

```bash
just docker-build          # or: docker build -t ggrok:latest .

docker run --rm -p 4443:4443 -v /etc/ggrok/relay:/certs:ro ggrok:latest \
  relay -listen 0.0.0.0:4443 \
  -cert-file /certs/cert.pem -key-file /certs/key.pem -ca-file /certs/ca.pem
```

Point relay at its certificates explicitly - it has no default paths for them. `share` and `listen`
do default to `~/.ggrok`, which inside the image is `/home/nonroot/.ggrok`, so mounting a bundle
issued by `ggrok ca issue -out <dir>` there lets them run with no cert flags at all.

## Usage

### 1. Stand up a private CA, once

```bash
ggrok ca init
```

Writes a root certificate and key to `~/.ggrok/ca` by default (override with `-out`). Keep this
machine's key safe - anyone who holds it can mint identities that relay, share, and listen will all
trust. It doesn't need to live on the same machine as relay itself.

### 2. Issue a certificate for every node

Run wherever the CA's private key lives (see above), once per node - relay needs a *server*
certificate with a SAN matching however peers will reach it; share and listen need ordinary client
certificates. `-out <dir>` writes `cert.pem`/`key.pem`/`ca.pem` into `<dir>`, which happens to be
exactly the layout share/listen read by default from `~/.ggrok`, so a bundle issued straight into
that path needs no further configuration on the node it's copied to:

```bash
ggrok ca issue -common-name relay -server -dns-name relay.example.com -out /etc/ggrok/relay
ggrok ca issue -common-name my-laptop -out ~/.ggrok
ggrok ca issue -common-name friends-laptop -out /tmp/friend-bundle   # copy this dir to their machine
```

Add `-admin` to issue an operator identity for [managing a running relay](#managing-a-running-relay).
A relay's `-server` certificate is issued for server authentication only, since relay never dials
anyone.

### 3. Run relay

```bash
ggrok relay -listen 0.0.0.0:4443 \
  -cert-file /etc/ggrok/relay/cert.pem -key-file /etc/ggrok/relay/key.pem -ca-file /etc/ggrok/relay/ca.pem
```

That TCP port needs to be reachable from outside - it's the only one relay listens on.

### 4. Share a local TCP service

```bash
ggrok share -tcp 127.0.0.1:8080 -server relay.example.com:4443
```

Prints a **subscriber token** - that's the only thing a `listen` subscriber needs to reach this
session, and it deliberately cannot publish the session (see [Two secrets, not
one](#two-secrets-not-one)). Once `-server`/`-cert-file`/`-key-file`/`-ca-file` are set in
`~/.ggrok/config.json` (see below) or their `GGROK_*` env var, day-to-day this shrinks to just `ggrok
share -tcp 127.0.0.1:8080`.

The token is printed only when stdout is a terminal. Anywhere else - a pipe, a log file, a CI job -
pass `-token-out <file>`, which creates a fresh file with mode `0600` (existing files and symlinks are refused), or `-token-out -` to print it anyway.

Each run generates a fresh session key, and so a fresh token. To keep the same token across
restarts, save the session key once and reuse it:

```bash
ggrok share -tcp 127.0.0.1:8080 -session-key-file ~/.ggrok/session.key
```

### 5. Subscribe from the other side

```bash
ggrok listen -tcp 127.0.0.1:9090 -server relay.example.com:4443 -token-file token.txt
```

Binds `127.0.0.1:9090` locally; every connection to it is forwarded through relay to whatever `share`
is serving. The token can also come from `GGROK_TOKEN` or `-token`; `-token-file -` reads it from
stdin. Passing it as a positional argument still works but is deprecated - an argument is visible to
every local user through `ps` and is kept in shell history.

### Upgrading the wire protocol

This version uses ALPN `ggrok/3`. Upgrade relay, share, and listen together; older peers cannot
connect. The publish handshake grew a challenge round-trip: relay now makes a publisher sign for the
key its `SessionID` is derived from, instead of handing the slot to whoever asks first.

**Tokens issued by earlier versions no longer work.** The single 26-character token is now two
values - a 26-character session key the publisher keeps, and a 52-character subscriber token derived
from it - so every session has to be re-shared. Certificates keep their existing format and do not
need reissuing.

Credential issuance now requires fresh output files: existing `cert.pem`, `key.pem`, or
`ca.pem` files (including symlinks) are refused. For rotation, issue into a new directory
that you control, then explicitly switch the node to the new bundle.

The admin plane did not change the protocol version. It adds a new connection kind, which is purely
additive: an older relay reading one fails immediately and closes, which is the clean refusal the
ALPN pin exists to produce. What forces a version bump is an existing byte meaning something new, or
a handshake growing a round-trip.

Relay permits at most 1024 concurrent sockets, including TLS handshakes, control sockets,
pending data sockets, admin connections, and both halves of active streams. Excess connections are
closed. Share and listen each cap concurrent tunnels at 256;
excess publisher requests time out and excess local listener connections are closed.

### Port ranges

`-tcp` takes `host:first-last` in place of `host:port`, forwarding every port in the
range over the one session:

```bash
ggrok share  -tcp 127.0.0.1:8000-8010                    # publisher: 11 local ports
ggrok listen -tcp 127.0.0.1:9000-9010 -token-file tok    # subscriber: 11 local ports
```

The two ranges are matched **by position, not by number** - `9000` reaches `8000`, `9001` reaches
`8001`, and so on - so the subscriber is free to bind whatever numbers are available locally. What
crosses the wire is an index into the range, and the relay is never told either side's actual port
numbers.

The only requirement is that both ranges are the same size; a subscriber whose range is a different
length is refused at subscribe time rather than left to discover it as ports that mysteriously don't
work. A range is capped at 1024 ports, since each one costs a live socket for the life of the
session.

### Config file, instead of repeating flags

`~/.ggrok/config.json` (or the `GGROK_SERVER`/`GGROK_CERT_FILE`/`GGROK_KEY_FILE`/`GGROK_CA_FILE` env
vars) lets share/listen skip `-server`/`-cert-file`/`-key-file`/`-ca-file` on every invocation:

```json
{
  "server": "relay.example.com:4443",
  "cert_file": "/home/you/.ggrok/cert.pem",
  "key_file": "/home/you/.ggrok/key.pem",
  "ca_file": "/home/you/.ggrok/ca.pem"
}
```

### Revoking a peer

```bash
ggrok ca revoke -common-name friends-laptop
ggrok ca crl -out revoked.txt          # copy this to wherever relay runs
```

Relay reads that file at startup:

```bash
ggrok relay ... -revoked-file revoked.txt
```

To make a revocation take effect on a relay that is already running - including closing the
connections the revoked peer already has open - reload it through the admin plane instead of
restarting:

```bash
ggrok admin reload-crl -server relay.example.com:4443
```

Without that, a revocation reaches nothing until relay restarts: a TLS handshake happens once, so an
already-authenticated peer stays connected, and the file relay read at startup is the only one it
knows about.

### Managing a running relay

Relay can expose an admin plane for the operator who runs it: what is connected right now, and the
two operations that act on it. It is off unless asked for, and reachable only by a certificate
issued with the admin role - two independent gates, either one closed being enough to refuse.

```bash
ggrok ca issue -common-name ops-laptop -admin -out ~/.ggrok-admin   # mint an operator identity
ggrok relay ... -admin                                              # turn the plane on
```

There is no second port and no HTTP server: the admin client speaks to relay's ordinary listener
over the same mTLS as every other peer, and `ggrok ca list` shows a ROLE column so you can see which
certificates carry the role before you need one.

```bash
ggrok admin ls                                # what is connected, and what it is carrying
ggrok admin kick -serial <serial>             # drop one identity's connections
ggrok admin reload-crl                        # re-read the revoked list, and enforce it
```

`ls` reports each session's publisher and subscribers by the identity the CA vouched for, plus every
forwarded connection currently open with a running byte count - which for a tunnel that stays up for
hours is the only account there is, since the log line for a stream is written when it *ends*. Each
byte count is followed by the average rate in decimal megabits per second over the stream's whole
life, so a snapshot answers "is this moving?" without having to diff two of them by hand.

```
session 8f8220ea7b37  tcp  1 port(s)  up 4m12s
  ROLE        COMMON NAME  SERIAL                            ADDRESS          UP
  publisher   my-laptop    568c02dc8f5b2edddc5435018992b366  10.0.0.4:51558   4m12s
  subscriber  friends-lap  f3de3b55a4d3c7cc0d95eddf208cbc01  10.0.0.9:51565   4m10s
  STREAM  PORT  AGE    TO SUBSCRIBER  Mb/s   TO PUBLISHER  Mb/s
  0       0     3m58s  525520         0.018  525520        0.018
```

Note what that means, because it is a real change and not only a convenience: **an operator can see
who is tunneling to whom, and how much.** It does not weaken the cryptographic claim - relay still
holds none of the keys and decrypts nothing, and the byte counts are ciphertext as relay sees it -
but it does make that traffic pattern queryable rather than merely inferable from logs. Sessions are
named by the same truncated tag the logs use; the full SessionID, which is what would let someone
join a tunnel, never appears.

`kick` closes connections and nothing more, so a peer whose certificate is still valid reconnects
immediately. That is the point of having it separate: evicting a misbehaving but still-trusted peer
is a different decision from withdrawing its identity. To make it stick, revoke first and then
`reload-crl`, which does both.

### Features

#### The relay server never parses your traffic

Relay reads exactly one handshake message per connection - a `Hello` or `Attach` naming the session
by its derived `SessionID` - and from then on splices raw bytes between publisher and subscriber
without interpreting any of them. Relay has no idea what application-level protocol you are
tunneling, and per the next section it could not read the payload even if it wanted to.

#### End-to-end encryption, not just hop-by-hop

mTLS secures each leg to relay separately, which would ordinarily make relay a place where plaintext
appears. It isn't. Before forwarding application bytes, share and listen exchange fresh challenges
and HMAC-SHA256 proofs that both hold the session's data secret, binding both roles and the requested
port index. A separate transcript-bound secret derives one XChaCha20-Poly1305 key per direction for
that connection. Relay is handed only the `SessionID`, which is enough to pair a publisher with its
subscribers and nowhere near enough to decrypt a frame - the data keys are not derivable from it, and
relay never holds the secret they come from.

#### Two secrets, not one

A session has a **session key** (26 characters) and a **subscriber token** (52 characters) derived
from it. They are not interchangeable, and the difference is the point:

| | holds | can join and decrypt | can publish |
|---|---|---|---|
| session key | share, and nobody else | yes | **yes** |
| subscriber token | everyone you share with | yes | no |

The session key seeds an ML-DSA-65 keypair, and the `SessionID` relay routes by is derived from a
hash of that keypair's public half. So the identifier commits to a key, and claiming a session means
proving possession of it rather than merely knowing its name.

Both are derived deterministically, so reusing a session key reproduces the same `SessionID` and the
same subscriber token - tokens handed out yesterday still work after a restart.

#### Publishing takes a signature, not just a token

Relay has no enrollment step: the first thing it learns about a session is someone claiming it. So
when a peer asks to publish, relay draws a fresh single-use challenge and requires back the session
public key plus a signature over that challenge and the whole `Hello`. It then checks two independent
things - that the key derives the `SessionID` being claimed, and that the signature verifies under it.

Without this, holding a token was enough to publish. Every subscriber can derive the `SessionID`, so
a subscriber could wait for the real publisher's connection to sever - which relay tolerates for a
full 30-second heartbeat timeout, and which the publisher's own reconnect backoff is deliberately
shaped to keep knocking inside - then register in its place and serve its own service to every other
subscriber, decrypting correctly, with no warning anywhere. The displaced publisher would see
`ErrPublisherExists` and retry into a slot it was never getting back.

The claim is signed rather than pinned to a certificate because the attacker here *is* a legitimate
peer: its certificate is issued by the same CA and is exactly as privileged as the publisher's. A
certificate role can only separate classes of device, and any laptop that runs `share` today runs
`listen` tomorrow. Only per-session key material distinguishes "the peer that owns this tunnel" from
"a peer I gave a token to".

#### Data connections are bound to their control connection's certificate

Every peer maintains two kinds of connections to a relay. One long lived control connection used
to register and subscribe, heartbeat, session closing, and all of that stuff. But the data connections
actually carry the tunneled bytes. An invariant we pursue is that a data connection's client certificate
must be byte-identical to the certificate its owner's control connection authenticated and set up with.

#### Post-quantum hybrid KEX

Harvest now and decrypt later SIGINT types seeth when they see this, which is a good sign. We run
classical `X25519MLKEM768` for securing the key exchange. We mix a robust classical algorithm with
a new and less battle tested algorithm that claims to be quantum resistant. I hope it is. Because if
this doesn't age well, then it will turn out that I probably could have just as well used X25519.
But who knows, NIST and Cloudflare are only betting the future of the internet on this algorithm doing its job.

#### Two-tier trust model

cert = "you're allowed on my network", subscriber token = "you're allowed in *this* tunnel",
session key = "this tunnel is mine."

The admin role is the one exception, and rides on a certificate extension rather than on a name: the
Common Name stays a label for logging and audit, never an input to an authorization decision.

#### Certificate revocation, enforced live

You can revoke a certificate and hand the list to relay. A subsequent connection from the revoked
client is refused at the TLS handshake, and `ggrok admin reload-crl` applies a new list to a relay
that is already running - closing whatever connections the revoked peer still holds open, rather
than waiting for a restart.

Session resumption is disabled deliberately, because a resumed TLS 1.3 connection skips the client
certificate message: leaving it on would let a revoked certificate keep authenticating from a cached
ticket.

#### Keeping secrets out of argv and shell history

A secret on the command line is visible to every local user through `ps` and is persisted in shell
history. An environment variable is better but not clean either: it is readable through
`/proc/<pid>/environ`, inherited by every child process, and exposed by `ps e` on some systems.

A file is the only channel here with no ambient exposure and real permissions, so `-session-key-file` and
`-token-file` (both accepting `-` for stdin) are the documented path. In the other direction,
`share` prints its subscriber token only to a terminal; `-token-out <file>` writes it `0600` for
everywhere else.

### Disclaimers

I don't recommend using this to subvert a firewall. I imagine this would be pretty easy to fingerprint (the ALPN is literally `ggrok/3`, and ALPNs are sent in cleartext in TLS 1.3). You also should keep your endpoints secure, as if those are owned, then no amount of channel security will save you.
