## GGrok

Have you ever developed a web service and wanted to share it with someone else, securely and reliably so that only they may access it? This is the problem that `ggrok` solves.

GGrok is a TCP tunneling tool. It operates at OSI level 4.

Using `ggrok share -tcp`, you may share a local TCP service - or a whole contiguous
range of ports - through the tunnel to any number of concurrent `listen` subscribers holding the
session's token.
`relay` terminates each peer's transport TLS connection and forwards a separate end-to-end encrypted stream. Each
node is mutually authenticated by a private CA you run yourself!

Every connection is TLS 1.3 mTLS against that same CA: both the control connection and the data
connections dial relay directly over TCP+TLS 1.3, with a post-quantum hybrid key exchange. On top of
that, the data plane is sealed end-to-end - relay routes a session by an identifier derived from its
token and cannot decrypt a byte of what passes through it.

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

Prints a token (unless you pass `-token`, or set `GGROK_TOKEN`) - that's the only thing a `listen`
subscriber needs to reach this session. Once `-server`/`-cert-file`/`-key-file`/`-ca-file` are set in
`~/.ggrok/config.json` (see below) or their `GGROK_*` env var, day-to-day this shrinks to just `ggrok
share -tcp 127.0.0.1:8080`.

### 5. Subscribe from the other side

```bash
ggrok listen -tcp 127.0.0.1:9090 -server relay.example.com:4443 <token>
```

Binds `127.0.0.1:9090` locally; every connection to it is forwarded through relay to whatever `share`
is serving. The token can come from `GGROK_TOKEN` instead of the positional argument, keeping it out
of shell history.

### Upgrading the wire protocol

This version uses ALPN `ggrok/2`. Upgrade relay, share, and listen together; version 1 peers
cannot connect. The new end-to-end handshake prevents recorded connections or data frames
from being replayed into a fresh tunnel, and authenticates the requested port before share
opens the local service. Tokens and certificates keep their existing format.

Credential issuance now requires fresh output files: existing `cert.pem`, `key.pem`, or
`ca.pem` files (including symlinks) are refused. For rotation, issue into a new directory
that you control, then explicitly switch the node to the new bundle.

Relay permits at most 1024 concurrent sockets, including TLS handshakes, control sockets,
pending data sockets, and both halves of active streams. Excess connections are closed. Share and listen each cap concurrent tunnels at 256;
excess publisher requests time out and excess local listener connections are closed.

### Port ranges

`-tcp` takes `host:first-last` in place of `host:port`, forwarding every port in the
range over the one session:

```bash
ggrok share  -tcp 127.0.0.1:8000-8010            # publisher: 11 local ports
ggrok listen -tcp 127.0.0.1:9000-9010 <token>    # subscriber: 11 local ports
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
ggrok ca crl -out revoked.txt
# copy revoked.txt to wherever relay runs, then restart relay pointed at it:
ggrok relay ... -revoked-file revoked.txt
```

### Features

#### The relay server never parses your traffic

Relay reads exactly one handshake message per connection - a `Hello` or `Attach` naming the session
by its derived `SessionID` - and from then on splices raw bytes between publisher and subscriber
without interpreting any of them. Relay has no idea what application-level protocol you are
tunneling, and per the next section it could not read the payload even if it wanted to.

#### End-to-end encryption, not just hop-by-hop

mTLS secures each leg to relay separately, which would ordinarily make relay a place where plaintext
appears. It isn't. The session token derives the routing `SessionID`. Before forwarding application bytes,
share and listen exchange fresh challenges and HMAC-SHA256 proofs of token possession, binding
both roles and the requested port index. A separate transcript-bound secret derives one
XChaCha20-Poly1305 key per direction for that connection. Relay is handed only the `SessionID`, which
is enough to pair a publisher with its subscribers and nowhere near enough to decrypt a frame - the
data keys are not derivable from it, and relay never holds the token they come from.

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

cert = "you're allowed on my network", token = "you're allowed in *this* tunnel."

#### Certificate revocation

You can revoke a certificate and send it to the server. A subsequent connection will no longer work for
the revoked client.

#### Keeping tokens out of argv and shell history

You can use environment variables to accomplish this. I recommend passing in sensitive data as environment variables.

### Disclaimers

I don't recommend using this to subvert a firewall. I imagine this would be pretty easy to fingerprint (the ALPN is literally `ggrok/2`, and ALPNs are sent in cleartext in TLS 1.3). You also should keep your endpoints secure, as if those are owned, then no amount of channel security will save you.


### Security limits and audit

Anyone with the session token can authenticate as either end of its encrypted streams;
issue a separate token for each trust group. Token-derived encryption does not provide
forward secrecy against later disclosure of that token. A relay can still deny service,
observe traffic sizes and timing, and terminate a TCP stream; applications that need an
authenticated end-of-message must enforce that in their own protocol.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the audit findings and remaining improvements.
