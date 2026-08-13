## GGrok

GGrok is a TCP/UDP tunneling tool. It operates at OSI level 4.

Using `ggrok share <-tcp|-udp>`, you may share a local TCP or UDP service through
the tunnel to any number of concurrent `listen` subscribers holding the session's token.
`relay` brokers every session over the public internet without ever terminating TLS. Each
node is mutually authenticated by a private CA you run yourself!

Every connection is TLS 1.3 mTLS against that same CA: control connections and TCP-mode data
connections dial relay directly over TCP+TLS 1.3 (with that hybrid algorithm mentioned earlier).
UDP-mode's data plane is a dedicate QUIC connection per publisher/subscriber, using its unreliable
datagram extension (RFC 9221) rather than QUIC's ordered streams to maintain similar transport semantics
to UDP. Using QUIC comes at a bit of a runtime cost, but it gives us QUIC's congestion control and other goodies that make the connection more robust and stay alive across network changes.

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

Needs both the TCP and UDP flavors of that port reachable from outside - see the firewall note below.

### 4. Share a local TCP or UDP service

```bash
ggrok share -tcp 127.0.0.1:8080 -server relay.example.com:4443
```

Prints a token (unless you pass `-token`, or set `GGROK_TOKEN`) - that's the only thing a `listen`
subscriber needs to reach this session. Once `-server`/`-cert-file`/`-key-file`/`-ca-file` are set in
`~/.ggrok/config.json` (see below) or their `GGROK_*` env var, day-to-day this shrinks to just `ggrok
share -tcp 127.0.0.1:8080`. UDP mode is identical - `-udp` in place of `-tcp`.

### 5. Subscribe from the other side

```bash
ggrok listen -tcp 127.0.0.1:9090 -server relay.example.com:4443 <token>
```

Binds `127.0.0.1:9090` locally; every connection to it is forwarded through relay to whatever `share`
is serving. Swap in `-udp` to match a UDP-mode share. The token can come from `GGROK_TOKEN` instead of
the positional argument, keeping it out of shell history.

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

Relay parses a small routing header on every UDP datagram to know which subscriber's connection
to forward it to/from. We never touch the payload bytes after that header. Relay has no idea what
application-level protocol you are tunneling.

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

#### Tokens never touch argv or shell history

You can use environment variables to accomplish this. I recommend passing in sensitive data as environment variables.

### Disclaimers

I don't recommend using this to subvert a firewall. I imagine this would be pretty easy to fingerprint (the ALPN is literally `ggrok/1`, and ALPNs are sent in cleartext in TLS 1.3). You also should keep your endpoints secure, as if those are owned, then no amount of channel security will save you.
