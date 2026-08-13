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
