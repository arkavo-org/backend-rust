# HTTP/3 (QUIC) Support

arks can terminate HTTP/3 in-process, alongside its existing TCP (HTTP/1.1 +
HTTP/2) listener, behind an opt-in `http3` Cargo feature. The implementation
ports the proven in-process `quinn` + `h3` bridge from the identity service
(identity.arkavo.net / authnz-rs).

## What it covers — and what it doesn't

HTTP/3 serves the **request/response surface**: `/kas/v2/kas_public_key`,
`/kas/v2/rewrap`, `/media/v1/*`, the C2PA endpoints, and the `.well-known`
discovery / platform-proxy routes. Each request is driven through the *same*
axum `Router` as the TCP path, so behavior is identical.

The **`/ws` NanoTDF channel is unaffected and stays on TCP/HTTP-1.1.** Classic
WebSockets use the HTTP/1.1 `Upgrade` mechanism, which HTTP/3 does not carry
(that requires Extended CONNECT / RFC 9220, not implemented by the axum +
tokio-tungstenite stack). WebSocket clients simply continue over TCP — no
configuration needed. This is a protocol limitation, not a missing feature.

## Building

```bash
cargo build --release --bin arks --features http3
```

The default build (`cargo build`) does not compile any HTTP/3 code and is
byte-for-byte unchanged.

## Running

HTTP/3 is only spawned when **TLS is enabled** (QUIC requires TLS 1.3). With
`TLS_CERT_PATH` / `TLS_KEY_PATH` set and a binary built with `--features http3`,
arks binds:

- **TCP** `0.0.0.0:$PORT` — HTTP/1.1 + HTTP/2 (unchanged)
- **UDP** `0.0.0.0:$PORT` — HTTP/3 (QUIC), same port number

TCP responses advertise HTTP/3 via `Alt-Svc: h3=":$PORT"; ma=86400`, so
compliant clients upgrade to QUIC on their next connection.

## Deployment requirement: open UDP ingress

HTTP/3 runs over **UDP**, not TCP. The server port must accept UDP in addition
to TCP — update firewalls, security groups, and any load balancer to allow
`udp/$PORT`. Without UDP ingress, the `Alt-Svc` advert points at an unreachable
endpoint and clients fall back to TCP (correct, but you get no H3 benefit).

## Security notes

- **0-RTT (early data) is disabled** (`max_early_data_size = 0`). 0-RTT data is
  replayable by a network attacker (RFC 9001 §9.2, RFC 8470), and the rewrap /
  media key-request endpoints are non-idempotent with no per-request replay
  guard. The only cost is one extra round trip on session resumption.
- The QUIC config reuses the same certificate/key files and the same **ring**
  crypto provider (installed at startup) as the TCP TLS path.
- Request bodies are bounded (2 MiB) before being handed to the router, to avoid
  buffering unbounded memory from an untrusted peer.
- Client IP is preserved: the bridge injects `ConnectInfo(remote_address)` into
  every request, so IP-dependent policy (e.g. media geo-restriction) behaves the
  same over H3 as over TCP.

## Testing

The end-to-end smoke test drives a real QUIC/h3 client through the bridge:

```bash
cargo test --features http3 --bin arks h3_handshake_get_head_and_404
```

It asserts the QUIC handshake negotiates ALPN `h3`, a GET returns its real
status and body, a missing route returns a real 404 (not a stub), and a HEAD
carries `Content-Length` with an empty body.
