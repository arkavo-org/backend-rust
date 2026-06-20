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

The default build (`cargo build`) compiles **no** HTTP/3 / QUIC code — that is
all behind the `http3` feature. The one behavior change that *does* ship in every
build is ALPN: the TLS listener now advertises `h2` + `http/1.1` (see
"Protocol negotiation" below). This is independent of the `http3` feature.

## Running

HTTP/3 is only spawned when **TLS is enabled** (QUIC requires TLS 1.3). With
`TLS_CERT_PATH` / `TLS_KEY_PATH` set and a binary built with `--features http3`,
arks binds:

- **TCP** `0.0.0.0:$PORT` — HTTP/1.1 + HTTP/2 (unchanged)
- **UDP** `0.0.0.0:$PORT` — HTTP/3 (QUIC), same port number

TCP responses advertise HTTP/3 via `Alt-Svc: h3=":$PORT"; ma=86400`, so
compliant clients upgrade to QUIC on their next connection.

## One port, not two

TCP and UDP are independent transports that share the **same port number**, so
this is a single standard HTTPS port — `$PORT` is opened for *both* TCP and UDP.
There is no separate H3 port.

You cannot run "HTTP/3 only" and drop TCP, by design:

- **H3 has no cold-start discovery.** A fresh client learns the server speaks
  H3 only via the `Alt-Svc` header (read over an *initial TCP* connection, then
  upgraded to QUIC) or via a **DNS HTTPS/SVCB record** with `alpn="h3"`
  (DNS-side, optional, no code change) that lets a client attempt QUIC first.
- **TCP is the mandatory fallback** for clients/networks that block UDP/QUIC.
- **`/ws` only exists on TCP** (WebSocket cannot ride H3 — see above).

Steady state: one HTTPS port; H3 carries all REST/discovery traffic once clients
upgrade; TCP remains for bootstrap, fallback, and `/ws`.

## Protocol negotiation (ALPN)

The TLS listener advertises ALPN `h2`, `http/1.1` (in **all** builds, not just
`http3`). REST clients negotiate HTTP/2; the `/ws` WebSocket upgrade negotiates
`http/1.1`.

> **Validate before relying on this in production:** offering `h2` first means a
> client whose ALPN list includes `h2` may be steered onto HTTP/2, and the `/ws`
> HTTP/1.1 `Upgrade` cannot run over h2 (no RFC 9220 extended CONNECT in this
> stack). Native WebSocket clients (e.g. iOS OpenTDFKit) negotiate `http/1.1`
> and are unaffected; confirm any **browser** WebSocket clients still connect.

## Routing scope

H3 serves the **same full router** as TCP — no allow-list. Requests that don't
fit H3 degrade benignly: a `/ws` upgrade over H3 returns a normal 4xx, and
gRPC-with-trailers is not relayed (the bridge forwards data frames only), so
gRPC/ConnectRPC streaming stays on TCP. Connect-protocol unary calls work over
H3 because their status travels in headers, not trailers.

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
