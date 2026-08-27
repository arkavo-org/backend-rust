# Production Hostname Policy

`platform.arkavo.net` is the **only published production name** for arks (KAS +
NanoTDF `/ws` + media DRM). `identity.arkavo.net` remains the separate IdP.

## Decision

**`kas.arkavo.net` and `100.arkavo.net` stay unpublished.** No DNS records, no
certificate SANs, no client configuration. Clients pin and dial
`https://platform.arkavo.net` and `wss://platform.arkavo.net/ws`.

Old NanoTDF headers still carry the `kas.arkavo.net` locator. That is expected
and requires no server-side change: the locator is an identifier, not a dial
target. iOS treats it as "central KAS" and rewraps against
`wss://platform.arkavo.net/ws`. See `ArkavoMessageRouter` in the app repo.

The alternative — keeping the old names as aliases — was **not** taken. It would
require A/CNAME records to `71.179.48.228` *and* a certificate reissue with
`kas.arkavo.net` / `100.arkavo.net` SANs. Today those names are NXDOMAIN and the
certificate carries a single SAN, so any client still dialing them fails at DNS
(and would fail at TLS with `no alternative certificate subject name matches`).

## Verified state (probed 2026-08-26)

| Check | Result |
|-------|--------|
| `platform.arkavo.net` | `71.179.48.228` |
| `identity.arkavo.net` | `71.179.48.230` (separate host, unchanged) |
| `kas.arkavo.net`, `100.arkavo.net` | NXDOMAIN |
| TLS | Let's Encrypt `CN=platform.arkavo.net`, **SAN = `platform.arkavo.net` only**, notAfter 2026-11-24 |
| ALPN | `h2`, `http/1.1` (no `h3` on TCP) |
| `GET /.well-known/opentdf-configuration` | 200 — `kas.uri`, `rewrap_url`, `connect_*_url` all `https://platform.arkavo.net` |
| `GET /kas/v2/kas_public_key` | 200 |
| `POST /kas/v2/rewrap` | 422 on empty body (route live, served locally) |
| `POST /kas.AccessService/Rewrap` | 401 on empty body (route live, proxied to platform) |
| `GET /media/v1/certificate` | 200 |
| `GET /.well-known/apple-app-site-association` | 200 |
| `GET /.well-known/authzen-configuration` | 404 (facade not implemented; see below) |
| `GET /ws` HTTP/1.1 + `Upgrade` | **101 Switching Protocols** |
| `GET /ws` HTTP/2 + `Upgrade` | **400** (expected — see below) |

`RegisteredKASURI` is `https://platform.arkavo.net`. **Do not change it to
`kas.arkavo.net`.**

## `/ws` (NanoTDF) requirements

`/ws` is the ship blocker for the iOS/macOS apps — NanoTDF rewrap runs over it.

- **Path is exactly `/ws`** — not `/`, not `/kas/ws`.
- **`/ws` stays on arks.** `KAS_PROXY_MODE` does not move it; the proxy router
  only ever registers `/kas/v2/rewrap`, `/kas/v2/kas_public_key`,
  `/kas.AccessService/{Rewrap,PublicKey,LegacyPublicKey}`,
  `/authorization.v2.AuthorizationService/*`, `/attributes`, `/attr/*`, and
  `/.well-known/opentdf-configuration`. See `docs/platform-proxy.md`.
- **No reverse proxy is in front of arks.** arks binds `tcp/443` directly and
  terminates TLS itself (`production/start.sh`). There is no intermediary that
  could swallow `Connection` / `Upgrade` / `Sec-WebSocket-*`. If one is ever
  introduced, it must forward those headers verbatim.
- **HTTP/2 cannot carry the upgrade.** arks offers ALPN `h2, http/1.1`; a client
  that negotiates `h2` and sends `Upgrade: websocket` gets `400 Connection header
  did not include 'upgrade'`. **This is correct — do not "fix" it** by enabling
  RFC 8441 extended CONNECT. Native WebSocket clients negotiate `http/1.1`.

### Accept check

```sh
# Must return 101
curl -sS --http1.1 -D - -o /dev/null --max-time 5 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://platform.arkavo.net/ws

# Must return 400 — documents the H2 trap
curl -sS --http2 -D - -o /dev/null --max-time 5 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://platform.arkavo.net/ws
```

### `Alt-Svc: h3` and `/ws`

arks is built with `--features http3` and every TCP response — including the
`/ws` 101 — carries `Alt-Svc: h3=":443"; ma=86400`.

**Suppressing that header on `/ws` would not do what it appears to.** `Alt-Svc`
is **origin-scoped, not path-scoped** (RFC 7838): a client that learns `h3` from
*any* response on this origin (e.g. `/kas/v2/kas_public_key`) may use HTTP/3 for
subsequent requests to the same origin regardless of which response carried the
header. A per-path exclusion would suppress the advert without changing client
behavior, buying false confidence. The guarantee has to come from the client
stack, so it was verified there instead.

**Verified 2026-08-26:** `URLSessionWebSocketTask` — the transport used by
`OpenTDFKit/KASWebSocket.swift` (`URLSession(configuration: .default)` +
`webSocketTask(with:)`) — opens `wss://platform.arkavo.net/ws` successfully with
`Alt-Svc: h3=":443"` live on the origin, across repeated runs. URLSession does
not carry WebSocket tasks over HTTP/2 or HTTP/3; it performs the handshake over
HTTP/1.1. Alt-Svc does not hijack `/ws`.

A `/ws` upgrade attempted over H3 degrades benignly to a 4xx. See
`docs/http3.md`.

## Do not change

- `identity.arkavo.net` — IdP, `cose-keys`, `client_credentials`.
- The NanoTDF `/ws` protocol. No AuthZEN on that path.
- Ohio `3.15.26.24` — decommissioned, do not revive.

## Pending: AuthZEN facade

Not required for the hostname cutover. `AUTHZEN_FACADE` **is not implemented in
this codebase yet** (no references in `src/`; PR #65 is not merged — `main` is at
`e9e3499`). The current `404` on
`/.well-known/authzen-configuration` is therefore expected, not a
misconfiguration.

When #65 lands, enable with:

```sh
AUTHZEN_FACADE=on
OPENTDF_PLATFORM_URL=http://127.0.0.1:8181   # co-located platform on this host
```

Then `GET https://platform.arkavo.net/.well-known/authzen-configuration` should
return JSON with `policy_decision_point = https://platform.arkavo.net`.

The Connect caller credential is a **CWT** (`arkavo-org/opentdf-platform`, not
upstream JWT). PEPs send a service CWT — do not put a JWT mint/exchange in front.
