# OpenTDF Platform Reverse Proxy

arks can forward selected HTTP routes to an upstream opentdf-platform instance so
clients can hit a single endpoint for both legacy NanoTDF (handled locally) and
modern ZTDF rewrap (handled by platform).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENTDF_PLATFORM_URL` | — | Upstream base URL, e.g. `https://platform.svc:8443`. |
| `KAS_PROXY_MODE` | `off` | One of `off`, `connect`, `rest`, `both`. |
| `AUTHZ_PROXY` | `off` | `on` forwards `/authorization.v2.AuthorizationService/*` to platform. Independent of `KAS_PROXY_MODE`; requires `OPENTDF_PLATFORM_URL`. |

## Modes

- **`off`** — proxy disabled, all routes served locally.
- **`connect`** — `/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`, `/kas.AccessService/LegacyPublicKey` forward to platform.
- **`rest`** — `/kas/v2/rewrap` and `/kas/v2/kas_public_key` forward to platform (replaces the local `http_rewrap` shim).
- **`both`** — `connect` + `rest`.

Whenever the mode is anything other than `off`, `/.well-known/opentdf-configuration` is also forwarded to the upstream platform so clients see the authoritative discovery document, along with public attribute discovery (`GET /attributes`, `GET /attr/*`) served from the platform's policy snapshot — attribute FQNs dereference through this host when the namespace DNS (e.g. patreon.arkavo.com) points here.

`/ws` (custom NanoTDF binary protocol) always stays local; `/media/v1/*` and `/c2pa/v1/*` are always local.

## KAS URL identity caveat

The platform validates that the `kas_url` claim in a rewrap request matches its
`RegisteredKASURI` (see `service/kas/kas.go` in the platform repo). That claim
sits inside the signed rewrap envelope, so arks cannot rewrite it while
proxying — rewriting would require re-signing with a key the platform trusts,
which is not supported.

In production this is already consistent and needs no action: arks serves
`https://platform.arkavo.net`, and the co-located platform registers
`registered_kas_uri: https://platform.arkavo.net`. Clients mint against the
same name they dial.

The caveat matters only if the two ever diverge. If you point arks at an
upstream whose `RegisteredKASURI` is a different name (say `https://platform.svc`),
then TDFs must be minted against **that** name, not against the arks hostname —
otherwise the platform rejects the rewrap. Keep `registered_kas_uri` and the
public arks hostname equal unless you have a specific reason not to.

Note the value is the bare origin — `https://platform.arkavo.net`, with no
`/kas` path. A TDF minted with `.../kas` in `keyAccess[].url` carries a
`kas_url` that is not string-equal to the registered value and is denied.

See `docs/hostname-policy.md` for why `platform.arkavo.net` is the only
published production name.

## Authorization service forwarding

`AUTHZ_PROXY=on` exposes the platform's authorization.v2 decision endpoints
through this host. PDP delegators — the entitled-catalog endpoint on
iroh.arkavo.net (tdf-iroh-s3#5) — call
`POST /authorization.v2.AuthorizationService/GetDecisionMultiResource` here
with their service credentials; arks only relays, the platform's own authn
governs access and all policy evaluation stays in the platform.

## What is NOT proxied

- WebSocket `/ws` (NanoTDF rewrap, contracts, NATS push) — arks-only.
- `/media/v1/*` (TDF3 media DRM, session manager).
- `/c2pa/v1/*` (C2PA signing).
- `/.well-known/apple-app-site-association` (always local; `/.well-known/opentdf-configuration` is forwarded when the proxy is on).

## What's not done

- No JWT re-signing — clients must present credentials platform accepts.
- No request-body rewriting (e.g. `kas_url` rewrite).
- No request streaming — bodies are buffered up to 16 MiB before forwarding.
