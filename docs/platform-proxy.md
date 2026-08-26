# OpenTDF Platform Reverse Proxy

arks can forward selected HTTP routes to an upstream opentdf-platform instance so
clients can hit a single endpoint for both legacy NanoTDF (handled locally) and
modern ZTDF rewrap (handled by platform).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENTDF_PLATFORM_URL` | — | Upstream base URL, e.g. `https://platform.svc:8443`. Required when `KAS_PROXY_MODE` ≠ `off`, `AUTHZ_PROXY=on`, or `AUTHZEN_FACADE=on`. Loopback is allowed. |
| `KAS_PROXY_MODE` | `off` | One of `off`, `connect`, `rest`, `both`. |
| `AUTHZ_PROXY` | `off` | `on` forwards `/authorization.v2.AuthorizationService/*` to platform. Independent of `KAS_PROXY_MODE` and of `AUTHZEN_FACADE`; requires `OPENTDF_PLATFORM_URL`. |
| `AUTHZEN_FACADE` | `off` | `off` or `on` only. `on` serves AuthZEN 1.0 `/access/v1/evaluation`, `/access/v1/evaluations`, and `GET /.well-known/authzen-configuration`. Independent of `AUTHZ_PROXY`. Requires `OPENTDF_PLATFORM_URL`. There is no built-in evaluator. |
| `OIDC_ISSUER` | `https://identity.arkavo.net` | Service-CWT `iss` pin when the facade is on. |
| `AUTHZEN_COSE_KEYS_URL` | `{OIDC_ISSUER}/.well-known/cose-keys` | COSE_Key Set for PEP service-CWT verify (60s min refresh, 10s fetch). |
| `AUTHZEN_PEP_CLIENT_IDS` | unset | Optional comma-separated OAuth client ids. If set, other service CWTs get HTTP 403. If unset, any valid `service-account` CWT is accepted. |
| `AUTHZEN_PUBLIC_URL` | unset | `policy_decision_point` identifier. If unset, derived from the request `Host` / `X-Forwarded-*`. |
| `AUTHZEN_UPSTREAM_BEARER` | unset | Optional static bearer for facade→OpenTDF (tests / JWT exchange). Default: forward the verified PEP **service CWT**. |

## Modes

- **`off`** — proxy disabled, all routes served locally.
- **`connect`** — `/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`, `/kas.AccessService/LegacyPublicKey` forward to platform.
- **`rest`** — `/kas/v2/rewrap` and `/kas/v2/kas_public_key` forward to platform (replaces the local `http_rewrap` shim).
- **`both`** — `connect` + `rest`.

Whenever the mode is anything other than `off`, `/.well-known/opentdf-configuration` is also forwarded to the upstream platform so clients see the authoritative discovery document, along with public attribute discovery (`GET /attributes`, `GET /attr/*`) served from the platform's policy snapshot — attribute FQNs dereference through this host when the namespace DNS (e.g. patreon.arkavo.com) points here.

`/ws` (custom NanoTDF binary protocol) always stays local; `/media/v1/*` and `/c2pa/v1/*` are always local.

## KAS URL identity caveat

The platform validates that the `kas_url` claim in a rewrap request matches its
`RegisteredKASURI` (see `service/kas/kas.go` in the platform repo). If you run
arks at `https://platform.arkavo.net` but TDFs were minted against
`https://platform.svc`, the URL still points at platform — so direct hits or
proxying both work.

If you want clients to mint TDFs against `platform.arkavo.net` and have arks proxy
them through, you must either:

1. Register `https://platform.arkavo.net` as platform's `RegisteredKASURI`, or
2. Rewrite the `kas_url` field inside the signed rewrap request envelope — not
   currently supported; would require JWT re-signing with a key platform trusts.

## Authorization service forwarding

`AUTHZ_PROXY=on` exposes the platform's authorization.v2 decision endpoints
through this host. PDP delegators — the entitled-catalog endpoint on
iroh.arkavo.net (tdf-iroh-s3#5) — call
`POST /authorization.v2.AuthorizationService/GetDecisionMultiResource` here
with their service credentials; arks only relays, the platform's own authn
governs access and all policy evaluation stays in the platform.

## AuthZEN facade (`AUTHZEN_FACADE`)

Independent of `AUTHZ_PROXY`. When `on`, arks serves AuthZEN 1.0 JSON:

- `POST /access/v1/evaluation` → OpenTDF `GetDecision` (claims-mode entity chain)
- `POST /access/v1/evaluations` → `GetDecisionMultiResource` or `GetDecisionBulk`
- `GET /.well-known/authzen-configuration` (no `search_*` endpoints in v1; no `signed_metadata`)

The PEP authenticates with a **service CWT** (`Authorization: Bearer`). SARC
`subject` is PIP data, not the Bearer. Arkavo CWTs are never sent as
`EntityIdentifier.token`. Upstream timeout is 10s; upstream failure is HTTP 500
(not 502). `/ws` NanoTDF rewrap is unchanged.

When both flags are on, PEPs must pin the AuthZEN well-known URLs and must not
POST to `/authorization.v2.AuthorizationService/*`.

### Caller-credential spike (blocked)

PR 3's entry criterion was to confirm that production `platform.arkavo.net`
accepts a service CWT as the Connect caller credential, and to confirm the
deployed OpenTDF identifier charset.

**Not executed.** Production TLS on `platform.arkavo.net` is expired; this
checkout must not call production. Tests use a mock OpenTDF (wiremock). The
facade **forwards the verified PEP service CWT** as `Authorization: Bearer` to
OpenTDF (the hypothesized production path). If a lab later proves the platform
is JWT-only, set `AUTHZEN_UPSTREAM_BEARER` to a platform-acceptable token (or
implement mint/exchange) — PEPs still send service CWT to the facade. The
identifier charset `^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$` is enforced
on mapped OpenTDF action names and derived attribute values regardless.

## What is NOT proxied

- WebSocket `/ws` (NanoTDF rewrap, contracts, NATS push) — arks-only.
- `/media/v1/*` (TDF3 media DRM, session manager).
- `/c2pa/v1/*` (C2PA signing).
- `/.well-known/apple-app-site-association` (always local; `/.well-known/opentdf-configuration` is forwarded when the proxy is on).

## What's not done

- No JWT re-signing — clients must present credentials platform accepts.
- No request-body rewriting (e.g. `kas_url` rewrite).
- No request streaming — bodies are buffered up to 16 MiB before forwarding.
- Live `platform.arkavo.net` caller-credential spike (TLS expired; see AuthZEN facade).
- AuthZEN Resource Search (`GetEntitlements`) — phase 6.
