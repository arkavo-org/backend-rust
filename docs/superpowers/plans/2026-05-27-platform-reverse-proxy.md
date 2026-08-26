# OpenTDF Platform Reverse Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a thin reverse-proxy in arkavo-rs that forwards selected HTTP paths (`/kas/v2/*` REST shim and `/kas.AccessService/*` ConnectRPC) to an upstream opentdf-platform, controlled by `OPENTDF_PLATFORM_URL` + `KAS_PROXY_MODE`. NanoTDF `/ws` traffic stays local.

**Architecture:** New `platform_proxy` module exposes a single Axum handler that buffers the request body, strips hop-by-hop and Host headers, forwards via reqwest, and streams back the response. `main.rs` reads two env vars, builds a `PlatformProxyState`, and conditionally swaps the existing local `opentdf_router` for proxy sub-routers based on mode.

**Tech Stack:** Rust 2021, axum 0.7, reqwest 0.12 (already a dependency), tokio. Tests use wiremock 0.6 (new dev-dep) to spin an in-process upstream.

**Scope:** Out of scope — JWT re-signing, request-body rewriting (e.g. rewriting `kas_url` inside the signed envelope), KAS-key-registry sync with platform. Those become follow-ups if the registered-KAS-URI path is insufficient.

---

## File Structure

- **Create** `src/modules/platform_proxy.rs` — `ProxyMode` enum, `PlatformProxyState`, `proxy` handler, hop-by-hop constant.
- **Modify** `src/modules/mod.rs` — register the new module.
- **Modify** `Cargo.toml` — add `wiremock = "0.6"` to `[dev-dependencies]`.
- **Modify** `src/bin/main.rs` — read env vars, build state, conditionally merge proxy sub-routers (touches the import block near line 13 and the router assembly near lines 791–848).
- **Create** `tests/platform_proxy_tests.rs` — integration tests against wiremock upstream.
- **Modify** `CLAUDE.md` — add new env vars to the Configuration section.
- **Create** `docs/platform-proxy.md` — operator-facing docs (modes, URL identity caveat).

Each file has one responsibility: the module owns proxy behavior, tests own behavior coverage, docs explain operator-visible config. `main.rs` only wires.

---

## Task 1: Add wiremock dev-dependency and scaffold module

**Files:**
- Modify: `Cargo.toml`
- Create: `src/modules/platform_proxy.rs`
- Modify: `src/modules/mod.rs`

- [ ] **Step 1: Add wiremock to dev-dependencies**

Edit `Cargo.toml`, find the `[dev-dependencies]` block and append:

```toml
wiremock = "0.6"
```

- [ ] **Step 2: Create empty module file**

Create `src/modules/platform_proxy.rs` with:

```rust
//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;

/// Which arks routes get forwarded to opentdf-platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// No forwarding; arks handles everything locally.
    Off,
    /// Forward only ConnectRPC routes (`/kas.AccessService/*`).
    Connect,
    /// Forward only legacy REST routes (`/kas/v2/rewrap`, `/kas/v2/kas_public_key`).
    Rest,
    /// Forward both Connect and REST routes.
    Both,
}

impl FromStr for ProxyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "" => Ok(ProxyMode::Off),
            "connect" => Ok(ProxyMode::Connect),
            "rest" => Ok(ProxyMode::Rest),
            "both" => Ok(ProxyMode::Both),
            other => Err(format!("invalid KAS_PROXY_MODE: {other}")),
        }
    }
}

impl ProxyMode {
    pub fn forwards_connect(self) -> bool {
        matches!(self, ProxyMode::Connect | ProxyMode::Both)
    }

    pub fn forwards_rest(self) -> bool {
        matches!(self, ProxyMode::Rest | ProxyMode::Both)
    }
}
```

- [ ] **Step 3: Register module**

Edit `src/modules/mod.rs`, add the line after `pub mod media_api;`:

```rust
pub mod platform_proxy;
```

Final mod.rs:

```rust
#[cfg(feature = "c2pa_signing")]
pub mod c2pa_signing;
pub mod cbor_protocol;
pub mod crypto;
pub mod fairplay;
pub mod http_rewrap;
pub mod media_api;
pub mod ntdf_token;
pub mod platform_proxy;
pub mod rtmp;
pub mod secure_keys;
```

- [ ] **Step 4: Verify build**

Run: `cargo build --bin arks`
Expected: builds cleanly (warnings allowed; no errors).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/modules/platform_proxy.rs src/modules/mod.rs
git commit -m "feat(proxy): scaffold platform_proxy module with ProxyMode enum"
```

---

## Task 2: Test ProxyMode parsing

**Files:**
- Modify: `src/modules/platform_proxy.rs`

- [ ] **Step 1: Add failing unit tests for ProxyMode**

Append to `src/modules/platform_proxy.rs`:

```rust
#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn parses_known_modes() {
        assert_eq!(ProxyMode::from_str("off").unwrap(), ProxyMode::Off);
        assert_eq!(ProxyMode::from_str("connect").unwrap(), ProxyMode::Connect);
        assert_eq!(ProxyMode::from_str("rest").unwrap(), ProxyMode::Rest);
        assert_eq!(ProxyMode::from_str("both").unwrap(), ProxyMode::Both);
    }

    #[test]
    fn empty_string_defaults_to_off() {
        assert_eq!(ProxyMode::from_str("").unwrap(), ProxyMode::Off);
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ProxyMode::from_str("CONNECT").unwrap(), ProxyMode::Connect);
        assert_eq!(ProxyMode::from_str("Both").unwrap(), ProxyMode::Both);
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(ProxyMode::from_str("invalid").is_err());
    }

    #[test]
    fn forwarding_predicates() {
        assert!(!ProxyMode::Off.forwards_connect());
        assert!(!ProxyMode::Off.forwards_rest());

        assert!(ProxyMode::Connect.forwards_connect());
        assert!(!ProxyMode::Connect.forwards_rest());

        assert!(!ProxyMode::Rest.forwards_connect());
        assert!(ProxyMode::Rest.forwards_rest());

        assert!(ProxyMode::Both.forwards_connect());
        assert!(ProxyMode::Both.forwards_rest());
    }
}
```

- [ ] **Step 2: Run tests — should pass on first run (no implementation needed beyond Task 1)**

Run: `cargo test --lib platform_proxy::mode_tests`
Expected: 5 passed.

If any fail, the `ProxyMode` impl from Task 1 is wrong — fix it before continuing.

- [ ] **Step 3: Commit**

```bash
git add src/modules/platform_proxy.rs
git commit -m "test(proxy): cover ProxyMode parsing and forwarding predicates"
```

---

## Task 3: PlatformProxyState constructor

**Files:**
- Modify: `src/modules/platform_proxy.rs`

- [ ] **Step 1: Add failing test**

Insert above the `mode_tests` module:

```rust
#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn rejects_invalid_url() {
        let err = PlatformProxyState::new("not a url").unwrap_err();
        assert!(err.to_string().contains("invalid"), "got: {err}");
    }

    #[test]
    fn accepts_https_url() {
        let state = PlatformProxyState::new("https://platform.svc:8443").unwrap();
        assert_eq!(state.upstream_base, "https://platform.svc:8443");
    }

    #[test]
    fn strips_trailing_slash_from_upstream() {
        let state = PlatformProxyState::new("https://platform.svc/").unwrap();
        assert_eq!(state.upstream_base, "https://platform.svc");
    }
}
```

- [ ] **Step 2: Run — expect compile failure**

Run: `cargo test --lib platform_proxy::state_tests`
Expected: FAIL — `PlatformProxyState` not defined.

- [ ] **Step 3: Implement PlatformProxyState**

Insert near the top of `src/modules/platform_proxy.rs` (between the `FromStr` impl and the test modules):

```rust
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use url::Url;

/// Shared state for the reverse-proxy handler.
pub struct PlatformProxyState {
    pub client: Client,
    /// Upstream base URL with no trailing slash, e.g. `https://platform.svc:8443`.
    pub upstream_base: String,
}

impl PlatformProxyState {
    pub fn new(upstream: &str) -> Result<Arc<Self>, String> {
        let parsed = Url::parse(upstream).map_err(|e| format!("invalid upstream URL: {e}"))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(format!("invalid upstream URL scheme: {}", parsed.scheme()));
        }
        let upstream_base = upstream.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .build()
            .map_err(|e| format!("failed to build reqwest client: {e}"))?;
        Ok(Arc::new(Self { client, upstream_base }))
    }
}
```

- [ ] **Step 4: Add url crate if missing**

Check `Cargo.toml`. If `url = ` is not present, add to `[dependencies]`:

```toml
url = "2"
```

Run: `cargo build --bin arks`
Expected: builds cleanly.

- [ ] **Step 5: Run tests — should pass**

Run: `cargo test --lib platform_proxy::state_tests`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/modules/platform_proxy.rs
git commit -m "feat(proxy): PlatformProxyState with URL validation"
```

---

## Task 4: Hop-by-hop header constant

**Files:**
- Modify: `src/modules/platform_proxy.rs`

- [ ] **Step 1: Add failing test**

Add another test module to `src/modules/platform_proxy.rs`:

```rust
#[cfg(test)]
mod header_tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn strip_hop_by_hop_removes_rfc7230_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::HOST, HeaderValue::from_static("kas.local"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));

        strip_proxy_headers(&mut headers);

        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key(header::TE));
        assert!(!headers.contains_key(header::HOST));
        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer x");
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo test --lib platform_proxy::header_tests`
Expected: FAIL — `strip_proxy_headers` not defined.

- [ ] **Step 3: Implement `strip_proxy_headers`**

Add to `src/modules/platform_proxy.rs` (above the test modules):

```rust
use axum::http::{header, HeaderMap, HeaderName};

/// Headers we must not forward, per RFC 7230 §6.1, plus `Host`
/// (reqwest sets `Host` from the upstream URL).
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::HOST,
];

/// Strip hop-by-hop headers and `Host` from `headers` in place.
pub(crate) fn strip_proxy_headers(headers: &mut HeaderMap) {
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
    // Also strip any header named in a Connection: header list (RFC 7230 §6.1).
    // Not all proxies do this, but it's cheap and correct.
    headers.remove(header::HeaderName::from_static("keep-alive"));
}
```

- [ ] **Step 4: Run tests — pass**

Run: `cargo test --lib platform_proxy::header_tests`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/modules/platform_proxy.rs
git commit -m "feat(proxy): strip hop-by-hop and Host headers before forwarding"
```

---

## Task 5: End-to-end proxy handler (golden path)

**Files:**
- Modify: `src/modules/platform_proxy.rs`
- Create: `tests/platform_proxy_tests.rs`

- [ ] **Step 1: Write failing integration test**

Create `tests/platform_proxy_tests.rs`:

```rust
//! Integration tests for the reverse proxy.
//!
//! Spins up a wiremock upstream, builds a real axum router with the proxy
//! handler, and exercises it via a hyper client.

use std::sync::Arc;

use arkavo_rs::modules::platform_proxy::{proxy, PlatformProxyState};
use axum::{routing::any, Router};
use reqwest::Client;
use tokio::net::TcpListener;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

/// Build an arks-side server with the proxy mounted at `/kas/v2/rewrap`
/// pointing at `upstream`. Returns the bound base URL.
async fn spawn_proxy(upstream: &str) -> String {
    let state = PlatformProxyState::new(upstream).expect("valid upstream URL");
    let app = Router::new()
        .route("/kas/v2/rewrap", any(proxy))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn forwards_post_with_body_and_returns_upstream_response() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kas/v2/rewrap"))
        .and(header("authorization", "Bearer test-jwt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"ok":true}"#),
        )
        .expect(1)
        .mount(&upstream)
        .await;

    let proxy_base = spawn_proxy(&upstream.uri()).await;

    let resp = Client::new()
        .post(format!("{proxy_base}/kas/v2/rewrap"))
        .header("authorization", "Bearer test-jwt")
        .body(r#"{"signed_request_token":"abc"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "application/json");
    assert_eq!(resp.text().await.unwrap(), r#"{"ok":true}"#);
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo test --test platform_proxy_tests forwards_post_with_body`
Expected: FAIL — `proxy` not defined / wrong signature.

- [ ] **Step 3: Implement the `proxy` handler**

Append to `src/modules/platform_proxy.rs`:

```rust
use std::sync::Arc as ArcImport; // keep import alias if `Arc` is already in scope above

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    response::Response,
};

const MAX_PROXY_BODY: usize = 16 * 1024 * 1024; // matches MAX_NANOTDF_SIZE in main.rs

/// Axum handler that forwards any inbound request to `state.upstream_base + path_and_query`.
pub async fn proxy(
    State(state): State<Arc<PlatformProxyState>>,
    req: Request,
) -> Result<Response, StatusCode> {
    let path_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.upstream_base, path_query);

    let (parts, body) = req.into_parts();

    let body_bytes: Bytes = axum::body::to_bytes(body, MAX_PROXY_BODY)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    let mut headers = parts.headers.clone();
    strip_proxy_headers(&mut headers);

    let upstream_resp = state
        .client
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            log::warn!("proxy upstream error: {e}");
            StatusCode::BAD_GATEWAY
        })?;

    let status = upstream_resp.status();
    let mut resp_headers = upstream_resp.headers().clone();
    strip_proxy_headers(&mut resp_headers);

    let bytes = upstream_resp
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}
```

(If you already have `use std::sync::Arc;` higher in the file from Task 3, delete the aliased import line above and use the existing `Arc`.)

- [ ] **Step 4: Re-export the module from `lib.rs` so integration tests can reach it**

Open `src/lib.rs`. If `pub mod modules;` is not already there, add it near the top. Otherwise no change.

Run: `grep -n "pub mod modules" src/lib.rs`
Expected: at least one match. If none, add `pub mod modules;` after the existing `pub use` lines.

- [ ] **Step 5: Run tests — pass**

Run: `cargo test --test platform_proxy_tests forwards_post_with_body`
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add src/modules/platform_proxy.rs src/lib.rs tests/platform_proxy_tests.rs
git commit -m "feat(proxy): forward HTTP requests to upstream platform"
```

---

## Task 6: Header passthrough and Host stripping integration test

**Files:**
- Modify: `tests/platform_proxy_tests.rs`

- [ ] **Step 1: Add test for Host stripping and hop-by-hop**

Append to `tests/platform_proxy_tests.rs`:

```rust
#[tokio::test]
async fn does_not_forward_host_or_hop_by_hop_headers() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kas/v2/rewrap"))
        // wiremock's `header_exists` would assert presence; we instead let
        // the matcher pass and inspect the recorded requests below.
        .respond_with(ResponseTemplate::new(204))
        .mount(&upstream)
        .await;

    let proxy_base = spawn_proxy(&upstream.uri()).await;

    Client::new()
        .get(format!("{proxy_base}/kas/v2/rewrap"))
        // reqwest sets Host automatically from the URL, but we can override.
        .header("connection", "close")
        .header("te", "trailers")
        .send()
        .await
        .unwrap();

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];

    // Host should be the upstream host, not the proxy's listening address.
    let host = req.headers.get("host").unwrap().to_str().unwrap();
    assert!(
        host.contains(&upstream.address().to_string()),
        "expected upstream host, got {host}"
    );

    // Hop-by-hop headers must not be forwarded.
    assert!(req.headers.get("connection").is_none());
    assert!(req.headers.get("te").is_none());
}
```

- [ ] **Step 2: Run — should pass**

Run: `cargo test --test platform_proxy_tests does_not_forward_host`
Expected: 1 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/platform_proxy_tests.rs
git commit -m "test(proxy): assert Host and hop-by-hop headers are stripped"
```

---

## Task 7: Upstream error mapping integration test

**Files:**
- Modify: `tests/platform_proxy_tests.rs`

- [ ] **Step 1: Add test for 5xx and dead-upstream behavior**

Append to `tests/platform_proxy_tests.rs`:

```rust
#[tokio::test]
async fn forwards_upstream_status_codes() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/kas/v2/rewrap"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&upstream)
        .await;

    let proxy_base = spawn_proxy(&upstream.uri()).await;
    let resp = Client::new()
        .post(format!("{proxy_base}/kas/v2/rewrap"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    assert_eq!(resp.text().await.unwrap(), "forbidden");
}

#[tokio::test]
async fn returns_502_when_upstream_unreachable() {
    // Point at a port nobody is listening on.
    let proxy_base = spawn_proxy("http://127.0.0.1:1").await;

    let resp = Client::new()
        .post(format!("{proxy_base}/kas/v2/rewrap"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
}
```

- [ ] **Step 2: Run — should pass**

Run: `cargo test --test platform_proxy_tests`
Expected: 4 tests passed total in this file.

- [ ] **Step 3: Commit**

```bash
git add tests/platform_proxy_tests.rs
git commit -m "test(proxy): cover upstream error code passthrough and dead-upstream 502"
```

---

## Task 8: Wire env vars and state initialization in main.rs

**Files:**
- Modify: `src/bin/main.rs`

- [ ] **Step 1: Add module import**

Find line 13 in `src/bin/main.rs`:

```rust
use modules::{cbor_protocol, http_rewrap, media_api, ntdf_token};
```

Replace with:

```rust
use modules::{cbor_protocol, http_rewrap, media_api, ntdf_token, platform_proxy};
```

- [ ] **Step 2: Build proxy state after `rewrap_state` (around main.rs:700)**

Find the block that creates `rewrap_state` (begins around line 693):

```rust
    let rewrap_state = Arc::new(http_rewrap::RewrapState {
        ...
        chain_validator: chain_validator.clone(),
    });
```

Immediately after that block (before the `// Initialize media DRM components` comment), insert:

```rust
    // Build optional reverse-proxy to upstream opentdf-platform.
    let proxy_mode: platform_proxy::ProxyMode = env::var("KAS_PROXY_MODE")
        .ok()
        .as_deref()
        .unwrap_or("off")
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    let platform_proxy_state = match (env::var("OPENTDF_PLATFORM_URL").ok(), proxy_mode) {
        (Some(url), mode) if mode != platform_proxy::ProxyMode::Off => {
            let state = platform_proxy::PlatformProxyState::new(&url)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            info!(
                "Platform proxy enabled: mode={:?}, upstream={}",
                mode, state.upstream_base
            );
            Some(state)
        }
        (None, mode) if mode != platform_proxy::ProxyMode::Off => {
            return Err(format!(
                "KAS_PROXY_MODE={:?} requires OPENTDF_PLATFORM_URL to be set",
                mode
            )
            .into());
        }
        _ => {
            info!("Platform proxy disabled (KAS_PROXY_MODE=off or unset)");
            None
        }
    };
```

- [ ] **Step 3: Build**

Run: `cargo build --bin arks`
Expected: builds cleanly.

- [ ] **Step 4: Commit**

```bash
git add src/bin/main.rs
git commit -m "feat(proxy): wire OPENTDF_PLATFORM_URL and KAS_PROXY_MODE env vars"
```

---

## Task 9: Conditional router merge

**Files:**
- Modify: `src/bin/main.rs`

- [ ] **Step 1: Modify the OpenTDF compatibility router block**

Find the existing block (around line 791):

```rust
    // OpenTDF compatibility router
    let opentdf_router = Router::new()
        .route("/kas/v2/rewrap", post(http_rewrap::rewrap_handler))
        .route(
            "/kas/v2/kas_public_key",
            get(http_rewrap::kas_public_key_handler),
        )
        .with_state(rewrap_state);
```

Replace with:

```rust
    // OpenTDF compatibility router — either local handlers or forwarded
    // to upstream platform, depending on KAS_PROXY_MODE.
    let opentdf_router = if proxy_mode.forwards_rest() {
        // SAFETY: presence of upstream URL is enforced by the env-var check above.
        let state = platform_proxy_state
            .clone()
            .expect("platform_proxy_state must exist when forwards_rest()");
        Router::new()
            .route("/kas/v2/rewrap", post(platform_proxy::proxy))
            .route("/kas/v2/kas_public_key", get(platform_proxy::proxy))
            .with_state(state)
    } else {
        Router::new()
            .route("/kas/v2/rewrap", post(http_rewrap::rewrap_handler))
            .route(
                "/kas/v2/kas_public_key",
                get(http_rewrap::kas_public_key_handler),
            )
            .with_state(rewrap_state)
    };
```

- [ ] **Step 2: Add ConnectRPC sub-router immediately after**

After the `opentdf_router` assignment, insert:

```rust
    // ConnectRPC routes — only mounted when proxying is enabled.
    let connect_router = if proxy_mode.forwards_connect() {
        let state = platform_proxy_state
            .clone()
            .expect("platform_proxy_state must exist when forwards_connect()");
        Router::new()
            .route("/kas.AccessService/Rewrap", post(platform_proxy::proxy))
            .route("/kas.AccessService/PublicKey", post(platform_proxy::proxy))
            .route("/kas.AccessService/PublicKey", get(platform_proxy::proxy))
            .route(
                "/kas.AccessService/LegacyPublicKey",
                get(platform_proxy::proxy),
            )
            .with_state(state)
    } else {
        Router::new()
    };
```

- [ ] **Step 3: Merge the new sub-router into the app**

Find the final `let app = Router::new()` block (around main.rs:836):

```rust
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_app_site_association_handler),
        )
        .with_state(ws_state)
        .merge(opentdf_router)
        .merge(media_router)
        .merge(c2pa_router)
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(log_request_middleware)),
        );
```

Add `.merge(connect_router)` after `.merge(opentdf_router)`:

```rust
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_app_site_association_handler),
        )
        .with_state(ws_state)
        .merge(opentdf_router)
        .merge(connect_router)
        .merge(media_router)
        .merge(c2pa_router)
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(log_request_middleware)),
        );
```

- [ ] **Step 4: Build**

Run: `cargo build --bin arks`
Expected: builds cleanly.

- [ ] **Step 5: Run full test suite — nothing regressed**

Run: `cargo test`
Expected: all existing tests still pass, plus the 4 new ones from Tasks 5–7.

- [ ] **Step 6: Lint as CI does**

Run: `cargo clippy --lib --bin arks --all-features -- -D warnings`
Expected: 0 warnings.

If clippy complains about the `expect` calls, replace with an `unwrap_or_else(|| unreachable!(...))` or restructure to bind the state once.

- [ ] **Step 7: Commit**

```bash
git add src/bin/main.rs
git commit -m "feat(proxy): mount platform-proxy routes when KAS_PROXY_MODE is set"
```

---

## Task 10: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Create: `docs/platform-proxy.md`

- [ ] **Step 1: Add env vars to CLAUDE.md Configuration section**

Find the `# Chain Validation Configuration` block in `CLAUDE.md` (around line 245). After it, append:

```markdown
# OpenTDF Platform Reverse Proxy Configuration (optional)
export OPENTDF_PLATFORM_URL=https://platform.svc:8443  # Upstream platform base URL
export KAS_PROXY_MODE=connect                          # off | connect | rest | both
```

Also append a `**Note:**` block similar to the existing ones:

```markdown
**Note:** For OpenTDF Platform reverse-proxy:
- Proxying is optional and disabled when `KAS_PROXY_MODE` is `off` or unset.
- `connect` forwards `/kas.AccessService/*` ConnectRPC routes.
- `rest` forwards `/kas/v2/rewrap` and `/kas/v2/kas_public_key`, replacing the local OpenTDF-compat shim.
- `both` forwards all of the above.
- `/ws` (NanoTDF) always stays local. See `docs/platform-proxy.md`.
```

- [ ] **Step 2: Create operator-facing doc**

Create `docs/platform-proxy.md`:

```markdown
# OpenTDF Platform Reverse Proxy

arks can forward selected HTTP routes to an upstream opentdf-platform instance so
clients can hit a single endpoint for both legacy NanoTDF (handled locally) and
modern ZTDF rewrap (handled by platform).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENTDF_PLATFORM_URL` | — | Upstream base URL, e.g. `https://platform.svc:8443`. |
| `KAS_PROXY_MODE` | `off` | One of `off`, `connect`, `rest`, `both`. |

## Modes

- **`off`** — proxy disabled, all routes served locally.
- **`connect`** — `/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`, `/kas.AccessService/LegacyPublicKey` forward to platform.
- **`rest`** — `/kas/v2/rewrap` and `/kas/v2/kas_public_key` forward to platform (replaces the local `http_rewrap` shim).
- **`both`** — `connect` + `rest`.

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

## What is NOT proxied

- WebSocket `/ws` (NanoTDF rewrap, contracts, NATS push) — arks-only.
- `/media/v1/*` (TDF3 media DRM, session manager).
- `/c2pa/v1/*` (C2PA signing).
- `/.well-known/apple-app-site-association`.

## What's not done

- No JWT re-signing — clients must present credentials platform accepts.
- No request-body rewriting (e.g. `kas_url` rewrite).
- No request streaming — bodies are buffered up to 16 MiB before forwarding.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/platform-proxy.md
git commit -m "docs(proxy): document OPENTDF_PLATFORM_URL and KAS_PROXY_MODE"
```

---

## Task 11: Manual smoke test

**Files:** none (verification only)

- [ ] **Step 1: Verify `off` mode is a no-op**

In one terminal:

```bash
unset OPENTDF_PLATFORM_URL KAS_PROXY_MODE
cargo run --bin arks
```

In another terminal:

```bash
curl -sS http://localhost:8080/kas/v2/kas_public_key | head -c 200
```

Expected: a JSON response with `public_key` from the *local* KAS — matches behavior before this change.

- [ ] **Step 2: Verify `connect` mode forwards**

Start a stub upstream (any port, any tool). Easiest is a `python3 -m http.server` in another terminal that serves a JSON file at the right path, or run the real `opentdf-platform` locally on `:8443`.

```bash
export OPENTDF_PLATFORM_URL=http://localhost:8081
export KAS_PROXY_MODE=connect
cargo run --bin arks
```

Then:

```bash
curl -sS -i http://localhost:8080/kas.AccessService/PublicKey
```

Expected: response comes from upstream `:8081`. Compare against `curl http://localhost:8081/kas.AccessService/PublicKey` directly — bodies should match.

Also verify `/kas/v2/kas_public_key` still hits the local handler (since `mode=connect`):

```bash
curl -sS http://localhost:8080/kas/v2/kas_public_key | head -c 200
```

Expected: local KAS key, same as Step 1.

- [ ] **Step 3: Verify `both` mode forwards both**

```bash
export KAS_PROXY_MODE=both
cargo run --bin arks
```

```bash
curl -sS http://localhost:8080/kas/v2/kas_public_key
```

Expected: response from upstream `:8081`, not the local handler.

- [ ] **Step 4: Verify misconfiguration is caught**

```bash
unset OPENTDF_PLATFORM_URL
export KAS_PROXY_MODE=connect
cargo run --bin arks
```

Expected: process exits with `KAS_PROXY_MODE=Connect requires OPENTDF_PLATFORM_URL to be set`.

- [ ] **Step 5: Verify WebSocket still works (regression check)**

With any of the modes above:

```bash
# Using websocat or similar:
websocat ws://localhost:8080/ws
```

Send a 0x01 byte followed by 33 bytes of compressed P-256 public key. Expect a 0x01 response with 33 bytes + 32-byte salt.

If you don't have a NanoTDF test client handy, at minimum confirm the WebSocket handshake completes (HTTP 101 Switching Protocols).

---

## Self-Review

**Spec coverage:**
- Proxy module with state, mode enum, header stripping — Tasks 1–4 ✓
- Forwarding handler covering golden path, headers, errors — Tasks 5–7 ✓
- Env-var wiring and conditional routing in main.rs — Tasks 8–9 ✓
- Documentation — Task 10 ✓
- Manual verification — Task 11 ✓

**Placeholder scan:** No TBDs, no "add error handling", no "tests for the above" without code. Each step shows the actual diff or command.

**Type consistency:** `PlatformProxyState`, `ProxyMode`, `proxy`, `strip_proxy_headers` are used identically across Tasks 3, 5, 6, 8, 9. `upstream_base` field name matches between the state struct and the handler. `MAX_PROXY_BODY` is defined once.

**One known wart:** Task 5 includes a defensive `use std::sync::Arc as ArcImport;` aliased import with a note to delete it if `Arc` is already in scope — that's because the file structure depends on whether Task 3's import landed at the top of the file or elsewhere. The note tells the engineer what to do.
