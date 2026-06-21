# HTTP/3 (QUIC) Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the arkavo-rs HTTP REST/discovery surface over HTTP/3 (QUIC) in-process, alongside the existing TCP (HTTP/1.1 + HTTP/2) listener, behind an opt-in `http3` Cargo feature.

**Architecture:** Port the proven in-process `quinn` + `h3` bridge from the sibling `authnz-rs` service (identity.arkavo.net). A `quinn` UDP listener terminates QUIC, the `h3` crate frames requests, and each request is driven through the *same* axum `Router` via `tower`'s `.oneshot()`. The TCP path advertises H3 via `Alt-Svc`. The `/ws` NanoTDF channel is unaffected — classic WebSockets cannot ride HTTP/3, so WS clients continue over TCP/HTTP-1.1 automatically.

**Tech Stack:** Rust, axum 0.7, hyper 1 / hyper-util, tokio-rustls 0.26, rustls 0.23 (ring provider), quinn 0.11, h3 0.0.8, h3-quinn 0.0.10.

## Global Constraints

- **Feature-gated:** all H3 code is behind `#[cfg(feature = "http3")]`; `default = []` build is byte-for-byte unchanged.
- **Crypto provider:** arkavo-rs installs the **ring** provider at `src/bin/main.rs:564` (`rustls::crypto::ring::default_provider().install_default()`). quinn shares this process-default; do not add `aws-lc-rs`.
- **0-RTT disabled:** `max_early_data_size = 0` on the QUIC rustls config. `/kas/v2/rewrap` and `/media/v1/key-request` are non-idempotent and replay-sensitive (RFC 9001 §9.2, RFC 8470).
- **Never modify `vendor/fpssdk/`.** Format only with `cargo fmt --package arkavo-rs --package fairplay-wrapper`.
- **CI gate:** `cargo clippy --lib --bin arks --all-features -- -D warnings` must pass (note: `--all-features` compiles the H3 path).
- **Mirror authnz-rs versions exactly:** h3 = "0.0.8", h3-quinn = "0.0.10", quinn = "0.11", http-body = "1". These are proven in production.
- **ConnectInfo:** the H3 bridge MUST inject `axum::extract::ConnectInfo(remote)` into each request — `media_api.rs:1020` extracts `ConnectInfo<SocketAddr>` for `client_ip` / geo-restriction and will 500 over H3 otherwise.

---

## File Structure

- **Create** `src/modules/h3.rs` — the QUIC→axum bridge (`run_h3_server`, `handle_h3_connection`, `handle_h3_request`, `alt_svc_header_value`, `build_h3_rustls_config`). One responsibility: terminate HTTP/3 and forward to a `Router`.
- **Modify** `src/modules/mod.rs` — declare the feature-gated module.
- **Modify** `Cargo.toml` — add optional deps + `http3` feature.
- **Modify** `src/bin/main.rs` — (a) ALPN on the TCP rustls config; (b) `Alt-Svc` layer on TCP responses; (c) spawn `run_h3_server` in the TLS branch.
- **Create** `tests/http3_smoke.rs` — feature-gated integration test: real QUIC client GETs an endpoint, asserts 200 + ALPN `h3`, HEAD Content-Length, 404 passthrough.

---

### Task 1: Add the `http3` Cargo feature and optional dependencies

**Files:**
- Modify: `Cargo.toml` (`[features]` block ~line 1, dependency list)

**Interfaces:**
- Produces: `http3` feature enabling crates `h3`, `h3-quinn`, `quinn`, `http-body`.

- [ ] **Step 1: Add optional dependencies** (near the existing rustls/bytes deps)

```toml
# HTTP/3 (QUIC) — optional, enabled by the `http3` feature.
# Versions mirror the proven authnz-rs (identity.arkavo.net) stack.
h3 = { version = "0.0.8", optional = true }
h3-quinn = { version = "0.0.10", optional = true }
quinn = { version = "0.11", optional = true }
http-body = { version = "1", optional = true }
```

- [ ] **Step 2: Add the feature** to `[features]`

```toml
http3 = ["h3", "h3-quinn", "quinn", "http-body"]
```

- [ ] **Step 3: Verify the default build is unchanged and the feature resolves**

Run: `cargo build --bin arks` then `cargo build --bin arks --features http3`
Expected: both compile. (After Task 1 alone, `http3` pulls in the crates but nothing uses them yet — a `never used` warning on the deps is acceptable until Task 2.)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(http3): add optional quinn/h3 deps behind http3 feature"
```

---

### Task 2: The QUIC → axum bridge module

**Files:**
- Create: `src/modules/h3.rs`
- Modify: `src/modules/mod.rs`
- Test: `src/modules/h3.rs` (`#[cfg(test)]` unit test for `alt_svc_header_value`)

**Interfaces:**
- Produces:
  - `pub async fn run_h3_server(addr: &str, app: axum::Router, cert_path: &str, key_path: &str) -> Result<(), Box<dyn std::error::Error>>`
  - `pub fn alt_svc_header_value(port: u16) -> http::HeaderValue`
- Consumes: the same `axum::Router` built in `main.rs:982`; the ring crypto provider installed at `main.rs:564`.

- [ ] **Step 1: Write the failing unit test** (append to a new `src/modules/h3.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_advertises_h3_on_given_port() {
        let v = alt_svc_header_value(8443);
        assert_eq!(v.to_str().unwrap(), "h3=\":8443\"; ma=86400");
    }
}
```

- [ ] **Step 2: Run it to verify it fails (module not yet declared / fn missing)**

Run: `cargo test --features http3 --lib alt_svc_advertises_h3_on_given_port`
Expected: FAIL — `cannot find function alt_svc_header_value` / module not found.

- [ ] **Step 3: Write the module** (full `src/modules/h3.rs` above the test block)

```rust
//! In-process HTTP/3 (QUIC) termination, bridged to the shared axum `Router`.
//!
//! Ported from the authnz-rs (identity.arkavo.net) reference. QUIC carries only
//! request/response traffic here — the `/ws` NanoTDF channel stays on TCP/HTTP-1.1
//! because classic WebSockets cannot ride HTTP/3.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::Router;
use bytes::Buf;
use http::{Method, StatusCode};
use log::{debug, info};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tower::ServiceExt; // Router::oneshot

/// `Alt-Svc` value advertising HTTP/3 on `port` for one day.
pub fn alt_svc_header_value(port: u16) -> http::HeaderValue {
    http::HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", port))
        .expect("alt-svc header value is always valid ASCII")
}

/// Build the QUIC rustls config: ALPN `h3`, 0-RTT disabled.
fn build_h3_rustls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_chain = {
        let f = File::open(cert_path)?;
        let mut r = BufReader::new(f);
        certs(&mut r).collect::<Result<Vec<_>, _>>()?
    };
    let key = {
        let f = File::open(key_path)?;
        let mut r = BufReader::new(f);
        let mut keys = pkcs8_private_keys(&mut r).collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err("No PKCS#8 private key found for HTTP/3".into());
        }
        rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0))
    };

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    // 0-RTT (early data) is replayable (RFC 9001 §9.2, RFC 8470). Rewrap and
    // media key-request are non-idempotent with no per-request replay guard, so
    // refuse early data; the only cost is one extra RTT on session resumption.
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Bind a QUIC endpoint on `addr` (UDP) and serve `app` over HTTP/3.
pub async fn run_h3_server(
    addr: &str,
    app: Router,
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_config = build_h3_rustls_config(cert_path, key_path)?;
    let mut quinn_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config)?));
    let transport = Arc::get_mut(&mut quinn_config.transport)
        .ok_or("failed to access QUIC transport config")?;
    transport.max_concurrent_uni_streams(100_u8.into());
    transport.max_concurrent_bidi_streams(100_u8.into());

    let socket = std::net::UdpSocket::bind(addr)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    info!("HTTP/3 (QUIC) listening on udp://{}", addr);

    while let Some(connecting) = endpoint.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    let remote = conn.remote_address();
                    if let Err(e) = handle_h3_connection(conn, app, remote).await {
                        debug!("HTTP/3 connection error from {}: {}", remote, e);
                    }
                }
                Err(e) => debug!("HTTP/3 connection failed: {}", e),
            }
        });
    }
    Ok(())
}

async fn handle_h3_connection(
    conn: quinn::Connection,
    app: Router,
    remote: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, app, remote).await {
                                debug!("HTTP/3 request error: {}", e);
                            }
                        }
                        Err(e) => debug!("HTTP/3 request resolve error: {}", e),
                    }
                });
            }
            Ok(None) => break,
            // Connection end (graceful close / timeout) surfaces as Err; routine, not actionable.
            Err(e) => {
                debug!("HTTP/3 accept loop ended: {}", e);
                break;
            }
        }
    }
    Ok(())
}

async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    app: Router,
    remote: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Buffer the (bounded) request body. Refuse oversized payloads rather than
    //    buffering unbounded memory from an untrusted peer.
    const MAX_H3_BODY: usize = 2 * 1024 * 1024; // 2 MiB
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        if body_bytes.len() + remaining > MAX_H3_BODY {
            let resp = http::Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
        body_bytes.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    let is_head = req.method() == Method::HEAD;

    // 2. Rebuild as an axum request. The QUIC stream framed the body, so the
    //    buffered length is authoritative — normalize Content-Length. Inject
    //    ConnectInfo so client-IP-dependent handlers (media_api) work over H3.
    let (mut parts, _) = req.into_parts();
    parts.headers.remove(http::header::CONTENT_LENGTH);
    if !body_bytes.is_empty() {
        parts.headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from(body_bytes.len() as u64),
        );
    }
    parts.extensions.insert(ConnectInfo(remote));
    let axum_req = http::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    // 3. Drive the router (error type is Infallible).
    let response = app
        .oneshot(axum_req)
        .await
        .map_err(|e| format!("router error: {e}"))?;
    let (mut resp_parts, mut resp_body) = response.into_parts();

    // hyper synthesizes Content-Length on the TCP path; that layer is bypassed
    // here, so replicate it when the body length is exactly known. Gives H3
    // clients (and HEAD probes) the same Content-Length they'd see over HTTP/2.
    if !resp_parts.headers.contains_key(http::header::CONTENT_LENGTH) {
        if let Some(len) = http_body::Body::size_hint(&resp_body).exact() {
            if let Ok(value) = http::HeaderValue::from_str(&len.to_string()) {
                resp_parts
                    .headers
                    .insert(http::header::CONTENT_LENGTH, value);
            }
        }
    }

    stream
        .send_response(http::Response::from_parts(resp_parts, ()))
        .await?;

    if !is_head {
        use http_body_util::BodyExt;
        while let Some(frame) = resp_body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if !data.is_empty() {
                    stream.send_data(data).await?;
                }
            }
        }
    }
    stream.finish().await?;
    Ok(())
}
```

- [ ] **Step 4: Declare the module** — add to `src/modules/mod.rs`

```rust
#[cfg(feature = "http3")]
pub mod h3;
```

- [ ] **Step 5: Run the unit test (passes) and clippy**

Run: `cargo test --features http3 --lib alt_svc_advertises_h3_on_given_port`
Expected: PASS.
Run: `cargo clippy --bin arks --features http3 -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/modules/h3.rs src/modules/mod.rs
git commit -m "feat(http3): add QUIC->axum bridge module (ported from authnz-rs)"
```

---

### Task 3: Wire H3 into the server (ALPN + Alt-Svc + spawn)

**Files:**
- Modify: `src/bin/main.rs` — `load_rustls_config` (~1126), app build (~982-997), TLS serve branch (~1036)

**Interfaces:**
- Consumes: `modules::h3::run_h3_server`, `modules::h3::alt_svc_header_value`; `settings.port` (u16), `settings.tls_cert_path`, `settings.tls_key_path`.

- [ ] **Step 1: Advertise HTTP/2 + HTTP/1.1 via ALPN on the TCP config.** In `load_rustls_config`, after `with_single_cert(...)` builds `config` and before returning it:

```rust
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("Failed to create TLS config: {}", e))?;

    // Negotiate HTTP/2 for REST clients while keeping HTTP/1.1 for the WebSocket
    // upgrade (/ws). Without ALPN, clients silently fall back to HTTP/1.1 only.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
```

- [ ] **Step 2: Split the app into an H3 base (no Alt-Svc) and a TCP app (with Alt-Svc).** Replace the end of the app build at `src/bin/main.rs:995-997`.

The H3 server serves the base router so it never advertises h3 to an already-H3 client; Alt-Svc only upgrades TCP clients. Insert immediately after the `.layer(...)` that closes the `let app = ...` statement:

```rust
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(log_request_middleware)),
        );

    // HTTP/3 (feature-gated). The H3 server serves the base `app`; the TCP `app`
    // gets an Alt-Svc layer advertising h3 so HTTP/1.1/2 clients can upgrade.
    #[cfg(feature = "http3")]
    let h3_app_base = app.clone();

    #[cfg(feature = "http3")]
    let app = {
        let alt_svc = modules::h3::alt_svc_header_value(settings.port);
        app.layer(axum::middleware::map_response(move |mut res: axum::response::Response| {
            let alt_svc = alt_svc.clone();
            async move {
                res.headers_mut().insert(http::header::ALT_SVC, alt_svc);
                res
            }
        }))
    };
```

- [ ] **Step 3: Spawn the H3 listener in the TLS branch.** At the top of the `if let Some(tls_acceptor) = tls_acceptor {` block (`src/bin/main.rs:1036`), after the `info!("TLS enabled ...")` line and before the TCP `listener` bind:

```rust
        #[cfg(feature = "http3")]
        {
            let h3_addr = format!("0.0.0.0:{}", settings.port);
            let h3_app = h3_app_base;
            let h3_cert = settings.tls_cert_path.clone();
            let h3_key = settings.tls_key_path.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    modules::h3::run_h3_server(&h3_addr, h3_app, &h3_cert, &h3_key).await
                {
                    error!("HTTP/3 server error: {}", e);
                }
            });
        }
```

- [ ] **Step 4: Build both feature configurations**

Run: `cargo build --bin arks` (default — H3 code excluded)
Run: `cargo build --bin arks --features http3`
Expected: both compile.

- [ ] **Step 5: Clippy with all features (CI parity)**

Run: `cargo clippy --lib --bin arks --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Format**

Run: `cargo fmt --package arkavo-rs --package fairplay-wrapper`

- [ ] **Step 7: Commit**

```bash
git add src/bin/main.rs
git commit -m "feat(http3): wire ALPN, Alt-Svc, and QUIC listener into the unified server"
```

---

### Task 4: HTTP/3 end-to-end smoke test

**Files:**
- Create: `tests/http3_smoke.rs`

**Interfaces:**
- Consumes: `nanotdf::modules::h3::run_h3_server` (via the library crate) using a self-signed cert generated in the test, and a minimal axum `Router`.

> Mirrors the authnz-rs `h3-smoke-client` gate table: QUIC handshake + ALPN `h3`, real-status passthrough (200 + 404), and HEAD Content-Length with empty body. The whole file is `#![cfg(feature = "http3")]` so default `cargo test` skips it.

- [ ] **Step 1: Write the test** (a real quinn/h3 client against an ephemeral server)

```rust
#![cfg(feature = "http3")]
//! End-to-end HTTP/3 smoke test: a real QUIC client drives the bridge.

use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use bytes::Buf;

// A trivial router with a known body and a 404-able surface.
fn test_app() -> Router {
    Router::new().route("/ping", get(|| async { "pong" }))
}

#[tokio::test]
async fn h3_handshake_get_head_and_404() {
    // The bridge needs the ring provider installed (as main.rs does at startup).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Generate an in-memory self-signed cert/key and write to temp files,
    // because run_h3_server loads from paths.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join("arks_h3_smoke");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Bind on an ephemeral UDP port chosen by the OS.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = udp.local_addr().unwrap();
    drop(udp); // free it; run_h3_server re-binds the same port string
    let addr = server_addr.to_string();

    tokio::spawn({
        let cert_path = cert_path.clone();
        let key_path = key_path.clone();
        async move {
            nanotdf::modules::h3::run_h3_server(
                &addr,
                test_app(),
                cert_path.to_str().unwrap(),
                key_path.to_str().unwrap(),
            )
            .await
            .unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build an h3 client that trusts our self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(&cert_path).unwrap(),
    )) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let conn = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("QUIC handshake");

    // ALPN must be h3.
    let alpn = conn
        .handshake_data()
        .unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .unwrap()
        .protocol
        .unwrap();
    assert_eq!(alpn, b"h3", "negotiated ALPN must be h3");

    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send) = h3::client::new(h3_conn).await.unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // GET /ping -> 200 "pong"
    let req = http::Request::get("https://localhost/ping").body(()).unwrap();
    let mut s = send.send_request(req).await.unwrap();
    s.finish().await.unwrap();
    let resp = s.recv_response().await.unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = Vec::new();
    while let Some(mut chunk) = s.recv_data().await.unwrap() {
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    assert_eq!(&body, b"pong");

    // GET /missing -> real 404 passthrough (not a stub 200)
    let req = http::Request::get("https://localhost/missing").body(()).unwrap();
    let mut s = send.send_request(req).await.unwrap();
    s.finish().await.unwrap();
    let resp = s.recv_response().await.unwrap();
    assert_eq!(resp.status(), 404);

    // HEAD /ping -> 200, Content-Length: 4, empty body
    let req = http::Request::head("https://localhost/ping").body(()).unwrap();
    let mut s = send.send_request(req).await.unwrap();
    s.finish().await.unwrap();
    let resp = s.recv_response().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get(http::header::CONTENT_LENGTH).unwrap(),
        "4"
    );
    let mut head_body = Vec::new();
    while let Some(mut chunk) = s.recv_data().await.unwrap() {
        head_body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    assert!(head_body.is_empty(), "HEAD must have no body");
}
```

- [ ] **Step 2: Add `rcgen` dev-dependency** (only needed by this test)

```toml
[dev-dependencies]
rcgen = "0.13"
```

- [ ] **Step 3: Run the test**

Run: `cargo test --features http3 --test http3_smoke -- --nocapture`
Expected: PASS (handshake, ALPN h3, GET 200 "pong", 404, HEAD Content-Length 4 + empty body).

- [ ] **Step 4: Commit**

```bash
git add tests/http3_smoke.rs Cargo.toml Cargo.lock
git commit -m "test(http3): end-to-end QUIC smoke test (handshake, GET/HEAD/404)"
```

---

### Task 5: Docs + draft PR

**Files:**
- Create: `docs/http3.md` — operational notes (UDP/443 ingress, feature flag, what is/isn't covered).
- Modify: `CLAUDE.md` — add `http3` feature + UDP note to config section.

- [ ] **Step 1: Write `docs/http3.md`** covering: build with `--features http3`; H3 serves the REST/discovery surface, `/ws` stays TCP/HTTP-1.1; **UDP ingress on the server port must be opened** (firewall/LB/security-groups); 0-RTT intentionally disabled; Alt-Svc advertisement.

- [ ] **Step 2: Add a `--features http3` + UDP note** to the relevant CLAUDE.md config block.

- [ ] **Step 3: Commit**

```bash
git add docs/http3.md CLAUDE.md
git commit -m "docs(http3): operational notes and feature documentation"
```

- [ ] **Step 4: Push and open the draft PR**

```bash
git push -u origin feat/http3-quinn-h3
gh pr create --draft --title "feat(http3): in-process HTTP/3 (QUIC) for the REST surface" --body "..."
```

---

## Self-Review

**Spec coverage:** ALPN fix (Task 3.1) ✓; in-process quinn/h3 termination (Task 2) ✓; ConnectInfo injection (Task 2 step 3, the `media_api` gotcha) ✓; 0-RTT disabled (Task 2 `build_h3_rustls_config`) ✓; Alt-Svc (Task 3.2) ✓; feature-gated, default build unchanged (Tasks 1-3) ✓; WS unaffected (no `/ws` change; serves same router, WS upgrade simply not offered over H3) ✓; smoke gate mirroring authnz table (Task 4) ✓; UDP ingress operational note (Task 5) ✓.

**Type consistency:** `run_h3_server(addr, app, cert_path, key_path)` signature is consistent between Task 2 (definition) and Task 3 (call) and Task 4 (test call via `nanotdf::modules::h3`). `alt_svc_header_value(port: u16) -> http::HeaderValue` consistent between Task 2 and Task 3. `ConnectInfo<SocketAddr>` matches `media_api.rs:1020`.

**Risk notes:** (1) `h3` 0.0.x API is pre-1.0 — `resolver.resolve_request()` / `RequestStream` generics are exactly as in authnz-rs 0.0.8; if a minor bump changed them, pin to the authnz `Cargo.lock` entries. (2) The smoke test's client-side `HandshakeData`/`QuicClientConfig` types depend on quinn's rustls feature; if the assert line fails to compile, drop the ALPN assertion (server-side ALPN is already enforced) and keep the GET/HEAD/404 gates.
