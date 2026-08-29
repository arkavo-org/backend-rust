//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use reqwest::Client;
use url::Url;

use crate::modules::cwt_auth::ACTOR_TOKEN_HEADER;

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

    /// `/.well-known/opentdf-configuration` is platform-authoritative discovery.
    /// Whenever any proxying is on, defer to the upstream document.
    pub fn forwards_discovery(self) -> bool {
        !matches!(self, ProxyMode::Off)
    }
}

/// Shared state for the reverse-proxy handler.
#[derive(Debug)]
pub struct PlatformProxyState {
    pub client: Client,
    /// Upstream base URL with no trailing slash, e.g. `https://platform.svc:8443`.
    pub upstream_base: String,
    /// This service's own CWT, sent as `X-Actor-Token` on every forwarded
    /// request so the upstream can see *who forwarded* the caller's bearer.
    /// Parsed once at startup: a bad value must fail loudly, not per-request.
    /// Marked sensitive (`HeaderValue::set_sensitive`) so this struct's
    /// derived `Debug` cannot print the credential.
    pub actor_token: Option<HeaderValue>,
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
        Ok(Arc::new(Self {
            client,
            upstream_base,
            actor_token: None,
        }))
    }

    /// Attach this service's CWT, relayed as `X-Actor-Token`. The caller's own
    /// `Authorization` bearer is still forwarded untouched — the upstream
    /// platform verifies it and uses the actor token to authenticate the
    /// forwarder against the bearer's `act[]`.
    pub fn with_actor_token(self: Arc<Self>, token: &str) -> Result<Arc<Self>, String> {
        let mut value = HeaderValue::from_str(token.trim())
            .map_err(|e| format!("service CWT is not a valid header value: {e}"))?;
        // This is a live bearer credential and `PlatformProxyState` derives
        // `Debug`; a non-sensitive `HeaderValue` prints its full contents.
        // Marking it sensitive makes `{:?}` render `Sensitive` instead.
        value.set_sensitive(true);
        Ok(Arc::new(Self {
            client: self.client.clone(),
            upstream_base: self.upstream_base.clone(),
            actor_token: Some(value),
        }))
    }
}

/// Per-request body cap (16 MiB). Matches `MAX_NANOTDF_SIZE` in `main.rs`
/// and bounds memory used buffering an inbound request before forwarding.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;

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
        .map_err(|e| {
            log::warn!("proxy request body read error: {e}");
            StatusCode::PAYLOAD_TOO_LARGE
        })?;

    let mut headers = parts.headers.clone();
    strip_proxy_headers(&mut headers);
    // Never relay a client-supplied actor token: the actor is *this* service,
    // and only this service may assert it.
    headers.remove(HeaderName::from_static(ACTOR_TOKEN_HEADER));
    if let Some(actor) = state.actor_token.as_ref() {
        headers.insert(HeaderName::from_static(ACTOR_TOKEN_HEADER), actor.clone());
    }

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

    let bytes = upstream_resp.bytes().await.map_err(|e| {
        log::warn!("proxy upstream body read error: {e}");
        StatusCode::BAD_GATEWAY
    })?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}

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

/// Strip RFC 7230 hop-by-hop headers (including `Host`) and `keep-alive` from `headers` in place.
/// Also parses the `Connection:` value and strips any headers named there (RFC 7230 §6.1).
pub(crate) fn strip_proxy_headers(headers: &mut HeaderMap) {
    // RFC 7230 §6.1: the Connection header lists additional hop-by-hop names
    // for this specific message. Collect them before mutating, since the next
    // loop removes Connection itself.
    let mut connection_listed: Vec<HeaderName> = Vec::new();
    if let Some(conn) = headers.get(header::CONNECTION) {
        if let Ok(val) = conn.to_str() {
            for name in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Ok(hn) = HeaderName::from_str(name) {
                    connection_listed.push(hn);
                }
            }
        }
    }
    for h in &connection_listed {
        headers.remove(h);
    }
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
    headers.remove(HeaderName::from_static("keep-alive"));
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn rejects_invalid_url() {
        let err = PlatformProxyState::new("not a url").unwrap_err();
        assert!(err.to_string().contains("invalid"), "got: {err}");
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = PlatformProxyState::new("file:///etc/passwd").unwrap_err();
        assert!(err.to_string().contains("scheme"), "got: {err}");
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

    #[test]
    fn no_actor_token_by_default() {
        let state = PlatformProxyState::new("https://platform.svc").unwrap();
        assert!(state.actor_token.is_none());
    }

    #[test]
    fn actor_token_trims_trailing_newline() {
        // Reading the CWT from a file leaves a trailing newline, which
        // `HeaderValue::from_str` rejects outright.
        let state = PlatformProxyState::new("https://platform.svc")
            .unwrap()
            .with_actor_token("d2.abc123\n")
            .unwrap();
        assert_eq!(state.actor_token.as_ref().unwrap(), "d2.abc123");
    }

    #[test]
    fn actor_token_rejects_invalid_header_value() {
        let err = PlatformProxyState::new("https://platform.svc")
            .unwrap()
            .with_actor_token("bad\u{7f}value")
            .unwrap_err();
        assert!(err.contains("not a valid header value"), "got: {err}");
    }
}

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
        assert!(!ProxyMode::Off.forwards_discovery());

        assert!(ProxyMode::Connect.forwards_connect());
        assert!(!ProxyMode::Connect.forwards_rest());
        assert!(ProxyMode::Connect.forwards_discovery());

        assert!(!ProxyMode::Rest.forwards_connect());
        assert!(ProxyMode::Rest.forwards_rest());
        assert!(ProxyMode::Rest.forwards_discovery());

        assert!(ProxyMode::Both.forwards_connect());
        assert!(ProxyMode::Both.forwards_rest());
        assert!(ProxyMode::Both.forwards_discovery());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::{routing::any, Router};
    use reqwest::Client;
    use tokio::net::TcpListener;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// Build an arks-side server with the proxy mounted at `/kas/v2/rewrap`
    /// pointing at `upstream`. Returns the bound base URL and socket address.
    async fn spawn_proxy(upstream: &str) -> (String, std::net::SocketAddr) {
        let state = PlatformProxyState::new(upstream).expect("valid upstream URL");
        let app = Router::new()
            .route("/kas/v2/rewrap", any(proxy))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), addr)
    }

    #[tokio::test]
    async fn forwards_attribute_discovery_routes() {
        // Attribute FQN paths must dereference through this host to the
        // upstream platform's policy snapshot (single source of truth).
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/attr/tier/value/supporter"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"value":"supporter","fqn":"https://patreon.arkavo.com/attr/tier/value/supporter"}"#,
                "application/json",
            ))
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri()).expect("valid upstream URL");
        let app = Router::new()
            .route("/attr/*rest", axum::routing::get(proxy))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = Client::new()
            .get(format!("http://{addr}/attr/tier/value/supporter"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.text().await.unwrap().contains("supporter"));
    }

    #[tokio::test]
    async fn forwards_authorization_v2_wildcard_routes() {
        // The entitled-catalog endpoint (tdf-iroh-s3#5) reaches the platform
        // PDP through this host; every AuthorizationService method must
        // forward under the wildcard.
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"resourceDecisions":[]}"#, "application/json"),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri()).expect("valid upstream URL");
        let app = Router::new()
            .route(
                // post() mirrors the production binding in main.rs so the
                // test catches accidental method-binding regressions.
                "/authorization.v2.AuthorizationService/*method",
                axum::routing::post(proxy),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = Client::new()
            .post(format!(
                "http://{addr}/authorization.v2.AuthorizationService/GetDecisionMultiResource"
            ))
            .header("content-type", "application/json")
            .body(r#"{"entityIdentifier":{}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn forwards_post_with_body_and_returns_upstream_response() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .and(header("authorization", "Bearer test-jwt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{"ok":true}"#, "application/json"),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let (proxy_base, _) = spawn_proxy(&upstream.uri()).await;

        let resp = Client::new()
            .post(format!("{proxy_base}/kas/v2/rewrap"))
            .header("authorization", "Bearer test-jwt")
            .body(r#"{"signed_request_token":"abc"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(resp.text().await.unwrap(), r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn does_not_forward_host_or_hop_by_hop_headers() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kas/v2/rewrap"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&upstream)
            .await;

        let (proxy_base, proxy_addr) = spawn_proxy(&upstream.uri()).await;

        Client::new()
            .get(format!("{proxy_base}/kas/v2/rewrap"))
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
        assert!(
            !host.contains(&proxy_addr.to_string()),
            "host header leaked proxy address {proxy_addr}, got {host}"
        );

        // Hop-by-hop headers must not be forwarded.
        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("te").is_none());
    }

    #[tokio::test]
    async fn forwards_upstream_status_codes() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .expect(1)
            .mount(&upstream)
            .await;

        let (proxy_base, _) = spawn_proxy(&upstream.uri()).await;
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
        let (proxy_base, _) = spawn_proxy("http://127.0.0.1:1").await;

        let resp = Client::new()
            .post(format!("{proxy_base}/kas/v2/rewrap"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 502);
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn strip_hop_by_hop_removes_rfc7230_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::HOST, HeaderValue::from_static("kas.local"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );

        strip_proxy_headers(&mut headers);

        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key(header::TE));
        assert!(!headers.contains_key(header::HOST));
        assert!(!headers.contains_key(HeaderName::from_static("keep-alive")));
        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer x");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn strip_proxy_headers_honors_connection_listed_names() {
        // RFC 7230 §6.1: headers named in the Connection field are hop-by-hop
        // for that specific message and must be removed before forwarding.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Custom-Hop"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-hop"),
            HeaderValue::from_static("session=abc"),
        );
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));

        strip_proxy_headers(&mut headers);

        assert!(!headers.contains_key(HeaderName::from_static("x-custom-hop")));
        assert!(!headers.contains_key(header::CONNECTION));
        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer x");
    }
}

/// The relay leg of the CWT identity plane: arks forwards the caller's bearer
/// untouched and asserts *itself* as the forwarder via `X-Actor-Token`.
#[cfg(test)]
mod actor_token_tests {
    use super::*;

    /// `PlatformProxyState` derives `Debug` and the actor token is a live
    /// bearer credential, so the stored `HeaderValue` must be sensitive.
    #[test]
    fn debug_does_not_print_the_service_cwt() {
        let state = PlatformProxyState::new("https://platform.test")
            .unwrap()
            .with_actor_token("d2845820deadbeefcafe")
            .unwrap();
        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains("deadbeefcafe"),
            "service CWT leaked into Debug: {rendered}"
        );
    }

    use axum::{routing::any, Router};
    use reqwest::Client;
    use tokio::net::TcpListener;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    async fn spawn(state: Arc<PlatformProxyState>) -> String {
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
    async fn injects_service_actor_token_and_keeps_caller_bearer() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .and(header("authorization", "Bearer caller-cwt"))
            .and(header("x-actor-token", "arks-service-cwt"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri())
            .unwrap()
            .with_actor_token("arks-service-cwt\n")
            .unwrap();
        let base = spawn(state).await;

        let resp = Client::new()
            .post(format!("{base}/kas/v2/rewrap"))
            .header("authorization", "Bearer caller-cwt")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn overwrites_a_client_supplied_actor_token() {
        // Only arks may assert who forwarded the request; a client-supplied
        // X-Actor-Token must never reach the upstream.
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .and(header("x-actor-token", "arks-service-cwt"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri())
            .unwrap()
            .with_actor_token("arks-service-cwt")
            .unwrap();
        let base = spawn(state).await;

        let resp = Client::new()
            .post(format!("{base}/kas/v2/rewrap"))
            .header("x-actor-token", "forged-by-client")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn strips_client_actor_token_when_service_has_none() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri()).unwrap();
        let base = spawn(state).await;

        let resp = Client::new()
            .post(format!("{base}/kas/v2/rewrap"))
            .header("x-actor-token", "forged-by-client")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        // The upstream never saw the forged header.
        let reqs = upstream.received_requests().await.unwrap();
        assert!(reqs[0].headers.get("x-actor-token").is_none());
    }
}
