//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::Response;
use reqwest::Client;
use url::Url;

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
