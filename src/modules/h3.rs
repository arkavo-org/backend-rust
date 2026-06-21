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

/// Global cap on concurrent QUIC connections. With per-connection streams also
/// bounded (below), this caps worst-case in-flight tasks and buffered memory
/// regardless of how many peers connect.
const MAX_H3_CONNECTIONS: usize = 1024;

/// Serve HTTP/3 over the pre-bound QUIC `socket`.
///
/// The socket is bound by the caller so a hard bind error (e.g. UDP port
/// conflict) surfaces at startup — and the caller can decide whether to
/// advertise `Alt-Svc` — rather than dying quietly inside a detached task while
/// TCP keeps pointing clients at a dead H3 endpoint.
pub async fn run_h3_server(
    socket: std::net::UdpSocket,
    app: Router,
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_config = build_h3_rustls_config(cert_path, key_path)?;
    let mut quinn_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config)?));
    let transport = Arc::get_mut(&mut quinn_config.transport)
        .ok_or("failed to access QUIC transport config")?;
    // Each in-flight request can buffer up to MAX_H3_BODY (2 MiB), so bound the
    // per-connection bidi streams to keep worst-case per-connection memory
    // modest (32 * 2 MiB). HTTP/3 needs a few uni streams for control + QPACK.
    transport.max_concurrent_uni_streams(16_u8.into());
    transport.max_concurrent_bidi_streams(32_u8.into());

    let local_addr = socket.local_addr()?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    info!("HTTP/3 (QUIC) listening on udp://{}", local_addr);

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_H3_CONNECTIONS));
    while let Some(connecting) = endpoint.accept().await {
        // Backpressure: stop accepting once at the connection cap; the permit is
        // held for the connection's lifetime and released when its task ends.
        let permit = match conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore is never closed while the loop runs
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
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
    const MAX_H3_BODY: usize = 2 * 1024 * 1024; // 2 MiB

    // 0. Reject content types that carry their status in HTTP trailers (gRPC's
    //    grpc-status). This bridge forwards data frames only, so a gRPC call
    //    would otherwise get a silent 200 with no status. gRPC-Web keeps its
    //    status in the body, so it is allowed through.
    if req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.starts_with("application/grpc") && !ct.starts_with("application/grpc-web")
        })
    {
        let resp = http::Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    // 1. Buffer the (bounded) request body. Reject an oversized *declared*
    //    Content-Length before buffering anything, then enforce the same bound
    //    per chunk (the header can lie or be absent).
    if req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|declared| declared > MAX_H3_BODY)
    {
        let resp = http::Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

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
    if !resp_parts
        .headers
        .contains_key(http::header::CONTENT_LENGTH)
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_svc_advertises_h3_on_given_port() {
        let v = alt_svc_header_value(8443);
        assert_eq!(v.to_str().unwrap(), "h3=\":8443\"; ma=86400");
    }
}

#[cfg(test)]
mod e2e_tests {
    //! End-to-end smoke test: a real QUIC/h3 client drives the bridge against a
    //! trivial router. Mirrors the authnz-rs `h3-smoke-client` gate table —
    //! handshake + ALPN h3, real-status passthrough (200/404), and a HEAD that
    //! carries Content-Length but no body.
    use super::*;
    use axum::routing::get;

    /// Accept-any-cert verifier — local self-signed testing only.
    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn test_app() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    async fn do_req(
        send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
        method: &str,
        uri: &str,
    ) -> (http::StatusCode, Option<String>, Vec<u8>) {
        let req = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .unwrap();
        let mut stream = send.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let status = resp.status();
        let clen = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|v| v.to_str().unwrap().to_string());
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let n = chunk.remaining();
            body.extend_from_slice(chunk.copy_to_bytes(n).as_ref());
        }
        (status, clen, body)
    }

    #[tokio::test]
    async fn h3_handshake_get_head_and_404() {
        // The bridge needs a process-default crypto provider (as main.rs installs).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Self-signed cert/key to temp files (run_h3_server loads from paths).
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir();
        let cert_path = dir.join("arks_h3_smoke_cert.pem");
        let key_path = dir.join("arks_h3_smoke_key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();

        // Bind the server's UDP socket up-front (no probe/drop race) and read the
        // assigned port before handing the socket to the server.
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let cert_s = cert_path.to_str().unwrap().to_string();
        let key_s = key_path.to_str().unwrap().to_string();
        tokio::spawn(async move {
            let _ = run_h3_server(server_socket, test_app(), &cert_s, &key_s).await;
        });
        // No fixed readiness sleep: the socket is already bound, so the kernel
        // buffers the client's handshake datagrams until the endpoint starts
        // reading, and QUIC retransmission covers the brief startup gap.

        // h3 client trusting any cert.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));

        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .expect("QUIC handshake + ALPN h3");
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // GET /ping -> 200 "pong"
        let (status, _, body) = do_req(&mut send, "GET", "https://localhost/ping").await;
        assert_eq!(status, 200);
        assert_eq!(&body, b"pong");

        // GET /missing -> real 404 passthrough (not a stub 200)
        let (status, _, _) = do_req(&mut send, "GET", "https://localhost/missing").await;
        assert_eq!(status, 404);

        // HEAD /ping -> 200, Content-Length: 4, empty body
        let (status, clen, body) = do_req(&mut send, "HEAD", "https://localhost/ping").await;
        assert_eq!(status, 200);
        assert_eq!(clen.as_deref(), Some("4"));
        assert!(body.is_empty(), "HEAD response must have no body");

        drop(send);
        drive.abort();
        endpoint.wait_idle().await;
    }
}
