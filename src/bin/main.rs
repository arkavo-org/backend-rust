mod contracts;
mod schemas;

// Import modules from library
use nanotdf::{chain, media_metrics, session_manager};

// Include modules from parent src/modules directory
#[path = "../modules/mod.rs"]
mod modules;

#[cfg(feature = "c2pa_signing")]
use modules::c2pa_signing;
use modules::{cbor_protocol, http_rewrap, media_api, ntdf_token, platform_proxy};
use opentdf_kas::{
    compute_nanotdf_salt, custom_ecdh, detect_nanotdf_version, rewrap_dek, NanoTdfVersion,
};

use crate::contracts::content_rating::content_rating::{
    AgeLevel, ContentRating, Rating, RatingLevel,
};
use crate::contracts::geo_fence_contract::geo_fence_contract::Geofence3D;
use crate::contracts::{contract_simple_abac, geo_fence_contract};
use crate::schemas::event_generated::arkavo::{Action, Event, EventData};
use crate::schemas::metadata_generated::arkavo;
use crate::schemas::metadata_generated::arkavo::{root_as_metadata, Metadata};
use async_nats::Message as NatsMessage;
use async_nats::{Client as NatsClient, PublishError};
use aws_sdk_s3 as s3;
use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use flatbuffers::root;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::{error, info, warn};
use nanotdf::{BinaryParser, PolicyType, ProtocolEnum, ResourceLocator};
use once_cell::sync::OnceCell;
use p256::ecdh::EphemeralSecret;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use redis::AsyncCommands;
use redis::Client as RedisClient;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyMessage {
    salt: Vec<u8>,
    public_key: Vec<u8>,
}

const MAX_NANOTDF_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const NATS_RETRY_INTERVAL: Duration = Duration::from_secs(5);

struct NatsConnection {
    client: Mutex<Option<async_nats::Client>>,
    url: String,
}

impl NatsConnection {
    fn new(url: String) -> Self {
        Self {
            client: Mutex::new(None),
            url,
        }
    }
    async fn connect(&self) -> Result<(), async_nats::Error> {
        let mut client = self.client.lock().await;
        match async_nats::connect(&self.url).await {
            Ok(new_client) => {
                *client = Some(new_client);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
    async fn get_client(&self) -> Option<async_nats::Client> {
        self.client.lock().await.clone()
    }
}

struct NATSMessage {
    data: Vec<u8>,
}

impl NATSMessage {
    fn new(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > MAX_NANOTDF_SIZE {
            return Err("NanoTDF message exceeds maximum size");
        }
        Ok(Self {
            data: data.to_vec(),
        })
    }

    async fn send_to_nats(
        &self,
        nats_client: &NatsClient,
        subject: String,
    ) -> Result<(), PublishError> {
        nats_client.publish(subject, self.data.clone().into()).await
    }
}

struct ConnectionState {
    salt_lock: RwLock<Option<Vec<u8>>>,
    shared_secret_lock: RwLock<Option<Vec<u8>>>,
    claims_lock: RwLock<Option<Claims>>,
    #[allow(dead_code)] // Used for future policy enforcement
    ntdf_claims_lock: RwLock<Option<ntdf_token::NtdfTokenPayload>>,
    outgoing_tx: mpsc::UnboundedSender<Message>,
}

impl ConnectionState {
    fn new(outgoing_tx: mpsc::UnboundedSender<Message>) -> Self {
        ConnectionState {
            salt_lock: RwLock::new(None),
            shared_secret_lock: RwLock::new(None),
            claims_lock: RwLock::new(None),
            ntdf_claims_lock: RwLock::new(None),
            outgoing_tx,
        }
    }

    fn new_with_ntdf_claims(
        outgoing_tx: mpsc::UnboundedSender<Message>,
        ntdf_claims: ntdf_token::NtdfTokenPayload,
    ) -> Self {
        ConnectionState {
            salt_lock: RwLock::new(None),
            shared_secret_lock: RwLock::new(None),
            claims_lock: RwLock::new(None),
            ntdf_claims_lock: RwLock::new(Some(ntdf_claims)),
            outgoing_tx,
        }
    }
}

#[derive(Debug)]
enum MessageType {
    PublicKey = 0x01,
    KasPublicKey = 0x02,
    Rewrap = 0x03,
    RewrappedKey = 0x04,
    Nats = 0x05,
    Event = 0x06,
    Cbor = 0x08, // CBOR-encoded messages (chain rewrap, etc.)
    Error = 0xFF,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::PublicKey),
            0x02 => Some(MessageType::KasPublicKey),
            0x03 => Some(MessageType::Rewrap),
            0x04 => Some(MessageType::RewrappedKey),
            0x05 => Some(MessageType::Nats),
            0x06 => Some(MessageType::Event),
            0x08 => Some(MessageType::Cbor),
            0xFF => Some(MessageType::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error_type: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl ErrorResponse {
    fn invalid_format(message: impl Into<String>) -> Self {
        Self {
            error_type: "invalid_format".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn policy_denied(message: impl Into<String>) -> Self {
        Self {
            error_type: "policy_denied".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn crypto_error(message: impl Into<String>) -> Self {
        Self {
            error_type: "crypto_error".to_string(),
            message: message.into(),
            details: None,
        }
    }

    #[allow(dead_code)]
    fn server_error(message: impl Into<String>) -> Self {
        Self {
            error_type: "server_error".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn to_message(&self) -> Message {
        let json_payload = serde_json::to_vec(self).unwrap_or_else(|_| {
            br#"{"error_type":"server_error","message":"Failed to serialize error"}"#.to_vec()
        });
        let mut response_data = Vec::with_capacity(1 + json_payload.len());
        response_data.push(MessageType::Error as u8);
        response_data.extend_from_slice(&json_payload);
        Message::Binary(response_data)
    }
}

struct KasKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

static KAS_KEYS: OnceCell<Arc<KasKeys>> = OnceCell::new();

/// Middleware for logging HTTP requests
async fn log_request_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    let response = next.run(req).await;

    let latency = start.elapsed();
    let status = response.status();

    info!("{} {} - {} ({:?})", method, uri, status.as_u16(), latency);

    response
}

/// WebSocket upgrade handler for Axum
async fn ws_handler(
    State(state): State<Arc<WebSocketState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Check for NTDF token in Authorization header
    if let Some(auth_header) = headers.get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("NTDF ") {
                // Validate NTDF token
                match get_kas_private_key_bytes() {
                    Some(kas_key_bytes) => {
                        let kas_key_array: [u8; 32] = match kas_key_bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => {
                                warn!("Invalid KAS private key length");
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Server configuration error",
                                )
                                    .into_response();
                            }
                        };
                        let kas_private_key = match SecretKey::from_bytes(&kas_key_array.into()) {
                            Ok(key) => key,
                            Err(_) => {
                                warn!("Invalid KAS private key");
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Server configuration error",
                                )
                                    .into_response();
                            }
                        };

                        match ntdf_token::validate_ntdf_token(
                            auth_str,
                            &kas_private_key,
                            &state.server_state.settings.ntdf_expected_audience,
                        ) {
                            Ok(claims) => {
                                info!("NTDF token validated: sub_id={}", claims.sub_id_hex());
                                return ws
                                    .on_upgrade(move |socket| {
                                        handle_websocket_axum_with_ntdf(socket, state, claims)
                                    })
                                    .into_response();
                            }
                            Err(e) => {
                                warn!("NTDF token validation failed: {:?}", e);
                                return (
                                    StatusCode::UNAUTHORIZED,
                                    format!("Invalid NTDF token: {}", e),
                                )
                                    .into_response();
                            }
                        }
                    }
                    None => {
                        warn!("KAS private key not initialized");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Server not ready")
                            .into_response();
                    }
                }
            }
        }
    }

    // No NTDF token - allow for backward compatibility
    ws.on_upgrade(move |socket| handle_websocket_axum(socket, state))
        .into_response()
}

/// Handle WebSocket connection using Axum's WebSocket type
async fn handle_websocket_axum(ws: WebSocket, state: Arc<WebSocketState>) {
    // Split the WebSocket into sender and receiver
    let (mut ws_sender, mut ws_receiver) = ws.split();

    // Create channel for outgoing messages
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();

    // Create ConnectionState with the outgoing channel
    let connection_state = Arc::new(ConnectionState::new(outgoing_tx));

    // Set up NATS subscription for this connection
    let nats_task = tokio::spawn(handle_nats_subscription(
        state.nats_connection.clone(),
        state.server_state.settings.nats_subject.clone(),
        connection_state.clone(),
    ));

    let mut public_id_nats_task: Option<tokio::task::JoinHandle<()>> = None;

    // Spawn task to forward outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            // Convert tokio_tungstenite Message to Axum WebSocket message
            let axum_msg = match msg {
                Message::Binary(data) => AxumMessage::Binary(data),
                Message::Text(text) => AxumMessage::Text(text),
                Message::Close(_) => AxumMessage::Close(None),
                _ => continue,
            };

            if ws_sender.send(axum_msg).await.is_err() {
                eprintln!("Failed to send outgoing message through WebSocket");
                break;
            }
        }
    });

    // Handle incoming WebSocket messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(msg) => {
                match msg {
                    AxumMessage::Close(_) => {
                        println!("Received a close message.");
                        break;
                    }
                    AxumMessage::Text(token) => {
                        // Handle JWT token
                        println!("token: {}", token);
                        match verify_token(&token, &state.server_state.settings) {
                            Ok(claims) => {
                                println!("Valid JWT received. Claims: {:?}", claims);
                                // Store the claims
                                {
                                    let mut claims_lock =
                                        connection_state.claims_lock.write().unwrap();
                                    *claims_lock = Some(claims.clone());
                                }
                                // Extract publicID from claims and subscribe to `profile.<publicID>`
                                let public_id = claims.sub;
                                let subject = format!("profile.{}", public_id);
                                // Cancel any existing `publicID`-specific NATS task
                                if let Some(task) = public_id_nats_task.take() {
                                    task.abort();
                                }
                                // Set up new NATS subscription for `profile.<publicID>`
                                public_id_nats_task = Some(tokio::spawn(handle_nats_subscription(
                                    state.nats_connection.clone(),
                                    subject,
                                    connection_state.clone(),
                                )));
                            }
                            Err(e) => {
                                error!("Invalid JWT: {}", e);
                            }
                        }
                    }
                    AxumMessage::Binary(data) => {
                        // Handle binary message
                        if let Some(response) = handle_binary_message(
                            &connection_state,
                            &state.server_state,
                            data,
                            state.nats_connection.clone(),
                        )
                        .await
                        {
                            // Convert tokio_tungstenite Message to Axum message and send via channel
                            let _ = connection_state.outgoing_tx.send(response);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("Error reading message: {}", e);
                break;
            }
        }
    }

    // Cancel the NATS subscription when the WebSocket connection closes
    nats_task.abort();
    if let Some(task) = public_id_nats_task {
        task.abort();
    }
    outgoing_task.abort();
}

/// Handle WebSocket connection with pre-validated NTDF claims
async fn handle_websocket_axum_with_ntdf(
    ws: WebSocket,
    state: Arc<WebSocketState>,
    ntdf_claims: ntdf_token::NtdfTokenPayload,
) {
    // Split the WebSocket into sender and receiver
    let (mut ws_sender, mut ws_receiver) = ws.split();

    // Create channel for outgoing messages
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();

    // Create ConnectionState with NTDF claims
    let connection_state = Arc::new(ConnectionState::new_with_ntdf_claims(
        outgoing_tx,
        ntdf_claims.clone(),
    ));

    // Set up NATS subscription for this connection
    let nats_task = tokio::spawn(handle_nats_subscription(
        state.nats_connection.clone(),
        state.server_state.settings.nats_subject.clone(),
        connection_state.clone(),
    ));

    // Subscribe to user-specific subject based on sub_id from NTDF token
    let user_subject = format!("profile.{}", ntdf_claims.sub_id_hex());
    info!("Subscribing to user subject: {}", user_subject);
    let public_id_nats_task = Some(tokio::spawn(handle_nats_subscription(
        state.nats_connection.clone(),
        user_subject,
        connection_state.clone(),
    )));

    // Spawn task to forward outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            // Convert tokio_tungstenite Message to Axum WebSocket message
            let axum_msg = match msg {
                Message::Binary(data) => AxumMessage::Binary(data),
                Message::Text(text) => AxumMessage::Text(text),
                Message::Close(_) => AxumMessage::Close(None),
                _ => continue,
            };

            if ws_sender.send(axum_msg).await.is_err() {
                eprintln!("Failed to send outgoing message through WebSocket");
                break;
            }
        }
    });

    // Handle incoming WebSocket messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(msg) => {
                match msg {
                    AxumMessage::Close(_) => {
                        info!("Received a close message.");
                        break;
                    }
                    AxumMessage::Text(_text) => {
                        // JWT tokens not needed - already authenticated via NTDF
                        // Could be used for other text-based messages in the future
                    }
                    AxumMessage::Binary(data) => {
                        // Handle binary message
                        if let Some(response) = handle_binary_message(
                            &connection_state,
                            &state.server_state,
                            data,
                            state.nats_connection.clone(),
                        )
                        .await
                        {
                            // Convert tokio_tungstenite Message to Axum message and send via channel
                            let _ = connection_state.outgoing_tx.send(response);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("Error reading message: {}", e);
                break;
            }
        }
    }

    // Cancel the NATS subscription when the WebSocket connection closes
    nats_task.abort();
    if let Some(task) = public_id_nats_task {
        task.abort();
    }
    outgoing_task.abort();
}

/// Apple App Site Association handler
async fn apple_app_site_association_handler(
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    let content = {
        let read_guard = state.apple_app_site_association.read().unwrap();
        read_guard.clone()
    };

    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        content,
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with default level if RUST_LOG not set
    // Force unbuffered output to stderr for immediate log visibility
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load configuration
    let settings = load_config()?;

    // Validate configuration
    validate_config(&settings)?;

    // Initialize Redis client early (needed for chain cache and session manager)
    info!("Attempting to connect to Redis at {}", settings.redis_url);
    let redis_client = RedisClient::open(settings.redis_url.clone()).map_err(|e| {
        error!("Failed to connect to Redis server: {}", e);
        e
    })?;
    info!("Successfully connected to Redis server");

    // Initialize chain validator only if CHAIN_RPC_URL is configured
    let chain_validator: Option<Arc<dyn chain::SessionValidator>> =
        if let Some(ref chain_url) = settings.chain_rpc_url {
            info!("Initializing chain client for {}", chain_url);
            let chain_client = Arc::new(chain::ChainClient::new(chain_url.clone()));

            // Generate server secret for cache integrity (random 32 bytes)
            let mut server_secret = [0u8; 32];
            OsRng.fill_bytes(&mut server_secret);

            // Initialize session cache with 6-second TTL
            let session_cache = Arc::new(chain::SessionCache::new(
                server_secret,
                Arc::new(redis_client.clone()),
            ));

            // Create chain validator
            let validator: Arc<dyn chain::SessionValidator> =
                Arc::new(chain::ChainValidator::new(chain_client, session_cache));

            info!("Chain validation initialized (cache TTL: 6s)");
            Some(validator)
        } else {
            info!("Chain validation disabled (CHAIN_RPC_URL not set)");
            None
        };

    let server_state =
        Arc::new(ServerState::new(settings.clone(), redis_client, chain_validator.clone()).await?);
    // Load and cache the apple-app-site-association.json file
    let apple_app_site_association = load_apple_app_site_association().await;
    // Initialize KAS keys
    init_kas_keys(&settings.kas_key_path)?;

    // Get KAS keys for HTTP rewrap endpoint
    let kas_private_key_bytes = get_kas_private_key_bytes().expect("KAS keys not initialized");
    let kas_private_key_array: [u8; 32] = kas_private_key_bytes
        .try_into()
        .expect("Invalid KAS private key size");
    let kas_private_key =
        SecretKey::from_bytes(&kas_private_key_array.into()).expect("Invalid KAS private key");
    let kas_public_key = kas_private_key.public_key();
    let kas_public_key_pem = modules::crypto::public_key_to_pem(&kas_public_key)
        .expect("Failed to encode KAS public key");

    // Set up TLS if not disabled
    let tls_acceptor = if settings.tls_enabled {
        Some(load_tls_config(
            &settings.tls_cert_path,
            &settings.tls_key_path,
        )?)
    } else {
        None
    };

    // Initialize NATS connection
    let nats_connection = Arc::new(NatsConnection::new(settings.nats_url.clone()));
    // Spawn a task to handle NATS connection and reconnection
    let nats_connection_clone = nats_connection.clone();
    tokio::spawn(async move {
        loop {
            let client = nats_connection_clone.get_client().await;
            if client.is_none() {
                info!("NATS client not connected. Attempting to connect...");
                match nats_connection_clone.connect().await {
                    Ok(_) => info!("Successfully connected to NATS server"),
                    Err(e) => {
                        error!(
                            "Failed to connect to NATS server: {}. Retrying in {:?}...",
                            e, NATS_RETRY_INTERVAL
                        );
                        tokio::time::sleep(NATS_RETRY_INTERVAL).await;
                        continue;
                    }
                }
            }
            tokio::time::sleep(NATS_RETRY_INTERVAL).await;
        }
    });

    // Load OAuth public key from environment if provided
    let oauth_public_key_pem = env::var("OAUTH_PUBLIC_KEY_PATH")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok());

    if oauth_public_key_pem.is_some() {
        info!("OAuth JWT signature validation enabled");
    } else {
        info!("OAuth JWT signature validation disabled (development mode)");
    }

    // Load optional RSA key for Standard TDF support
    let (kas_rsa_private_key, kas_rsa_public_key_pem) =
        if let Ok(rsa_key_path) = env::var("KAS_RSA_KEY_PATH") {
            info!("Loading RSA key from: {}", rsa_key_path);
            match load_rsa_key(&rsa_key_path) {
                Ok((private_key, public_key_pem)) => {
                    info!("RSA key loaded successfully");
                    (Some(private_key), Some(public_key_pem))
                }
                Err(e) => {
                    error!("Failed to load RSA key: {}. RSA support disabled.", e);
                    (None, None)
                }
            }
        } else {
            info!("KAS_RSA_KEY_PATH not set. RSA support disabled (EC only).");
            (None, None)
        };

    // Create HTTP rewrap state with chain validator
    let rewrap_state = Arc::new(http_rewrap::RewrapState {
        kas_ec_private_key: kas_private_key,
        kas_ec_public_key_pem: kas_public_key_pem,
        kas_rsa_private_key,
        kas_rsa_public_key_pem,
        oauth_public_key_pem,
        chain_validator: chain_validator.clone(),
    });

    // Build optional reverse-proxy to upstream opentdf-platform.
    let proxy_mode: platform_proxy::ProxyMode = env::var("KAS_PROXY_MODE")
        .ok()
        .as_deref()
        .unwrap_or("off")
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;

    // Authorization-service forwarding (AUTHZ_PROXY=on): exposes
    // /authorization.v2.AuthorizationService/* from the upstream platform so
    // PDP delegators (the entitled-catalog endpoint on iroh.arkavo.net,
    // tdf-iroh-s3#5) can reach decisions through this host. Explicit opt-in,
    // independent of KAS_PROXY_MODE.
    let authz_proxy = matches!(
        env::var("AUTHZ_PROXY").ok().as_deref(),
        Some("on") | Some("true") | Some("1")
    );

    let needs_upstream = proxy_mode != platform_proxy::ProxyMode::Off || authz_proxy;
    let platform_proxy_state = match (env::var("OPENTDF_PLATFORM_URL").ok(), needs_upstream) {
        (Some(url), true) => {
            let state = platform_proxy::PlatformProxyState::new(&url)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            info!(
                "Platform proxy enabled: mode={:?}, authz_proxy={}, upstream={}",
                proxy_mode, authz_proxy, state.upstream_base
            );
            Some(state)
        }
        (None, true) => {
            return Err(format!(
                "KAS_PROXY_MODE={:?} / AUTHZ_PROXY={} requires OPENTDF_PLATFORM_URL to be set",
                proxy_mode, authz_proxy
            )
            .into());
        }
        _ => {
            info!("Platform proxy disabled (KAS_PROXY_MODE=off or unset)");
            None
        }
    };

    // Initialize media DRM components
    let max_concurrent_streams = env::var("MAX_CONCURRENT_STREAMS")
        .ok()
        .and_then(|s| s.parse().ok());

    let session_manager = Arc::new(session_manager::SessionManager::new(
        Arc::new(server_state.redis_client.clone()),
        max_concurrent_streams,
    ));

    let enable_media_analytics = env::var("ENABLE_MEDIA_ANALYTICS")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);

    let media_metrics_subject =
        env::var("MEDIA_METRICS_SUBJECT").unwrap_or_else(|_| "media.metrics".to_string());

    // Validate media DRM configuration
    validate_media_config(
        max_concurrent_streams.unwrap_or(5),
        &media_metrics_subject,
        enable_media_analytics,
    )?;

    let nats_client_for_metrics = nats_connection.get_client().await.map(Arc::new);
    let media_metrics = Arc::new(media_metrics::MediaMetrics::new(
        nats_client_for_metrics,
        media_metrics_subject,
        enable_media_analytics,
    ));

    // Initialize FairPlay handler if feature enabled
    #[cfg(feature = "fairplay")]
    let fairplay_handler = {
        use modules::fairplay::FairPlayHandler;
        use std::path::PathBuf;

        let credentials_path = std::env::var("FAIRPLAY_CREDENTIALS_PATH").unwrap_or_else(|_| {
            log::warn!("FAIRPLAY_CREDENTIALS_PATH not set, using default");
            "./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials"
                .to_string()
        });

        match FairPlayHandler::new(PathBuf::from(credentials_path)) {
            Ok(handler) => {
                log::info!("FairPlay handler initialized successfully");
                Arc::new(handler)
            }
            Err(e) => {
                log::error!("Failed to initialize FairPlay handler: {}", e);
                log::error!("FairPlay support will be disabled");
                Arc::new(FairPlayHandler::new(PathBuf::from(".")).unwrap())
            }
        }
    };

    // Resolve and pre-load FairPlay certificate from credentials directory.
    // Loading once at startup avoids per-request disk I/O in the cert handler.
    let fairplay_certificate_data = {
        let credentials_dir = std::env::var("FAIRPLAY_CREDENTIALS_PATH").ok();
        let cert_path = credentials_dir.as_ref().and_then(|dir| {
            let certs_json_path = std::path::Path::new(dir).join("certificates.json");
            let contents = std::fs::read_to_string(&certs_json_path).ok()?;
            let parsed: serde_json::Value = serde_json::from_str(&contents).ok()?;
            parsed["certificates"]
                .as_array()
                .and_then(|certs| certs.first())
                .and_then(|cert| cert["certificate"].as_str())
                .map(|filename| std::path::Path::new(dir).join(filename))
                .filter(|path| path.exists())
        });

        cert_path.and_then(|path| match std::fs::read(&path) {
            Ok(bytes) => {
                info!(
                    "FairPlay certificate loaded ({} bytes) from {:?}",
                    bytes.len(),
                    path
                );
                Some(Arc::new(bytes))
            }
            Err(e) => {
                warn!("Failed to read FairPlay certificate from {:?}: {}", path, e);
                None
            }
        })
    };

    let media_api_state = Arc::new(media_api::MediaApiState {
        rewrap_state: rewrap_state.clone(),
        session_manager: session_manager.clone(),
        media_metrics: media_metrics.clone(),
        #[cfg(feature = "fairplay")]
        fairplay_handler: Some(fairplay_handler),
        #[cfg(not(feature = "fairplay"))]
        fairplay_handler: None,
        chain_validator: chain_validator.clone(),
        fairplay_certificate_data,
    });

    // Initialize C2PA signing state (optional - only if configured)
    #[cfg(feature = "c2pa_signing")]
    let c2pa_signing_state = match c2pa_signing::C2paConfig::from_env() {
        Ok(config) => {
            info!("C2PA signing enabled");
            Some(Arc::new(c2pa_signing::C2paSigningState::new(config)))
        }
        Err(e) => {
            info!("C2PA signing disabled: {}", e);
            None
        }
    };

    #[cfg(not(feature = "c2pa_signing"))]
    let _c2pa_signing_state: Option<Arc<()>> = None;

    use axum::{
        routing::{delete, get, post},
        Router,
    };

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

    // Platform discovery — `/.well-known/opentdf-configuration` is published by
    // the upstream platform and lists its endpoints/keys. Forward whenever any
    // proxying is on so clients see the authoritative document.
    let wellknown_router = if proxy_mode.forwards_discovery() {
        let state = platform_proxy_state
            .clone()
            .expect("platform_proxy_state must exist when forwards_discovery()");
        Router::new()
            .route(
                "/.well-known/opentdf-configuration",
                get(platform_proxy::proxy),
            )
            // Public attribute discovery served from the upstream platform's
            // policy snapshot (single source of truth). Attribute FQNs
            // (https://<namespace>/attr/...) dereference through this host
            // when the namespace DNS points here.
            .route("/attributes", get(platform_proxy::proxy))
            .route("/attr/*rest", get(platform_proxy::proxy))
            .with_state(state)
    } else {
        Router::new()
    };

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

    // Authorization service forwarding — decisions stay platform-evaluated;
    // arks only relays. The platform's own authn governs access.
    let authz_router = if authz_proxy {
        let state = platform_proxy_state
            .clone()
            .expect("platform_proxy_state must exist when authz_proxy");
        Router::new()
            .route(
                "/authorization.v2.AuthorizationService/*method",
                post(platform_proxy::proxy),
            )
            .with_state(state)
    } else {
        Router::new()
    };

    // Media DRM router
    let media_router = Router::new()
        .route("/media/v1/key-request", post(media_api::media_key_request))
        .route(
            "/media/v1/certificate",
            get(media_api::fairplay_certificate),
        )
        .route("/media/v1/session/start", post(media_api::session_start))
        .route(
            "/media/v1/session/:session_id/heartbeat",
            post(media_api::session_heartbeat),
        )
        .route(
            "/media/v1/session/:session_id",
            delete(media_api::session_terminate),
        )
        .with_state(media_api_state);

    // C2PA signing router (optional - only if configured)
    #[cfg(feature = "c2pa_signing")]
    let c2pa_router = if let Some(c2pa_state) = c2pa_signing_state {
        Router::new()
            .route("/c2pa/v1/sign", post(c2pa_signing::sign_manifest))
            .route("/c2pa/v1/validate", post(c2pa_signing::validate_manifest))
            .with_state(c2pa_state)
    } else {
        Router::new() // Empty router if C2PA not configured
    };

    #[cfg(not(feature = "c2pa_signing"))]
    let c2pa_router = Router::new(); // Empty router if C2PA feature disabled

    // Create WebSocket state for /ws route
    let ws_state = Arc::new(WebSocketState {
        server_state: server_state.clone(),
        nats_connection: nats_connection.clone(),
        apple_app_site_association: apple_app_site_association.clone(),
    });

    // Combine all routers
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_app_site_association_handler),
        )
        .with_state(ws_state)
        .merge(opentdf_router)
        .merge(wellknown_router)
        .merge(connect_router)
        .merge(authz_router)
        .merge(media_router)
        .merge(c2pa_router)
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(log_request_middleware)),
        );

    // HTTP/3 (feature-gated). The H3 server serves the base `app`; the TCP `app`
    // gets an Alt-Svc layer advertising h3 so HTTP/1.1/2 clients can upgrade.
    // Alt-Svc is only meaningful to a TCP client, so the H3 path omits it.
    #[cfg(feature = "http3")]
    let h3_app_base = app.clone();

    #[cfg(feature = "http3")]
    let app = {
        let alt_svc = modules::h3::alt_svc_header_value(settings.port);
        app.layer(axum::middleware::map_response(
            move |mut res: axum::response::Response| {
                let alt_svc = alt_svc.clone();
                async move {
                    res.headers_mut()
                        .insert(axum::http::header::ALT_SVC, alt_svc);
                    res
                }
            },
        ))
    };

    // Start RTMP server if RTMP_PORT is configured
    if let Ok(rtmp_port_str) = env::var("RTMP_PORT") {
        let rtmp_port: u16 = rtmp_port_str.parse().unwrap_or(1935);
        let rtmp_redis_client = Arc::new(server_state.redis_client.clone());
        let rtmp_kas_key = kas_private_key_array;

        // Get NATS client for stream event broadcasting
        let rtmp_nats_client = nats_connection.get_client().await;
        let rtmp_base_url =
            env::var("RTMP_BASE_URL").unwrap_or_else(|_| format!("rtmp://localhost:{}", rtmp_port));

        // Create stream event broadcaster
        let event_broadcaster = Arc::new(modules::rtmp::StreamEventBroadcaster::new(
            rtmp_nats_client,
            settings.nats_subject.clone(),
            rtmp_base_url,
        ));

        tokio::spawn(async move {
            let rtmp_server = modules::rtmp::RtmpServer::with_broadcaster(
                rtmp_port,
                rtmp_redis_client,
                rtmp_kas_key,
                event_broadcaster,
            );
            if let Err(e) = rtmp_server.run().await {
                error!("RTMP server error: {}", e);
            }
        });
        info!("NTDF-RTMP server started on port {}", rtmp_port);
    }

    // Set up unified server on single port
    let addr = format!("0.0.0.0:{}", settings.port);
    info!("Starting unified server (HTTP + WebSocket) on {}", addr);

    // Serve with or without TLS
    if let Some(tls_acceptor) = tls_acceptor {
        // TLS enabled - manual accept loop with per-connection TLS handshake
        // This avoids axum-server's synchronous TLS accept which can deadlock
        // if any client stalls during handshake.
        info!("TLS enabled - using rustls (async accept)");

        // Spawn the HTTP/3 (QUIC) listener on the same port (UDP). Serves the
        // base router (no Alt-Svc). Requires UDP ingress to be open on the port.
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

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        loop {
            let (tcp_stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    continue;
                }
            };
            let tls_acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                // TLS handshake with 10-second timeout - never blocks the accept loop
                let tls_stream = match tokio::time::timeout(
                    Duration::from_secs(10),
                    tls_acceptor.accept(tcp_stream),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        error!("TLS handshake failed from {}: {}", remote_addr, e);
                        return;
                    }
                    Err(_) => {
                        warn!("TLS handshake timeout from {}", remote_addr);
                        return;
                    }
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);

                let hyper_service = hyper::service::service_fn(
                    move |mut request: hyper::Request<hyper::body::Incoming>| {
                        // Inject ConnectInfo so handlers can extract the client address
                        request
                            .extensions_mut()
                            .insert(axum::extract::ConnectInfo(remote_addr));
                        let tower_service = app.clone();
                        async move { tower_service.oneshot(request).await }
                    },
                );

                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(io, hyper_service)
                .await
                {
                    let err_str = e.to_string();
                    if !err_str.contains("reset")
                        && !err_str.contains("closed")
                        && !err_str.contains("shutting down")
                    {
                        error!("HTTP connection error from {}: {}", remote_addr, e);
                    }
                }
            });
        }
    } else {
        // TLS disabled - plain HTTP
        info!("TLS disabled - using plain HTTP");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let config = load_rustls_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    Ok(acceptor)
}

fn load_rustls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use std::io::BufReader;

    info!("Loading TLS configuration...");
    info!("Certificate path: {}", cert_path);
    info!("Key path: {}", key_path);

    // Load certificates
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
        certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    info!(
        "Certificate chain loaded: {} certificates",
        cert_chain.len()
    );

    // Load private key
    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;

    if keys.is_empty() {
        return Err("No private keys found in key file".into());
    }

    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0));
    info!("Private key loaded successfully");

    // Create rustls server configuration
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("Failed to create TLS config: {}", e))?;

    // Negotiate HTTP/2 for REST clients while keeping HTTP/1.1 for the WebSocket
    // upgrade (/ws). Without ALPN, clients silently fall back to HTTP/1.1 only.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    info!("TLS configuration created successfully");
    Ok(config)
}

// Old handle_websocket and handle_connection functions removed - replaced by handle_websocket_axum

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    age: String,
}

fn verify_token(
    token: &str,
    settings: &ServerSettings,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    if settings.jwt_validation_disabled {
        // Development mode - disable signature validation
        log::warn!(
            "⚠️  JWT signature validation is DISABLED - for development only! \
             Set JWT_VALIDATION_DISABLED=false for production."
        );
        let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(token)?;
        Ok(token_data.claims)
    } else {
        // Production mode - proper JWT validation
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_aud = false; // Can be enabled if audience is specified

        // Load the public key for verification
        let public_key_path = settings.jwt_public_key_path.as_ref().ok_or_else(|| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)
        })?;

        let public_key_pem = std::fs::read_to_string(public_key_path).map_err(|e| {
            error!(
                "Failed to read JWT public key from {}: {}",
                public_key_path, e
            );
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)
        })?;

        // Support both RSA and ECDSA keys
        let decoding_key = if public_key_pem.contains("BEGIN RSA PUBLIC KEY")
            || public_key_pem.contains("BEGIN PUBLIC KEY")
        {
            validation.algorithms = vec![
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::RS384,
                jsonwebtoken::Algorithm::RS512,
            ];
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?
        } else if public_key_pem.contains("BEGIN EC PUBLIC KEY") {
            validation.algorithms = vec![
                jsonwebtoken::Algorithm::ES256,
                jsonwebtoken::Algorithm::ES384,
            ];
            DecodingKey::from_ec_pem(public_key_pem.as_bytes())?
        } else {
            error!("Unsupported JWT public key format");
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidKeyFormat,
            ));
        };

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        info!(
            "JWT signature verified successfully for subject: {}",
            token_data.claims.sub
        );
        Ok(token_data.claims)
    }
}

async fn handle_binary_message(
    connection_state: &Arc<ConnectionState>,
    server_state: &Arc<ServerState>,
    data: Vec<u8>,
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    if data.is_empty() {
        println!("Invalid message format");
        return None;
    }
    let message_type = MessageType::from_u8(data[0]);
    let payload = &data[1..data.len()];

    match message_type {
        Some(MessageType::PublicKey) => handle_public_key(connection_state, payload).await, // incoming
        Some(MessageType::KasPublicKey) => handle_kas_public_key(payload).await, // outgoing
        Some(MessageType::Rewrap) => {
            handle_rewrap(connection_state, payload, &server_state.settings).await
        } // incoming
        Some(MessageType::RewrappedKey) => None,                                 // outgoing
        Some(MessageType::Nats) => {
            handle_nats_publish(
                connection_state,
                payload,
                &server_state.settings,
                nats_connection,
            )
            .await
        } // internal
        Some(MessageType::Event) => handle_event(server_state, payload, nats_connection).await, // embedded
        Some(MessageType::Cbor) => {
            handle_cbor_message(connection_state, server_state, payload).await
        }
        Some(MessageType::Error) => {
            // Error messages are sent from server to client, not received
            error!("Received unexpected Error message type from client");
            None
        }
        None => {
            // Unknown message type
            None
        }
    }
}

async fn handle_nats_publish(
    _: &Arc<ConnectionState>,
    payload: &[u8],
    settings: &ServerSettings,
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    match NATSMessage::new(payload) {
        Ok(nanotdf_msg) => {
            // Check if NATS client is available before attempting to send
            if let Some(nats_client) = nats_connection.get_client().await {
                if let Err(e) = nanotdf_msg
                    .send_to_nats(&nats_client, settings.nats_subject.clone())
                    .await
                {
                    error!("Failed to send NanoTDF message to NATS: {}", e);
                } else {
                    info!("NanoTDF message sent to NATS successfully");
                }
            } else {
                error!("NATS client not available - message not sent");
            }
        }
        Err(e) => {
            error!("Failed to create NanoTDFMessage: {}", e);
        }
    }
    None
}

async fn handle_rewrap(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
    settings: &ServerSettings,
) -> Option<Message> {
    // Validate payload size before processing
    if payload.len() > MAX_NANOTDF_SIZE {
        error!(
            "Rewrap request exceeds maximum size: {} bytes (max: {} bytes)",
            payload.len(),
            MAX_NANOTDF_SIZE
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Rewrap request exceeds maximum size: {} bytes (max: {} bytes)",
                payload.len(),
                MAX_NANOTDF_SIZE
            ))
            .to_message(),
        );
    }

    // timing
    let start_time = Instant::now();
    // session shared secret
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret_lock.read().unwrap();
        shared_secret.clone()
    };
    if session_shared_secret.is_none() {
        error!("Rewrap attempted before key agreement - no session secret");
        return Some(
            ErrorResponse::invalid_format("Session not established - perform key agreement first")
                .to_message(),
        );
    }
    let session_shared_secret = session_shared_secret.unwrap();
    // Parse NanoTDF header
    let mut parser = BinaryParser::new(payload);
    let header = match BinaryParser::parse_header(&mut parser) {
        Ok(header) => header,
        Err(e) => {
            error!("Failed to parse NanoTDF header: {:?}", e);
            return Some(
                ErrorResponse::invalid_format(format!("Invalid NanoTDF header: {}", e))
                    .to_message(),
            );
        }
    };
    // timing
    let parse_time = start_time.elapsed();
    log_timing(settings, "Time to parse header", parse_time);
    // TDF ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    if tdf_ephemeral_key_bytes.len() != 33 {
        error!(
            "Invalid NanoTDF ephemeral key length: {} (expected 33)",
            tdf_ephemeral_key_bytes.len()
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Invalid ephemeral key size: {} bytes",
                tdf_ephemeral_key_bytes.len()
            ))
            .to_message(),
        );
    }
    // TDF contract
    let policy = header.get_policy();
    // println!("policy: {:?}", policy);
    let locator: Option<ResourceLocator>;
    let policy_body: Option<&[u8]> = None;
    let mut metadata: Option<Metadata> = None;

    match policy.policy_type {
        PolicyType::Remote => {
            info!("Processing remote policy");
            locator = policy.get_locator().clone();

            // Fetch remote policy if HTTP/HTTPS URL
            if let Some(ref loc) = locator {
                if loc.protocol_enum == ProtocolEnum::Http
                    || loc.protocol_enum == ProtocolEnum::Https
                {
                    info!("Fetching remote policy from: {}", loc.body);
                    // TODO: Implement actual HTTP fetch of remote policy
                    // For now, return error indicating feature not complete
                    error!("Remote policy fetching not yet implemented");
                    return Some(
                        ErrorResponse::invalid_format(
                            "Remote policy fetching via HTTP/HTTPS not yet implemented",
                        )
                        .to_message(),
                    );

                    // Future implementation:
                    // match reqwest::get(&loc.body).await {
                    //     Ok(response) => {
                    //         match response.bytes().await {
                    //             Ok(bytes) => {
                    //                 metadata = match root_as_metadata(&bytes) {
                    //                     Ok(meta) => Some(meta),
                    //                     Err(e) => {
                    //                         error!("Failed to parse remote policy metadata: {}", e);
                    //                         return Some(
                    //                             ErrorResponse::invalid_format(format!(
                    //                                 "Invalid remote policy metadata: {}",
                    //                                 e
                    //                             ))
                    //                             .to_message(),
                    //                         );
                    //                     }
                    //                 };
                    //             }
                    //             Err(e) => {
                    //                 error!("Failed to read remote policy response: {}", e);
                    //                 return Some(
                    //                     ErrorResponse::invalid_format(format!(
                    //                         "Failed to fetch remote policy: {}",
                    //                         e
                    //                     ))
                    //                     .to_message(),
                    //                 );
                    //             }
                    //         }
                    //     }
                    //     Err(e) => {
                    //         error!("Failed to fetch remote policy: {}", e);
                    //         return Some(
                    //             ErrorResponse::invalid_format(format!(
                    //                 "Failed to fetch remote policy: {}",
                    //                 e
                    //             ))
                    //             .to_message(),
                    //         );
                    //     }
                    // }
                }
            }
        }
        PolicyType::Embedded => {
            info!("Processing embedded policy");
            if let Some(body) = &policy.body {
                info!("Metadata buffer size: {}", body.len());
                metadata = match root_as_metadata(body) {
                    Ok(metadata) => Some(metadata),
                    Err(e) => {
                        error!("Failed to parse embedded policy metadata: {}", e);
                        return Some(
                            ErrorResponse::invalid_format(format!(
                                "Invalid embedded policy metadata: {}",
                                e
                            ))
                            .to_message(),
                        );
                    }
                };
                info!("Parsed metadata: {:#?}", metadata);

                // For embedded policies with rating metadata, infer content rating contract
                // TODO: Add contract_id field to metadata schema or use policy binding
                // to explicitly specify which contract to use
                if let Some(ref meta) = metadata {
                    if meta.rating().is_some() {
                        locator = Some(ResourceLocator {
                            protocol_enum: ProtocolEnum::SharedResource,
                            body: "5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB".to_string(),
                        });
                        info!("Inferred content rating contract from metadata");
                    } else {
                        // Metadata present but no rating - no contract enforcement
                        locator = None;
                        info!("No rating in metadata - skipping contract enforcement");
                    }
                } else {
                    locator = None;
                }
            } else {
                locator = None;
            }
        }
    }

    // Verify policy binding if present
    // Policy binding ensures integrity of the policy by cryptographically binding it
    // to either an ECDSA signature or GMAC tag
    if let Some(binding_bytes) = policy.get_binding() {
        info!("Policy binding present ({} bytes)", binding_bytes.len());

        let ecc_mode = header.get_ecc_mode();

        // Validate binding format based on binding type
        if ecc_mode.use_ecdsa_binding {
            // ECDSA binding - validate signature format
            let expected_size = match ecc_mode.ephemeral_ecc_params_enum {
                nanotdf::ECDSAParams::Secp256r1 | nanotdf::ECDSAParams::Secp256k1 => 64,
                nanotdf::ECDSAParams::Secp384r1 => 96,
                nanotdf::ECDSAParams::Secp521r1 => 132,
            };

            if binding_bytes.len() != expected_size {
                error!(
                    "Invalid ECDSA binding size: {} bytes (expected {} for {:?})",
                    binding_bytes.len(),
                    expected_size,
                    ecc_mode.ephemeral_ecc_params_enum
                );
                return Some(
                    ErrorResponse::invalid_format(format!(
                        "Invalid policy binding signature size: {} bytes (expected {})",
                        binding_bytes.len(),
                        expected_size
                    ))
                    .to_message(),
                );
            }

            info!(
                "ECDSA policy binding format validated ({:?})",
                ecc_mode.ephemeral_ecc_params_enum
            );

            // For full ECDSA verification, we need the public key from the policy authority
            // This would typically be:
            // 1. Embedded in the policy metadata as a JWK or raw bytes
            // 2. Retrieved from a trusted authority/certificate
            // 3. Derived from a known policy signing key
            //
            // Without the public key, we can only validate format
            log::warn!(
                "ECDSA policy binding signature format valid, but cryptographic verification \
                 requires policy authority public key (not implemented)"
            );
        } else {
            // GMAC binding - validate tag size
            if binding_bytes.len() != 16 {
                error!(
                    "Invalid GMAC binding size: {} bytes (expected 16)",
                    binding_bytes.len()
                );
                return Some(
                    ErrorResponse::invalid_format(format!(
                        "Invalid policy binding GMAC tag size: {} bytes (expected 16)",
                        binding_bytes.len()
                    ))
                    .to_message(),
                );
            }

            info!("GMAC policy binding format validated");

            // GMAC verification requires the symmetric key derived during rewrap
            // The GMAC tag is computed over the policy bytes using the payload key
            // We'll verify this later in the rewrap process after deriving the key
            log::warn!(
                "GMAC policy binding tag format valid, but cryptographic verification \
                 requires payload key (deferred to rewrap)"
            );
        }
    } else {
        info!("No policy binding present");
    }

    if let Some(locator) = &locator {
        if locator.protocol_enum == ProtocolEnum::SharedResource {
            info!("Evaluating contract: {}", locator.body.clone());
            if !locator.body.is_empty() {
                //  "Verified 18+"
                let claims_result = match connection_state.claims_lock.read() {
                    Ok(read_lock) => match read_lock.clone() {
                        Some(value) => Ok(value.sub),
                        None => Err("Error: Clone cannot be performed"),
                    },
                    Err(_) => Err("Error: Read lock cannot be obtained"),
                };
                let verified_age_result = match connection_state
                    .claims_lock
                    .read()
                    .expect("Error: Read lock cannot be obtained")
                    .clone()
                {
                    Some(claims) => Ok(claims.age == "Verified 18+"),
                    None => Err("Error: Claims data not available"),
                };
                // geo_fence_contract
                if locator
                    .body
                    .contains("5H6sLwXKBv3cdm5VVRxrvA8p5cux2Rrni5CQ4GRyYKo4b9B4")
                {
                    info!("Processing geofence contract");
                    let _contract = geo_fence_contract::geo_fence_contract::GeoFenceContract::new();

                    // Parse geofence bounds from policy body
                    // Expected format: 6 f64 values (48 bytes total)
                    // min_lat, max_lat, min_lon, max_lon, min_alt, max_alt
                    let _geofence = if let Some(body) = policy_body {
                        if body.len() >= 48 {
                            // Parse 6 f64 values from little-endian bytes
                            let mut values = [0f64; 6];
                            for (i, value) in values.iter_mut().enumerate() {
                                let start = i * 8;
                                let bytes = &body[start..start + 8];
                                *value = f64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8]));
                            }
                            Geofence3D {
                                min_latitude: values[0],
                                max_latitude: values[1],
                                min_longitude: values[2],
                                max_longitude: values[3],
                                min_altitude: values[4],
                                max_altitude: values[5],
                            }
                        } else {
                            error!(
                                "Policy body too small for geofence data: {} bytes (expected 48)",
                                body.len()
                            );
                            return Some(
                                ErrorResponse::invalid_format(
                                    "Geofence policy body must contain 48 bytes (6 f64 values)",
                                )
                                .to_message(),
                            );
                        }
                    } else {
                        error!("Geofence policy missing body data");
                        return Some(
                            ErrorResponse::invalid_format("Geofence policy requires body data")
                                .to_message(),
                        );
                    };

                    // Extract coordinates from JWT claims
                    // TODO: Add latitude/longitude/altitude fields to Claims struct
                    // For now, return error indicating feature not complete
                    error!("Geofence coordinate extraction from JWT claims not yet implemented");
                    return Some(
                        ErrorResponse::invalid_format(
                            "Geofence validation requires location fields in JWT claims (feature incomplete)",
                        )
                        .to_message(),
                    );

                    // Future implementation once Claims struct has location fields:
                    // let coordinate = match connection_state.claims_lock.read() {
                    //     Ok(read_lock) => match read_lock.clone() {
                    //         Some(claims) => geo_fence_contract::geo_fence_contract::Coordinate3D {
                    //             latitude: claims.latitude,
                    //             longitude: claims.longitude,
                    //             altitude: claims.altitude,
                    //         },
                    //         None => {
                    //             return Some(ErrorResponse::policy_denied(
                    //                 "Geofence validation requires authentication"
                    //             ).to_message());
                    //         }
                    //     },
                    //     Err(_) => {
                    //         return Some(ErrorResponse::policy_denied(
                    //             "Failed to read authentication claims"
                    //         ).to_message());
                    //     }
                    // };
                    //
                    // if !contract.is_within_geofence(geofence, coordinate) {
                    //     error!("Geofence policy denied access - location outside allowed area");
                    //     let total_time = start_time.elapsed();
                    //     log_timing(settings, "Time to deny (geofence)", total_time);
                    //     return Some(
                    //         ErrorResponse::policy_denied(
                    //             "Access denied - location outside permitted geofence",
                    //         )
                    //         .to_message(),
                    //     );
                    // }
                    // info!("Geofence validation passed");
                }
                // content_rating
                else if locator
                    .body
                    .contains("5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB")
                {
                    println!("contract content rating");
                    let contract = ContentRating::new();
                    // Parse the content rating data from the policy body
                    // get entitlements
                    let age_level = if verified_age_result.unwrap_or(false) {
                        AgeLevel::Adults
                    } else {
                        AgeLevel::Kids
                    };
                    if metadata.is_none() {
                        println!("metadata is null");
                        return None;
                    }
                    let rating_data = metadata.unwrap().rating()?;
                    let rating = Rating {
                        violent: convert_rating_level(rating_data.violent()),
                        sexual: convert_rating_level(rating_data.sexual()),
                        profane: convert_rating_level(rating_data.profane()),
                        substance: convert_rating_level(rating_data.substance()),
                        hate: convert_rating_level(rating_data.hate()),
                        harm: convert_rating_level(rating_data.harm()),
                        mature: convert_rating_level(rating_data.mature()),
                        bully: convert_rating_level(rating_data.bully()),
                    };
                    // Format age level before check_content consumes it
                    let age_level_str = format!("{:?}", age_level);
                    if !contract.check_content(age_level, rating) {
                        error!(
                            "Content rating policy denied access for age level: {}",
                            age_level_str
                        );
                        return Some(
                            ErrorResponse::policy_denied(format!(
                                "Content not suitable for age level: {}",
                                age_level_str
                            ))
                            .to_message(),
                        );
                    }
                }
                // simple_abac
                else if locator
                    .body
                    .contains("5Cqk3ERPToSMuY8UoKJtcmo4fs1iVyQpq6ndzWzpzWezAF1W")
                {
                    let contract = contract_simple_abac::simple_abac::SimpleAbac::new();
                    if claims_result.is_ok()
                        && !contract.check_access(claims_result.unwrap(), locator.body.clone())
                    {
                        error!("ABAC policy denied access for user claims");
                        // timing
                        let total_time = start_time.elapsed();
                        log_timing(settings, "Time to deny (ABAC)", total_time);
                        return Some(
                            ErrorResponse::policy_denied(
                                "Access denied by attribute-based access control policy",
                            )
                            .to_message(),
                        );
                    }
                }
            }
        }
    }
    // Deserialize the public key sent by the client
    let tdf_ephemeral_public_key = match PublicKey::from_sec1_bytes(tdf_ephemeral_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            info!("Error deserializing TDF ephemeral public key: {:?}", e);
            return None;
        }
    };
    // KAS key
    let kas_private_key_bytes = get_kas_private_key_bytes().unwrap();
    let kas_private_key_array: [u8; 32] = match kas_private_key_bytes.try_into() {
        Ok(key) => key,
        Err(_) => return None,
    };
    let kas_private_key = SecretKey::from_bytes(&kas_private_key_array.into())
        .map_err(|_| "Invalid private key")
        .ok()?;

    // Perform custom ECDH
    let ecdh_start = Instant::now();
    let dek_shared_secret_bytes = match custom_ecdh(&kas_private_key, &tdf_ephemeral_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            info!("Error performing ECDH: {:?}", e);
            return None;
        }
    };
    let ecdh_time = ecdh_start.elapsed();
    log_timing(settings, "Time for ECDH operation", ecdh_time);

    // Determine HKDF salt based on NanoTDF version
    let dek_salt = if let Some(version) = detect_nanotdf_version(payload) {
        compute_nanotdf_salt(version)
    } else {
        // Fallback to v12 for backward compatibility
        compute_nanotdf_salt(NanoTdfVersion::V12)
    };
    // Session salt is always v1.2 (matches Go reference KAS and all SDK clients)
    let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

    // Use NanoTDF-compatible HKDF: empty info parameter per spec section 4
    let info = b"";

    let encryption_start = Instant::now();
    let (nonce_vec, wrapped_dek) = match rewrap_dek(
        &dek_shared_secret_bytes,
        &session_shared_secret,
        &dek_salt,
        &session_salt,
        info,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Rewrap DEK failed: {}", e);
            return Some(
                ErrorResponse::crypto_error(format!("Failed to rewrap key: {}", e)).to_message(),
            );
        }
    };
    let encryption_time = encryption_start.elapsed();
    log_timing(settings, "Time for AES-GCM encryption", encryption_time);

    // binary response
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.extend_from_slice(tdf_ephemeral_key_bytes);
    response_data.extend_from_slice(&nonce_vec);
    response_data.extend_from_slice(&wrapped_dek);

    let total_time = start_time.elapsed();
    log_timing(settings, "Total time for handle_rewrap", total_time);

    Some(Message::Binary(response_data))
}

/// Handle CBOR-encoded messages (0x08 type prefix).
///
/// Supports chain-validated rewrap and other CBOR message types.
async fn handle_cbor_message(
    connection_state: &Arc<ConnectionState>,
    server_state: &Arc<ServerState>,
    payload: &[u8],
) -> Option<Message> {
    use cbor_protocol::CborRequest;

    // Decode CBOR request
    let request = match CborRequest::decode(payload) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to decode CBOR message: {}", e);
            return Some(cbor_error_response(
                "invalid_format",
                &format!("Failed to decode CBOR: {}", e),
            ));
        }
    };

    info!(
        "Received CBOR message: {:?}",
        std::mem::discriminant(&request)
    );

    match request {
        CborRequest::ChainRewrap { header, chain } => {
            handle_chain_rewrap(connection_state, server_state, &header, chain).await
        }
        CborRequest::KeyExchange { public_key } => {
            handle_cbor_key_exchange(connection_state, &public_key).await
        }
        CborRequest::MediaKeyRequest { .. } => {
            // Media key requests should go through HTTP API for now
            Some(cbor_error_response(
                "not_implemented",
                "Media key requests should use HTTP API /media/v1/key-request",
            ))
        }
        CborRequest::UserEvent { .. }
        | CborRequest::CacheEvent { .. }
        | CborRequest::RouteEvent { .. } => {
            // Events can be handled through the existing FlatBuffer path
            // or we can implement CBOR event handling later
            Some(cbor_error_response(
                "not_implemented",
                "Event types not yet implemented in CBOR protocol",
            ))
        }
    }
}

/// Handle chain-validated rewrap via CBOR.
async fn handle_chain_rewrap(
    connection_state: &Arc<ConnectionState>,
    server_state: &Arc<ServerState>,
    header: &[u8],
    chain: cbor_protocol::ChainValidation,
) -> Option<Message> {
    use cbor_protocol::{CborResponse, CBOR_MESSAGE_TYPE};
    use nanotdf::chain::{ChainValidationRequest, ValidationError};

    let start_time = Instant::now();

    // 1. Validate session is established
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret_lock.read().unwrap();
        shared_secret.clone()
    };
    let session_shared_secret = match session_shared_secret {
        Some(secret) => secret,
        None => {
            error!("Chain rewrap attempted before key agreement");
            return Some(cbor_error_response(
                "invalid_request",
                "Session not established - perform key agreement first",
            ));
        }
    };

    // 2. Perform chain validation
    let chain_validator = match server_state.chain_validator.as_ref() {
        Some(v) => v,
        None => {
            error!("Chain validation not configured");
            return Some(cbor_error_response(
                "internal_error",
                "Chain validation not configured on server",
            ));
        }
    };

    // Parse session_id from bytes to hex string for validation request
    if chain.session_id.len() != 32 {
        error!(
            "Invalid chain session_id length: {} (expected 32)",
            chain.session_id.len()
        );
        return Some(cbor_error_response(
            "invalid_request",
            "chain.session_id must be 32 bytes",
        ));
    }

    // DPoP Header Binding: Verify client-provided header_hash matches server computation
    let server_header_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(header).into()
    };

    // Verify header_hash is correct length
    if chain.header_hash.len() != 32 {
        error!(
            "Invalid header_hash length: {} (expected 32)",
            chain.header_hash.len()
        );
        return Some(cbor_error_response(
            "invalid_request",
            "header_hash must be exactly 32 bytes",
        ));
    }
    let client_header_hash: [u8; 32] = chain.header_hash.clone().try_into().unwrap();

    // Critical security check: client's header_hash must match server-computed hash
    // This binds the signature to the actual header content (DPoP-style binding)
    if client_header_hash != server_header_hash {
        error!(
            "Header hash mismatch: client={} server={}",
            hex::encode(client_header_hash),
            hex::encode(server_header_hash)
        );
        return Some(cbor_error_response(
            "authentication_failed",
            "header_hash does not match actual header content",
        ));
    }

    // Build validation request with verified header_hash
    let validation_request = ChainValidationRequest {
        session_id: hex::encode(&chain.session_id),
        header_hash: server_header_hash, // Use server-computed (verified) hash
        resource_id: hex::encode(server_header_hash), // Keep for logging
        signature: chain.signature.clone(),
        algorithm: chain.algorithm.clone(),
        nonce: chain.nonce,
    };

    match chain_validator.validate(&validation_request).await {
        Ok(validated) => {
            info!(
                "Chain validation passed for session {}, scope {}",
                hex::encode(validated.grant.session_id),
                hex::encode(validated.grant.scope_id)
            );
        }
        Err(e) => {
            log::warn!("Chain validation failed: {:?}", e);
            let (code, message) = match e {
                ValidationError::SessionNotFound { session_id } => (
                    "policy_denied",
                    format!("Session not found: {}", session_id),
                ),
                ValidationError::SessionExpired {
                    expired_at,
                    current,
                } => (
                    "policy_denied",
                    format!(
                        "Session expired at block {} (current: {})",
                        expired_at, current
                    ),
                ),
                ValidationError::SessionRevoked => {
                    ("policy_denied", "Session has been revoked".to_string())
                }
                ValidationError::SignatureInvalid { reason } => (
                    "authentication_failed",
                    format!("Invalid signature: {}", reason),
                ),
                ValidationError::NonceReplay => (
                    "authentication_failed",
                    "Nonce already used (replay attack detected)".to_string(),
                ),
                ValidationError::ScopeMismatch { resource_id } => (
                    "policy_denied",
                    format!("Resource {} not in session scope", resource_id),
                ),
                ValidationError::HeaderHashMismatch { client, server } => (
                    "authentication_failed",
                    format!("Header hash mismatch: client={}, server={}", client, server),
                ),
                ValidationError::Chain(chain_err) => (
                    "internal_error",
                    format!("Chain query failed: {}", chain_err),
                ),
                ValidationError::Crypto(err) => {
                    ("internal_error", format!("Crypto error: {}", err))
                }
            };
            return Some(cbor_error_response(code, &message));
        }
    }

    // 3. Parse NanoTDF header and perform rewrap
    let mut parser = BinaryParser::new(header);
    let parsed_header = match parser.parse_header() {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse NanoTDF header: {:?}", e);
            return Some(cbor_error_response(
                "invalid_format",
                &format!("Invalid NanoTDF header: {}", e),
            ));
        }
    };

    let tdf_ephemeral_key_bytes = parsed_header.get_ephemeral_key();
    if tdf_ephemeral_key_bytes.len() != 33 {
        error!(
            "Invalid ephemeral key size: {} (expected 33)",
            tdf_ephemeral_key_bytes.len()
        );
        return Some(cbor_error_response(
            "invalid_format",
            &format!(
                "Invalid ephemeral key size: {} bytes",
                tdf_ephemeral_key_bytes.len()
            ),
        ));
    }

    let tdf_ephemeral_public_key = match PublicKey::from_sec1_bytes(tdf_ephemeral_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to parse TDF ephemeral key: {:?}", e);
            return Some(cbor_error_response(
                "invalid_format",
                "Invalid TDF ephemeral public key",
            ));
        }
    };

    // 4. Perform ECDH and rewrap
    let kas_private_key_bytes = match get_kas_private_key_bytes() {
        Some(bytes) => bytes,
        None => {
            error!("KAS private key not available");
            return Some(cbor_error_response(
                "internal_error",
                "KAS private key not configured",
            ));
        }
    };

    let kas_private_key_array: [u8; 32] = match kas_private_key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            error!("Invalid KAS private key size");
            return Some(cbor_error_response(
                "internal_error",
                "Invalid KAS private key",
            ));
        }
    };

    let kas_private_key = match SecretKey::from_bytes(&kas_private_key_array.into()) {
        Ok(key) => key,
        Err(_) => {
            error!("Failed to create KAS secret key");
            return Some(cbor_error_response(
                "internal_error",
                "Invalid KAS private key",
            ));
        }
    };

    let dek_shared_secret_bytes = match custom_ecdh(&kas_private_key, &tdf_ephemeral_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            error!("ECDH failed: {:?}", e);
            return Some(cbor_error_response(
                "internal_error",
                &format!("Key agreement failed: {}", e),
            ));
        }
    };

    // Determine HKDF salt based on NanoTDF version
    let dek_salt = if let Some(version) = detect_nanotdf_version(header) {
        compute_nanotdf_salt(version)
    } else {
        compute_nanotdf_salt(NanoTdfVersion::V12)
    };
    // Session salt is always v1.2 (matches Go reference KAS and all SDK clients)
    let session_salt = compute_nanotdf_salt(NanoTdfVersion::V12);

    let (nonce_vec, wrapped_dek) = match rewrap_dek(
        &dek_shared_secret_bytes,
        &session_shared_secret,
        &dek_salt,
        &session_salt,
        b"", // Empty info per NanoTDF spec
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to rewrap DEK: {}", e);
            return Some(cbor_error_response(
                "internal_error",
                &format!("Failed to rewrap key: {}", e),
            ));
        }
    };

    let total_time = start_time.elapsed();
    info!(
        "Chain rewrap completed in {:?} for session {}",
        total_time,
        hex::encode(&chain.session_id)
    );

    // 5. Build CBOR response
    let response = CborResponse::RewrappedKey {
        ephemeral_key: tdf_ephemeral_key_bytes.to_vec(),
        nonce: nonce_vec.clone(),
        wrapped_dek: wrapped_dek.clone(),
    };

    match response.encode() {
        Ok(cbor_bytes) => {
            let mut response_data = Vec::with_capacity(1 + cbor_bytes.len());
            response_data.push(CBOR_MESSAGE_TYPE);
            response_data.extend_from_slice(&cbor_bytes);
            Some(Message::Binary(response_data))
        }
        Err(e) => {
            error!("Failed to encode CBOR response: {}", e);
            Some(cbor_error_response(
                "internal_error",
                "Failed to encode response",
            ))
        }
    }
}

/// Handle CBOR key exchange request.
async fn handle_cbor_key_exchange(
    connection_state: &Arc<ConnectionState>,
    public_key: &[u8],
) -> Option<Message> {
    use cbor_protocol::{CborResponse, CBOR_MESSAGE_TYPE};

    // Check if session already established
    {
        let shared_secret_lock = connection_state.shared_secret_lock.read();
        let shared_secret = shared_secret_lock.unwrap();
        if shared_secret.is_some() {
            return None; // Already established
        }
    }

    if public_key.len() != 33 && public_key.len() != 65 {
        error!("Invalid client public key size: {} bytes", public_key.len());
        return Some(cbor_error_response(
            "invalid_format",
            &format!(
                "Invalid public key size: {} bytes (expected 33 or 65 for P-256)",
                public_key.len()
            ),
        ));
    }

    let client_public_key = match PublicKey::from_sec1_bytes(public_key) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to deserialize client public key: {:?}", e);
            return Some(cbor_error_response(
                "invalid_format",
                "Invalid P-256 public key",
            ));
        }
    };

    // Generate ephemeral key pair
    let server_ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let server_ephemeral_public = PublicKey::from(&server_ephemeral_secret);

    // Perform ECDH
    let shared_secret = server_ephemeral_secret.diffie_hellman(&client_public_key);

    // Generate random salt
    let mut session_salt = [0u8; 32];
    OsRng.fill_bytes(&mut session_salt);

    // Derive session key using HKDF
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&session_salt), shared_secret.raw_secret_bytes());
    let mut session_key = vec![0u8; 32];
    hk.expand(b"arkavo-session-key", &mut session_key)
        .expect("HKDF expansion failed");

    // Store session shared secret
    {
        let mut shared_secret_lock = connection_state.shared_secret_lock.write().unwrap();
        *shared_secret_lock = Some(session_key);
    }

    // Build response
    let response = CborResponse::KeyExchangeResponse {
        kas_public_key: server_ephemeral_public
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
        session_salt: session_salt.to_vec(),
    };

    match response.encode() {
        Ok(cbor_bytes) => {
            let mut response_data = Vec::with_capacity(1 + cbor_bytes.len());
            response_data.push(CBOR_MESSAGE_TYPE);
            response_data.extend_from_slice(&cbor_bytes);
            Some(Message::Binary(response_data))
        }
        Err(e) => {
            error!("Failed to encode CBOR key exchange response: {}", e);
            Some(cbor_error_response(
                "internal_error",
                "Failed to encode response",
            ))
        }
    }
}

/// Helper to create a CBOR error response message.
fn cbor_error_response(code: &str, message: &str) -> Message {
    use cbor_protocol::{CborResponse, CBOR_MESSAGE_TYPE};

    let response = CborResponse::error(code, message);
    match response.encode() {
        Ok(cbor_bytes) => {
            let mut response_data = Vec::with_capacity(1 + cbor_bytes.len());
            response_data.push(CBOR_MESSAGE_TYPE);
            response_data.extend_from_slice(&cbor_bytes);
            Message::Binary(response_data)
        }
        Err(_) => {
            // Fallback to JSON error if CBOR encoding fails
            let json_error = serde_json::json!({
                "type": "error",
                "code": code,
                "message": message
            });
            Message::Text(json_error.to_string())
        }
    }
}

async fn handle_public_key(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    {
        let shared_secret_lock = connection_state.shared_secret_lock.read();
        let shared_secret = shared_secret_lock.unwrap();
        if shared_secret.is_some() {
            // Session already established - ignore duplicate key exchange
            return None;
        }
    }

    if payload.len() != 33 {
        error!(
            "Invalid client public key size: {} bytes (expected 33)",
            payload.len()
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Invalid public key size: {} bytes (expected 33 for compressed P-256)",
                payload.len()
            ))
            .to_message(),
        );
    }

    // Deserialize the public key sent by the client
    let client_public_key = match PublicKey::from_sec1_bytes(payload) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to deserialize client public key: {:?}", e);
            return Some(
                ErrorResponse::crypto_error(format!("Invalid P-256 public key: {}", e))
                    .to_message(),
            );
        }
    };
    // Generate an ephemeral private key
    let server_private_key = EphemeralSecret::random(&mut OsRng);
    let server_public_key = PublicKey::from(&server_private_key);
    // Perform the key agreement
    let shared_secret = server_private_key.diffie_hellman(&client_public_key);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    // println!("Shared Secret +++++++++++++");
    // println!("Shared Secret: {}", hex::encode(shared_secret_bytes));
    // println!("Shared Secret +++++++++++++");
    {
        let shared_secret = connection_state.shared_secret_lock.write();
        *shared_secret.unwrap() = Some(shared_secret_bytes.to_vec());
    }
    // session salt
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    {
        let mut salt_lock = connection_state.salt_lock.write().unwrap();
        *salt_lock = Some(salt.to_vec());
    }
    // println!("Session Salt: {}", hex::encode(salt));
    // Convert to compressed representation
    let compressed_public_key = server_public_key.to_encoded_point(true);
    let compressed_public_key_bytes = compressed_public_key.as_bytes();
    // Send server_public_key as publicKey message
    let mut response_data = Vec::new();
    // Appending MessageType::PublicKey
    response_data.push(MessageType::PublicKey as u8);
    // Appending server_public_key bytes
    response_data.extend_from_slice(compressed_public_key_bytes);
    // Appending salt bytes
    response_data.extend_from_slice(&salt);
    Some(Message::Binary(response_data))
}

async fn handle_kas_public_key(_: &[u8]) -> Option<Message> {
    // println!("Handling KAS public key");
    if let Some(kas_public_key_bytes) = get_kas_public_key() {
        // println!("KAS Public Key Size: {} bytes", kas_public_key_bytes.len());
        // println!("KAS Public Key Hex: {}", hex::encode(&kas_public_key_bytes));
        let mut response_data = Vec::new();
        response_data.push(MessageType::KasPublicKey as u8);
        response_data.extend_from_slice(&kas_public_key_bytes);
        return Some(Message::Binary(response_data));
    }
    None
}

async fn handle_nats_subscription(
    nats_connection: Arc<NatsConnection>,
    subject: String,
    connection_state: Arc<ConnectionState>,
) {
    loop {
        if let Some(client) = nats_connection.get_client().await {
            match client.subscribe(subject.clone()).await {
                Ok(mut subscription) => {
                    info!("Subscribed to NATS subject: {}", subject);
                    while let Some(msg) = subscription.next().await {
                        if let Err(e) = handle_nats(msg, connection_state.clone()).await {
                            error!("Error handling NATS message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to subscribe to NATS subject: {}. Retrying in {:?}...",
                        e, NATS_RETRY_INTERVAL
                    );
                }
            }
        }
        tokio::time::sleep(NATS_RETRY_INTERVAL).await;
    }
}

async fn handle_nats(
    msg: NatsMessage,
    connection_state: Arc<ConnectionState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // it nanotdf, then do a message, otherwise it is a Flatbuffers event
    let message_type = if msg.payload[0..3].iter().eq(&[0x4C, 0x31, 0x4C]) {
        MessageType::Nats
    } else {
        MessageType::Event
    };

    let ws_message = Message::Binary(
        vec![message_type as u8]
            .into_iter()
            .chain(msg.payload)
            .collect(),
    );
    connection_state.outgoing_tx.send(ws_message)?;
    Ok(())
}

async fn handle_event(
    server_state: &Arc<ServerState>,
    payload: &[u8],
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    let start_time = Instant::now();
    println!(
        "Payload (first 20 bytes in hex, space-delimited): {}",
        payload
            .iter()
            .take(20)
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ")
    );
    // Size validation for type 0x06
    const MAX_EVENT_SIZE: usize = 2000; // Adjust this value as needed
    if payload.len() > MAX_EVENT_SIZE {
        error!(
            "Event payload exceeds maximum allowed size of {} bytes",
            MAX_EVENT_SIZE
        );
        return None;
    }
    let mut event_data: Option<Vec<u8>> = None;
    if let Ok(event) = root::<Event>(payload) {
        println!("Event Action: {:?}", event.action());
        println!("Event Timestamp: {:?}", event.timestamp());
        println!("Event Status: {:?}", event.status());
        println!("Event Data Type: {:?}", event.data_type());
        // S3 store
        match event.action() {
            Action::store => {
                if let Some(cache_event) = event.data_as_cache_event() {
                    if let (Some(target_id), Some(target_payload)) =
                        (cache_event.target_id(), cache_event.target_payload())
                    {
                        // Create S3 key using target_id
                        let target_id_str = bs58::encode(target_id.bytes()).into_string();
                        let s3_key = format!("{}/data", target_id_str);

                        // Upload to S3
                        return match server_state
                            .s3_client
                            .put_object()
                            .bucket(&server_state.settings.s3_bucket)
                            .key(&s3_key)
                            .body(aws_sdk_s3::primitives::ByteStream::from(
                                target_payload.bytes().to_vec(),
                            ))
                            .send()
                            .await
                        {
                            Ok(_) => {
                                info!("Successfully stored object in S3: {}", s3_key);
                                let mut response = Vec::new();
                                response.push(MessageType::Event as u8);
                                response.extend_from_slice(b"Successfully stored");
                                Some(Message::Binary(response))
                            }
                            Err(e) => {
                                error!("Failed to store object in S3: {}", e);
                                None
                            }
                        };
                    }
                }
            }
            _ => {
                error!("Unhandled action: {:?}", event.action());
                drop(None::<Message>);
            }
        }
        // redis connection
        let mut redis_conn = match server_state
            .redis_client
            .get_multiplexed_async_connection()
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to connect to Redis: {}", e);
                return None;
            }
        };
        // Deserialize the event data based on its type
        match event.data_type() {
            EventData::UserEvent => {
                if let Some(user_event) = event.data_as_user_event() {
                    println!("User Event:");
                    println!("  Source Type: {:?}", user_event.source_type());
                    println!("  Target Type: {:?}", user_event.target_type());
                    println!("  Source ID: {:?}", user_event.source_id());
                    println!("  Target ID: {:?}", user_event.target_id());
                    let target_id = user_event.target_id().unwrap();
                    // Retrieve the event object from Redis
                    event_data = match redis_conn.get::<_, Vec<u8>>(target_id.bytes()).await {
                        Ok(data) => {
                            println!("redis target_id: {:?}", target_id);
                            println!("redis data size: {} bytes", data.len());
                            if data.is_empty() {
                                error!("Retrieved data from Redis has size 0");
                                return None;
                            }
                            Some(data)
                        }
                        Err(e) => {
                            error!("Failed to retrieve event from Redis: {}", e);
                            return None;
                        }
                    };
                    // TODO if cache miss then route to device
                } else {
                    error!("Failed to parse user event from payload");
                    return None;
                }
            }
            EventData::CacheEvent => {
                if let Some(cache_event) = event.data_as_cache_event() {
                    println!("Cache Event:");
                    println!("  Target ID: {:?}", cache_event.target_id());
                    println!("  Target Payload: {:?}", cache_event.target_payload());
                    println!(
                        "  Target Payload Size: {:?}",
                        cache_event.target_payload()?.bytes().len()
                    );
                    println!("  TTL: {:?}", cache_event.ttl());
                    println!("  One Time Access: {:?}", cache_event.one_time_access());
                    // Cache the object in Redis with specified TTL
                    let ttl = cache_event.ttl();
                    if ttl > 0 {
                        if let (Some(target_id), Some(target_payload)) =
                            (cache_event.target_id(), cache_event.target_payload())
                        {
                            let target_id_bytes = target_id.bytes();
                            let target_payload_bytes = target_payload.bytes();
                            redis_conn
                                .set_ex::<_, _, String>(
                                    target_id_bytes,
                                    target_payload_bytes,
                                    ttl as u64,
                                )
                                .await
                                .map_err(|e| {
                                    error!("Failed to cache data in Redis: {}", e);
                                })
                                .ok()?;
                        } else {
                            error!("target_id or target_payload was None while caching with TTL");
                            return None;
                        }
                    } else if let (Some(target_id), Some(target_payload)) =
                        (cache_event.target_id(), cache_event.target_payload())
                    {
                        let target_id_bytes = target_id.bytes();
                        let target_payload_bytes = target_payload.bytes();
                        redis_conn
                            .set::<_, _, String>(target_id_bytes, target_payload_bytes)
                            .await
                            .map_err(|e| {
                                error!("Failed to cache data in Redis: {}", e);
                            })
                            .ok()?;
                    } else {
                        error!("target_id or target_payload was None while caching without TTL");
                    }
                    event_data = Some(cache_event.target_payload().unwrap().bytes().to_vec());
                }
            }
            EventData::RouteEvent => {
                if let Some(route_event) = event.data_as_route_event() {
                    if let Some(target_id) = route_event.target_id() {
                        println!("Route Event:");
                        println!("  Target ID: {:?}", target_id);
                        let public_id = bs58::encode(target_id.bytes()).into_string();
                        println!("  Public ID: {}", public_id);
                        let subject = format!("profile.{}", public_id);
                        println!("  subject: {}", subject);
                        // Create NATS message
                        // Create NATS message
                        let nats_message = match NATSMessage::new(payload) {
                            Ok(msg) => msg,
                            Err(e) => {
                                error!("Failed to create NATS message: {}", e);
                                return None;
                            }
                        };
                        // Get NATS client
                        if let Some(nats_client) = nats_connection.get_client().await {
                            // Send the event to NATS
                            match nats_message.send_to_nats(&nats_client, subject).await {
                                Ok(_) => {
                                    println!("Successfully sent route event to NATS");
                                    return None;
                                }
                                Err(e) => {
                                    error!("Failed to send route event to NATS: {}", e);
                                    return None;
                                }
                            }
                        } else {
                            error!("NATS client not available");
                            return None;
                        }
                    } else {
                        error!("Target ID is missing.");
                        return None;
                    }
                }
            }
            EventData::NONE => {
                error!("No event data");
            }
            _ => {
                error!("Unknown event data type: {:?}", event.data_type());
            }
        }
    } else {
        error!("Failed to parse Event from payload");
        return None;
    }
    let response_data = match event_data {
        Some(data) => {
            let mut response = Vec::new();
            response.push(MessageType::Event as u8);
            response.extend_from_slice(&data);
            response
        }
        None => {
            error!("Event not found in Redis");
            let mut response = Vec::new();
            response.push(MessageType::Event as u8);
            response.extend_from_slice(b"Event not found");
            response
        }
    };

    let total_time = start_time.elapsed();
    log_timing(
        &server_state.settings,
        "Total time for handle_event",
        total_time,
    );

    Some(Message::Binary(response_data))
}

fn init_kas_keys(key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pem_content = std::fs::read_to_string(key_path)?;
    let ec_pem_contents = pem_content.as_bytes();
    let pem = pem::parse(ec_pem_contents)?;
    if pem.tag() != "EC PRIVATE KEY" {
        return Err("Not an EC private key".into());
    }
    let kas_private_key = SecretKey::from_sec1_der(pem.contents())?;
    // Derive the public key from the private key
    let kas_public_key = kas_private_key.public_key();
    // Get the compressed representation of the public key
    let kas_public_key_compressed = kas_public_key.to_encoded_point(true);
    let kas_public_key_bytes = kas_public_key_compressed.as_bytes().to_vec();
    // Ensure the public key is 33 bytes
    assert_eq!(
        kas_public_key_bytes.len(),
        33,
        "KAS public key should be 33 bytes"
    );
    let kas_keys = KasKeys {
        public_key: kas_public_key_bytes,
        private_key: kas_private_key.to_bytes().to_vec(),
    };
    KAS_KEYS
        .set(Arc::new(kas_keys))
        .map_err(|_| "KAS keys already initialized".into())
}

fn load_rsa_key(
    key_path: &str,
) -> Result<(rsa::RsaPrivateKey, String), Box<dyn std::error::Error>> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::RsaPublicKey;

    let pem_content = std::fs::read_to_string(key_path)?;

    // Try to parse as PKCS#8 RSA private key
    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem_content)?;

    // Derive public key and encode as PEM
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_pem =
        rsa::pkcs8::EncodePublicKey::to_public_key_pem(&public_key, Default::default())?;

    Ok((private_key, public_key_pem))
}

fn get_kas_public_key() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.public_key.clone())
}

fn get_kas_private_key_bytes() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.private_key.clone())
}

struct ServerState {
    settings: ServerSettings,
    redis_client: RedisClient,
    s3_client: s3::Client,
    chain_validator: Option<Arc<dyn chain::SessionValidator>>,
}

/// WebSocket route state - contains all dependencies needed for WebSocket handling
#[derive(Clone)]
struct WebSocketState {
    server_state: Arc<ServerState>,
    nats_connection: Arc<NatsConnection>,
    apple_app_site_association: Arc<RwLock<String>>,
}

impl ServerState {
    async fn new(
        settings: ServerSettings,
        redis_client: RedisClient,
        chain_validator: Option<Arc<dyn chain::SessionValidator>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize AWS S3 client
        info!("Loading AWS configuration...");
        let config = aws_config::load_from_env().await;
        info!("AWS configuration loaded successfully");
        let s3_client = s3::Client::new(&config);
        info!("S3 client initialized");

        Ok(ServerState {
            settings,
            redis_client,
            s3_client,
            chain_validator,
        })
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ServerSettings {
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
    kas_key_path: String,
    enable_timing_logs: bool,
    nats_url: String,
    nats_subject: String,
    redis_url: String,
    jwt_validation_disabled: bool,
    jwt_public_key_path: Option<String>,
    s3_bucket: String,
    /// Chain RPC URL for blockchain connectivity (optional - disables chain validation if not set)
    chain_rpc_url: Option<String>,
    /// Expected audience for NTDF token validation
    ntdf_expected_audience: String,
}

fn log_timing(settings: &ServerSettings, message: &str, duration: std::time::Duration) {
    if settings.enable_timing_logs {
        info!("{}: {:?}", message, duration);
    }
}
fn load_config() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    Ok(ServerSettings {
        port: env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?,
        tls_enabled: env::var("TLS_CERT_PATH").is_ok(),
        tls_cert_path: env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
            current_dir
                .join("fullchain.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        tls_key_path: env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("privkey.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        kas_key_path: env::var("KAS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("recipient_private_key.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
        nats_url: env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string()),
        nats_subject: env::var("NATS_SUBJECT").unwrap_or_else(|_| "nanotdf.messages".to_string()),
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        jwt_validation_disabled: env::var("JWT_VALIDATION_DISABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true),
        jwt_public_key_path: env::var("JWT_PUBLIC_KEY_PATH").ok(),
        s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "default-bucket".to_string()),
        chain_rpc_url: env::var("CHAIN_RPC_URL").ok(),
        ntdf_expected_audience: env::var("NTDF_EXPECTED_AUDIENCE")
            .unwrap_or_else(|_| "https://platform.arkavo.net".to_string()),
    })
}

/// Validate configuration parameters with clear error messages
fn validate_config(settings: &ServerSettings) -> Result<(), Box<dyn std::error::Error>> {
    // Validate port range
    if settings.port == 0 {
        return Err("PORT must be greater than 0".into());
    }

    // Validate TLS configuration
    if settings.tls_enabled {
        if settings.tls_cert_path.is_empty() {
            return Err("TLS_CERT_PATH must be set when TLS is enabled".into());
        }
        if settings.tls_key_path.is_empty() {
            return Err("TLS_KEY_PATH must be set when TLS is enabled".into());
        }
        // Check if cert file exists
        if !std::path::Path::new(&settings.tls_cert_path).exists() {
            return Err(
                format!("TLS certificate file not found: {}", settings.tls_cert_path).into(),
            );
        }
        // Check if key file exists
        if !std::path::Path::new(&settings.tls_key_path).exists() {
            return Err(format!("TLS key file not found: {}", settings.tls_key_path).into());
        }
    }

    // Validate KAS key path
    if settings.kas_key_path.is_empty() {
        return Err("KAS_KEY_PATH must be set".into());
    }
    if !std::path::Path::new(&settings.kas_key_path).exists() {
        return Err(format!("KAS private key file not found: {}", settings.kas_key_path).into());
    }

    // Validate NATS URL format
    if !settings.nats_url.starts_with("nats://") && !settings.nats_url.starts_with("tls://") {
        return Err(format!(
            "NATS_URL must start with 'nats://' or 'tls://': {}",
            settings.nats_url
        )
        .into());
    }

    // Validate NATS subject is not empty
    if settings.nats_subject.is_empty() {
        return Err("NATS_SUBJECT must not be empty".into());
    }

    // Validate Redis URL format
    if !settings.redis_url.starts_with("redis://") && !settings.redis_url.starts_with("rediss://") {
        return Err(format!(
            "REDIS_URL must start with 'redis://' or 'rediss://': {}",
            settings.redis_url
        )
        .into());
    }

    // Validate JWT configuration
    if !settings.jwt_validation_disabled && settings.jwt_public_key_path.is_none() {
        return Err("JWT_PUBLIC_KEY_PATH must be set when JWT validation is enabled".into());
    }
    if let Some(ref jwt_key_path) = settings.jwt_public_key_path {
        if !std::path::Path::new(jwt_key_path).exists() {
            return Err(format!("JWT public key file not found: {}", jwt_key_path).into());
        }
    }

    // Validate S3 bucket name
    if settings.s3_bucket.is_empty() {
        return Err("S3_BUCKET must not be empty".into());
    }

    // Validate Chain RPC URL format (only if configured)
    if let Some(ref chain_url) = settings.chain_rpc_url {
        if !chain_url.starts_with("ws://")
            && !chain_url.starts_with("wss://")
            && !chain_url.starts_with("http://")
            && !chain_url.starts_with("https://")
        {
            return Err(format!(
                "CHAIN_RPC_URL must be a valid WebSocket or HTTP URL: {}",
                chain_url
            )
            .into());
        }
    }

    info!("✓ Configuration validation passed");
    Ok(())
}

/// Validate media DRM configuration parameters
fn validate_media_config(
    max_concurrent_streams: u32,
    media_metrics_subject: &str,
    enable_analytics: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate max concurrent streams range
    if max_concurrent_streams == 0 {
        return Err("MAX_CONCURRENT_STREAMS must be greater than 0".into());
    }
    if max_concurrent_streams > 100 {
        return Err("MAX_CONCURRENT_STREAMS must not exceed 100 (current: {})".into());
    }

    // Validate metrics subject when analytics is enabled
    if enable_analytics && media_metrics_subject.is_empty() {
        return Err(
            "MEDIA_METRICS_SUBJECT must not be empty when ENABLE_MEDIA_ANALYTICS=true".into(),
        );
    }

    info!(
        "✓ Media DRM configuration validation passed (max_streams={}, analytics={})",
        max_concurrent_streams, enable_analytics
    );
    Ok(())
}

async fn load_apple_app_site_association() -> Arc<RwLock<String>> {
    let content = fs::read_to_string("apple-app-site-association.json")
        .await
        .expect("Failed to read apple-app-site-association.json");
    Arc::new(RwLock::new(content))
}

// RewindableStream removed - no longer needed with Axum routing

fn convert_rating_level(level: arkavo::RatingLevel) -> RatingLevel {
    match level.0 {
        x if x == arkavo::RatingLevel::unused.0 => RatingLevel::Unused,
        x if x == arkavo::RatingLevel::none.0 => RatingLevel::None,
        x if x == arkavo::RatingLevel::mild.0 => RatingLevel::Mild,
        x if x == arkavo::RatingLevel::moderate.0 => RatingLevel::Moderate,
        x if x == arkavo::RatingLevel::severe.0 => RatingLevel::Severe,
        _ => RatingLevel::Unused, // Default to Unused for any invalid values
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use elliptic_curve::ScalarPrimitive;
    use elliptic_curve::{CurveArithmetic, NonZeroScalar};
    use p256::NistP256;

    use super::*;

    #[tokio::test]
    async fn test_ephemeral_key_pair_and_custom_ecdh() {
        // Generate an ephemeral server key pair
        let server_private_key = EphemeralSecret::random(&mut OsRng);

        // Generate an ephemeral client key pair
        let client_private_key = EphemeralSecret::random(&mut OsRng);
        let client_public_key = PublicKey::from(&client_private_key);
        // Serialize the client public key
        let client_public_key_compressed = client_public_key.to_encoded_point(true);
        let client_public_key_bytes = client_public_key_compressed.as_bytes().to_vec();

        // Perform key agreement with the server's private key and the other party's (client's) public key
        let shared_secret = server_private_key.diffie_hellman(&client_public_key);

        // Convert the shared_secret into bytes
        let shared_secret_bytes = shared_secret.raw_secret_bytes().to_vec();
        let key_agreement_secret = hex::encode(shared_secret_bytes);
        // println!("Key agreement secret: {}", key_agreement_secret);

        let debug_server_private_key: DebugEphemeralSecret<NistP256> =
            unsafe { std::mem::transmute(server_private_key) };
        let secret_key = SecretKey::new(ScalarPrimitive::from(debug_server_private_key.scalar));
        // Deserialize the public key of client
        let public_key = PublicKey::from_sec1_bytes(&client_public_key_bytes)
            .expect("Error deserializing client public key");

        // Run custom ECDH
        let result = custom_ecdh(&secret_key, &public_key).expect("Error performing ECDH");

        let computed_secret = hex::encode(result);
        // println!("Computed shared secret: {}", computed_secret);

        assert_eq!(
            key_agreement_secret, computed_secret,
            "Key agreement secret does not match with computed shared secret."
        );
    }

    #[test]
    fn test_ecdh_known_values() -> Result<(), Box<dyn Error>> {
        // These are example values and should be replaced with actual test vectors
        // kas_private_key_bytes
        let server_private = "472c179ab235274ecb6678bcc5aa0a8578fc59b7431dd8dd37adbeb60c637618";
        let server_public = "03689f8463a91340e347847414f5ef67a6013ab7236b2229c70b717974ee74eb6c";
        // tdf_ephemeral_key
        let client_public = "02c8eee0d2c24780cbc29169739acc68904bdee3c0553d5ec1183ba476942de686";
        // kas_private_key_bytes
        let private_key_bytes = hex::decode(server_private).unwrap();
        // tdf_ephemeral_public_key
        let public_key_bytes = hex::decode(client_public).unwrap();
        // dek_shared_secret - from swift client
        // let expected_shared_secret = "0c53a5afa08acf1f2000cd9c050d35eca472d625a010146991aed9da05114e3b";
        let expected_shared_secret =
            "d5da0342ae4458cece9b3eb2d253c6212e9612ab9f8c9a4249ee4c9c59ccda13";

        let client_public_key = PublicKey::from_sec1_bytes(&public_key_bytes).unwrap();
        let kas_private_key_option: Option<[u8; 32]> = private_key_bytes.clone().try_into().ok();
        let kas_private_key_array = match kas_private_key_option {
            Some(array) => array,
            None => {
                return Err(Box::new(std::io::Error::other(
                    "Could not convert to array.",
                )))
            }
        };
        let server_secret_key = SecretKey::from_bytes(&kas_private_key_array.into())
            .map_err(|_| "Invalid private key")
            .ok();
        let server_secret_key = server_secret_key.unwrap();

        let server_public_key = server_secret_key.public_key();
        let compressed_public_key = server_public_key.to_encoded_point(true);
        let compressed_public_key_bytes = compressed_public_key.as_bytes();
        // println!("KAS Public Key Hex: {}", hex::encode(compressed_public_key_bytes));
        assert_eq!(hex::encode(compressed_public_key_bytes), server_public);

        let result = custom_ecdh(&server_secret_key, &client_public_key).unwrap();
        assert_eq!(hex::encode(result), expected_shared_secret);
        Ok(())
    }
    pub struct DebugEphemeralSecret<C>
    where
        C: CurveArithmetic,
    {
        pub scalar: NonZeroScalar<C>,
    }
}
