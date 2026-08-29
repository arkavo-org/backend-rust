//! Per-Connection RTMP Session State Machine
//!
//! Manages the lifecycle of an RTMP connection including:
//! - RTMP handshake
//! - Publisher/Subscriber role detection
//! - NanoTDF manifest via onMetaData `ntdf_header` field
//! - Frame encryption (publisher via Collection) / decryption (subscriber via Decryptor)
//! - Passthrough mode for standard cleartext RTMP streams

use bytes::Bytes;
use opentdf_crypto::tdf::{NanoTdfCollection, NanoTdfCollectionDecryptor};
use p256::pkcs8::EncodePrivateKey;
use rml_amf0::Amf0Value;
use rml_rtmp::chunk_io::Packet;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ServerSession, ServerSessionConfig, ServerSessionEvent, ServerSessionResult, StreamMetadata,
};
use rml_rtmp::time::RtmpTimestamp;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

use super::encryption::{
    create_decryptor_kas, decrypt_item, encrypt_item, rotation_threshold_reached,
};
use super::manifest::{delete_cached_manifest, get_cached_manifest, NanoTdfManifest};
use super::registry::StreamRegistry;
use super::stream_events::StreamEventBroadcaster;
use crate::modules::secure_keys::SecureEcPrivateKey;

/// RTMP session role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Not yet determined
    Unknown,
    /// Publishing content
    Publisher,
    /// Receiving content
    Subscriber,
}

/// Encryption mode for the stream
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// Waiting for metadata to determine mode
    Pending,
    /// NTDF encrypted stream (has manifest/DEK)
    Encrypted,
    /// Standard cleartext RTMP stream (passthrough)
    Passthrough,
}

/// RTMP session error
#[derive(Debug)]
pub enum SessionError {
    IoError(std::io::Error),
    RtmpError(String),
    EncryptionError(String),
    ManifestError(String),
    NoManifest,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::IoError(e) => write!(f, "IO error: {}", e),
            SessionError::RtmpError(e) => write!(f, "RTMP error: {}", e),
            SessionError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            SessionError::ManifestError(e) => write!(f, "Manifest error: {}", e),
            SessionError::NoManifest => write!(f, "No TDF manifest received"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        SessionError::IoError(e)
    }
}

/// Per-connection RTMP session state
pub struct RtmpSession {
    /// Session role (publisher or subscriber)
    role: SessionRole,
    /// Encryption mode for this stream
    encryption_mode: EncryptionMode,
    /// Stream key (app/stream_name)
    stream_key: Option<String>,
    /// NanoTDF manifest (received from publisher or cache)
    manifest: Option<NanoTdfManifest>,
    /// NanoTDF Collection for publisher-side encryption (thread-safe)
    collection: Option<Arc<NanoTdfCollection>>,
    /// NanoTDF Decryptor for subscriber-side decryption
    decryptor: Option<NanoTdfCollectionDecryptor>,
    /// KAS private key for DEK derivation. Held in the zeroizing wrapper; the
    /// PKCS#8 DER encoding opentdf-rs wants is materialized per decryptor and
    /// dropped immediately.
    kas_private_key: SecureEcPrivateKey,
    /// Redis client for manifest caching
    redis_client: Arc<redis::Client>,
    /// Stream registry for publisher-subscriber linking
    stream_registry: Arc<StreamRegistry>,
    /// Broadcast sender for publisher to send frames (only set for publishers)
    frame_sender: Option<broadcast::Sender<RelayFrame>>,
    /// Broadcast receiver for subscriber to receive frames (only set for subscribers)
    frame_receiver: Option<broadcast::Receiver<RelayFrame>>,
    /// Stream ID for subscriber (needed to send video/audio data)
    subscriber_stream_id: Option<u32>,
    /// Whether we've received onMetaData
    metadata_received: bool,
    /// Stream event broadcaster for NATS notifications
    event_broadcaster: Option<Arc<StreamEventBroadcaster>>,
    /// Whether stream_started event has been sent
    started_event_sent: bool,
    /// Cached video sequence header for late joiner (set during subscribe)
    cached_video_header: Option<Vec<u8>>,
    /// Cached audio sequence header for late joiner (set during subscribe)
    cached_audio_header: Option<Vec<u8>>,
    /// Cached stream metadata for late joiner (set during subscribe)
    cached_metadata: Option<StreamMetadata>,
    /// Cached NanoTDF header (base64-encoded) for late joiner (set during subscribe)
    cached_ntdf_header: Option<String>,
    /// Whether cached headers have been sent to subscriber
    headers_sent: bool,
    /// Frame counter for debugging (video + audio)
    frame_count: u64,
    /// Last frame count log time
    last_frame_log: std::time::Instant,
    /// Bytes received counter
    bytes_received: u64,
}

/// Frame to relay to subscribers
#[derive(Debug, Clone)]
pub struct RelayFrame {
    pub frame_type: FrameType,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// Type of media frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Video,
    Audio,
}

impl RtmpSession {
    /// Create a new RTMP session
    ///
    /// # Arguments
    /// * `redis_client` - Redis client for manifest caching
    /// * `kas_private_key` - KAS EC private key
    /// * `event_broadcaster` - Optional stream event broadcaster for NATS notifications
    /// * `stream_registry` - Shared stream registry for publisher-subscriber linking
    pub fn new(
        redis_client: Arc<redis::Client>,
        kas_private_key: SecureEcPrivateKey,
        event_broadcaster: Option<Arc<StreamEventBroadcaster>>,
        stream_registry: Arc<StreamRegistry>,
    ) -> Self {
        RtmpSession {
            role: SessionRole::Unknown,
            encryption_mode: EncryptionMode::Pending,
            stream_key: None,
            manifest: None,
            collection: None,
            decryptor: None,
            kas_private_key,
            redis_client,
            stream_registry,
            frame_sender: None,
            frame_receiver: None,
            subscriber_stream_id: None,
            metadata_received: false,
            event_broadcaster,
            started_event_sent: false,
            cached_video_header: None,
            cached_audio_header: None,
            cached_metadata: None,
            cached_ntdf_header: None,
            headers_sent: false,
            frame_count: 0,
            last_frame_log: std::time::Instant::now(),
            bytes_received: 0,
        }
    }

    /// Handle an incoming RTMP connection
    pub async fn handle_connection(mut self, mut socket: TcpStream) -> Result<(), SessionError> {
        let peer_addr = socket
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        log::info!("RTMP connection from {}", peer_addr);

        // Phase 1: RTMP Handshake
        let mut handshake = Handshake::new(PeerType::Server);
        let mut buf = [0u8; 4096];
        let mut remaining_bytes = Vec::new();

        loop {
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                return Err(SessionError::RtmpError(
                    "Connection closed during handshake".to_string(),
                ));
            }

            let mut input = buf[..n].to_vec();
            if !remaining_bytes.is_empty() {
                let mut combined = remaining_bytes.clone();
                combined.extend_from_slice(&input);
                input = combined;
                remaining_bytes.clear();
            }

            match handshake.process_bytes(&input) {
                Ok(HandshakeProcessResult::InProgress { response_bytes }) => {
                    socket.write_all(&response_bytes).await?;
                }
                Ok(HandshakeProcessResult::Completed {
                    response_bytes,
                    remaining_bytes: leftover,
                }) => {
                    socket.write_all(&response_bytes).await?;
                    remaining_bytes = leftover;
                    log::debug!("RTMP handshake completed for {}", peer_addr);
                    break;
                }
                Err(e) => {
                    return Err(SessionError::RtmpError(format!("Handshake error: {:?}", e)));
                }
            }
        }

        // Phase 2: RTMP Session
        let config = ServerSessionConfig::new();
        let (mut session, initial_results) =
            ServerSession::new(config).map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;

        // Send initial session responses
        for result in initial_results {
            self.process_result(&mut socket, &result).await?;
        }

        // Process any bytes left over from handshake
        if !remaining_bytes.is_empty() {
            let results = Self::safe_handle_input(&mut session, &remaining_bytes)?;

            for result in results {
                if let Some(request_id) = self.process_result(&mut socket, &result).await? {
                    let accept_results = session
                        .accept_request(request_id)
                        .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                    Self::send_responses(&mut socket, accept_results).await?;
                }
            }
        }

        // Main session loop - handles both socket reads and frame relay for subscribers
        loop {
            // Check if we're a subscriber with an active receiver
            if self.role == SessionRole::Subscriber {
                if let Some(ref mut receiver) = self.frame_receiver {
                    // Send cached metadata and sequence headers to late joiner (once)
                    if !self.headers_sent {
                        if let Some(stream_id) = self.subscriber_stream_id {
                            // Send metadata first (onMetaData) - required by most players
                            // The metadata now includes custom_fields (like ntdf_header) automatically
                            if let Some(ref metadata) = self.cached_metadata {
                                // If we have a cached ntdf_header, add it to the metadata
                                let mut meta_with_ntdf = metadata.clone();
                                if let Some(ref ntdf_header) = self.cached_ntdf_header {
                                    meta_with_ntdf
                                        .custom_fields
                                        .insert("ntdf_header".to_string(), ntdf_header.clone());
                                    log::info!(
                                        "Sending cached metadata with ntdf_header to late joiner ({} chars)",
                                        ntdf_header.len()
                                    );
                                } else {
                                    log::info!("Sending cached metadata to late joiner");
                                }
                                let packet = session
                                    .send_metadata(stream_id, &meta_with_ntdf)
                                    .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                                socket.write_all(&packet.bytes).await?;
                            }
                            // Send video sequence header
                            if let Some(ref video_header) = self.cached_video_header {
                                log::info!("Sending cached video sequence header to late joiner ({} bytes)", video_header.len());
                                let timestamp = RtmpTimestamp::new(0);
                                let data = Bytes::from(video_header.clone());
                                let packet = session
                                    .send_video_data(stream_id, data, timestamp, false)
                                    .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                                socket.write_all(&packet.bytes).await?;
                            }
                            // Send audio sequence header
                            if let Some(ref audio_header) = self.cached_audio_header {
                                log::info!("Sending cached audio sequence header to late joiner ({} bytes)", audio_header.len());
                                let timestamp = RtmpTimestamp::new(0);
                                let data = Bytes::from(audio_header.clone());
                                let packet = session
                                    .send_audio_data(stream_id, data, timestamp, false)
                                    .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                                socket.write_all(&packet.bytes).await?;
                            }
                        }
                        self.headers_sent = true;
                    }

                    // Use select to handle both socket reads and frame reception
                    tokio::select! {
                        // Handle incoming socket data
                        read_result = socket.read(&mut buf) => {
                            let n = read_result?;
                            if n == 0 {
                                log::info!("RTMP connection closed: {}", peer_addr);
                                break;
                            }

                            let results = Self::safe_handle_input(&mut session, &buf[..n])?;

                            for result in results {
                                if let Some(request_id) = self.process_result(&mut socket, &result).await? {
                                    let accept_results = session
                                        .accept_request(request_id)
                                        .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                                    Self::send_responses(&mut socket, accept_results).await?;
                                    log::info!("Request {} accepted", request_id);
                                }
                            }
                        }

                        // Handle frames from publisher
                        frame_result = receiver.recv() => {
                            match frame_result {
                                Ok(frame) => {
                                    // Get stream ID for sending
                                    if let Some(stream_id) = self.subscriber_stream_id {
                                        let timestamp = RtmpTimestamp::new(frame.timestamp);
                                        let data = Bytes::from(frame.data);

                                        // Wrap send calls with panic catching (rml_rtmp bug workaround)
                                        let packet = match frame.frame_type {
                                            FrameType::Video => {
                                                Self::safe_send_video(&mut session, stream_id, data, timestamp)?
                                            }
                                            FrameType::Audio => {
                                                Self::safe_send_audio(&mut session, stream_id, data, timestamp)?
                                            }
                                        };

                                        // Send the RTMP packet to subscriber
                                        socket.write_all(&packet.bytes).await?;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    log::warn!("Subscriber lagged, dropped {} frames", n);
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    log::info!("Publisher stream ended");
                                    break;
                                }
                            }
                        }
                    }
                    continue;
                }
            }

            // For publishers and subscribers without active stream - just read socket
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                log::info!("RTMP connection closed: {}", peer_addr);
                break;
            }

            // Track bytes received for debugging
            self.bytes_received += n as u64;

            // Log periodic stats every 5 seconds for publishers
            if self.role == SessionRole::Publisher && self.last_frame_log.elapsed().as_secs() >= 5 {
                log::info!(
                    "Publisher stats for {:?}: frames={}, bytes_received={}, role={:?}",
                    self.stream_key,
                    self.frame_count,
                    self.bytes_received,
                    self.role
                );
                self.last_frame_log = std::time::Instant::now();
            }

            // Process bytes through RTMP session (with panic catching for rml_rtmp bug)
            let results = Self::safe_handle_input(&mut session, &buf[..n])?;

            for result in results {
                if let Some(request_id) = self.process_result(&mut socket, &result).await? {
                    let accept_results = session
                        .accept_request(request_id)
                        .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                    Self::send_responses(&mut socket, accept_results).await?;
                    log::info!("Request {} accepted", request_id);
                }
            }
        }

        // Cleanup on disconnect
        if self.role == SessionRole::Publisher {
            if let Some(ref stream_key) = self.stream_key {
                // Unregister from stream registry
                self.stream_registry.unregister_publisher(stream_key).await;

                let _ = delete_cached_manifest(&self.redis_client, stream_key).await;
                log::info!("Publisher disconnected, cleaned up stream: {}", stream_key);

                // Broadcast stream_stopped event if stream was started
                if self.started_event_sent {
                    if let Some(ref broadcaster) = self.event_broadcaster {
                        broadcaster.stream_stopped(stream_key).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process an RTMP session result, returning any accept request IDs that need handling
    async fn process_result(
        &mut self,
        socket: &mut TcpStream,
        result: &ServerSessionResult,
    ) -> Result<Option<u32>, SessionError> {
        match result {
            ServerSessionResult::OutboundResponse(packet) => {
                socket.write_all(&packet.bytes).await?;
                Ok(None)
            }

            ServerSessionResult::RaisedEvent(event) => self.handle_event(event).await,

            ServerSessionResult::UnhandleableMessageReceived(_) => {
                // Ignore unhandled messages
                Ok(None)
            }
        }
    }

    /// Send outbound responses from accept_request
    async fn send_responses(
        socket: &mut TcpStream,
        results: Vec<ServerSessionResult>,
    ) -> Result<(), SessionError> {
        for result in results {
            if let ServerSessionResult::OutboundResponse(packet) = result {
                socket.write_all(&packet.bytes).await?;
            }
        }
        Ok(())
    }

    /// Safely handle RTMP input bytes with panic catching
    ///
    /// The rml_rtmp library has a known bug (deserializer.rs:371) where extended timestamp
    /// handling can cause an arithmetic underflow panic. This wrapper catches such panics
    /// and converts them to recoverable errors.
    fn safe_handle_input(
        session: &mut ServerSession,
        input: &[u8],
    ) -> Result<Vec<ServerSessionResult>, SessionError> {
        let input_len = input.len();
        let result = catch_unwind(AssertUnwindSafe(|| session.handle_input(input)));
        match result {
            Ok(Ok(results)) => {
                log::trace!(
                    "RTMP input processed: {} bytes, {} results",
                    input_len,
                    results.len()
                );
                Ok(results)
            }
            Ok(Err(e)) => {
                // Log detailed error info for debugging
                let first_bytes: Vec<u8> = input.iter().take(32).copied().collect();
                log::error!(
                    "RTMP chunk error: {:?}, input_len={}, first_bytes={:02x?}",
                    e,
                    input_len,
                    first_bytes
                );
                Err(SessionError::RtmpError(format!("{:?}", e)))
            }
            Err(panic_info) => {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic in RTMP deserializer".to_string()
                };
                let first_bytes: Vec<u8> = input.iter().take(32).copied().collect();
                log::error!(
                    "RTMP deserializer panic: {}, input_len={}, first_bytes={:02x?}",
                    msg,
                    input_len,
                    first_bytes
                );
                Err(SessionError::RtmpError(format!(
                    "RTMP deserializer panic: {}",
                    msg
                )))
            }
        }
    }

    /// Safely send video data with panic catching (rml_rtmp bug workaround)
    fn safe_send_video(
        session: &mut ServerSession,
        stream_id: u32,
        data: Bytes,
        timestamp: RtmpTimestamp,
    ) -> Result<Packet, SessionError> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            session.send_video_data(stream_id, data, timestamp, false)
        }));
        match result {
            Ok(Ok(packet)) => Ok(packet),
            Ok(Err(e)) => Err(SessionError::RtmpError(format!("{:?}", e))),
            Err(panic_info) => {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic in RTMP video send".to_string()
                };
                log::error!("RTMP send_video_data panic (rml_rtmp bug): {}", msg);
                Err(SessionError::RtmpError(format!("RTMP send panic: {}", msg)))
            }
        }
    }

    /// Safely send audio data with panic catching (rml_rtmp bug workaround)
    fn safe_send_audio(
        session: &mut ServerSession,
        stream_id: u32,
        data: Bytes,
        timestamp: RtmpTimestamp,
    ) -> Result<Packet, SessionError> {
        let result = catch_unwind(AssertUnwindSafe(|| {
            session.send_audio_data(stream_id, data, timestamp, false)
        }));
        match result {
            Ok(Ok(packet)) => Ok(packet),
            Ok(Err(e)) => Err(SessionError::RtmpError(format!("{:?}", e))),
            Err(panic_info) => {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic in RTMP audio send".to_string()
                };
                log::error!("RTMP send_audio_data panic (rml_rtmp bug): {}", msg);
                Err(SessionError::RtmpError(format!("RTMP send panic: {}", msg)))
            }
        }
    }

    /// Handle an RTMP session event, returning request_id if acceptance is needed
    async fn handle_event(
        &mut self,
        event: &ServerSessionEvent,
    ) -> Result<Option<u32>, SessionError> {
        match event {
            ServerSessionEvent::ConnectionRequested {
                request_id,
                app_name,
            } => {
                log::info!("Connection requested for app: {}", app_name);
                Ok(Some(*request_id))
            }

            ServerSessionEvent::PublishStreamRequested {
                request_id,
                app_name,
                stream_key,
                mode: _,
            } => {
                self.role = SessionRole::Publisher;
                let full_key = format!("{}/{}", app_name, stream_key);
                self.stream_key = Some(full_key.clone());

                // Register with stream registry and get broadcast sender
                let sender = self.stream_registry.register_publisher(&full_key).await;
                self.frame_sender = Some(sender);

                log::info!(
                    "Publish requested: {} (request_id: {})",
                    full_key,
                    request_id
                );
                Ok(Some(*request_id))
            }

            ServerSessionEvent::PlayStreamRequested {
                request_id,
                app_name,
                stream_key,
                start_at: _,
                duration: _,
                reset: _,
                stream_id,
            } => {
                self.role = SessionRole::Subscriber;
                let full_key = format!("{}/{}", app_name, stream_key);
                self.stream_key = Some(full_key.clone());
                self.subscriber_stream_id = Some(*stream_id);
                log::info!(
                    "Play requested: {} (request_id: {}, stream_id: {})",
                    full_key,
                    request_id,
                    stream_id
                );

                // Subscribe to the stream registry to receive frames from publisher
                if let Some((receiver, video_header, audio_header, metadata, ntdf_header)) =
                    self.stream_registry.subscribe(&full_key).await
                {
                    self.frame_receiver = Some(receiver);
                    // Cache headers for late joiner - will be sent after play is accepted
                    if video_header.is_some() {
                        log::info!("Got cached video sequence header for late joiner");
                    }
                    if audio_header.is_some() {
                        log::info!("Got cached audio sequence header for late joiner");
                    }
                    if metadata.is_some() {
                        log::info!("Got cached stream metadata for late joiner");
                    }
                    if ntdf_header.is_some() {
                        log::info!("Got cached ntdf_header for late joiner");
                    }
                    self.cached_video_header = video_header;
                    self.cached_audio_header = audio_header;
                    self.cached_metadata = metadata;
                    self.cached_ntdf_header = ntdf_header;
                    log::info!("Subscribed to live stream: {}", full_key);
                } else {
                    log::warn!("Stream {} not currently live", full_key);
                }

                // Try to fetch cached manifest for late joiner
                match get_cached_manifest(&self.redis_client, &full_key).await {
                    Ok(manifest) => {
                        log::info!("Found cached manifest for late joiner");
                        self.set_manifest_subscriber(manifest)?;
                    }
                    Err(_) => {
                        log::debug!("No cached manifest found, using passthrough mode");
                        self.encryption_mode = EncryptionMode::Passthrough;
                    }
                }
                Ok(Some(*request_id))
            }

            ServerSessionEvent::StreamMetadataChanged {
                app_name,
                stream_key,
                metadata,
            } => {
                log::info!("Metadata received for {}/{}", app_name, stream_key);
                self.metadata_received = true;
                self.handle_metadata(metadata).await?;
                Ok(None)
            }

            ServerSessionEvent::VideoDataReceived {
                app_name: _,
                stream_key: _,
                data,
                timestamp,
            } => {
                self.handle_video_data(data, timestamp).await?;
                Ok(None)
            }

            ServerSessionEvent::AudioDataReceived {
                app_name: _,
                stream_key: _,
                data,
                timestamp,
            } => {
                self.handle_audio_data(data, timestamp).await?;
                Ok(None)
            }

            ServerSessionEvent::UnhandleableAmf0Command {
                command_name,
                transaction_id: _,
                command_object: _,
                additional_values,
            } => {
                log::debug!("Unhandled AMF0 command: {}", command_name);

                // Check for @setDataFrame or onMetaData containing ntdf_header
                if command_name == "@setDataFrame" || command_name == "onMetaData" {
                    self.extract_ntdf_header_from_amf(additional_values).await;
                }

                Ok(None)
            }

            _ => {
                log::trace!("Unhandled RTMP event: {:?}", event);
                Ok(None)
            }
        }
    }

    /// Handle stream metadata (onMetaData)
    ///
    /// Checks for `ntdf_header` key containing base64-encoded NanoTDF header.
    /// If found, initializes encryption context. Otherwise, sets passthrough mode.
    ///
    /// Handle stream metadata from publisher.
    /// Extracts ntdf_header from custom_fields if present for NTDF-RTMP streams.
    async fn handle_metadata(&mut self, metadata: &StreamMetadata) -> Result<(), SessionError> {
        // Log standard metadata for debugging including encoder info
        log::info!(
            "Stream metadata: video={}x{}, audio_rate={:?}, encoder={:?}, custom_fields={:?}",
            metadata.video_width.unwrap_or(0),
            metadata.video_height.unwrap_or(0),
            metadata.audio_sample_rate,
            metadata.encoder,
            metadata.custom_fields.keys().collect::<Vec<_>>()
        );

        // Cache metadata in registry for late-joining subscribers
        if let Some(ref stream_key) = self.stream_key {
            self.stream_registry
                .set_stream_metadata(stream_key, metadata.clone())
                .await;
            log::debug!("Cached stream metadata for late joiners: {}", stream_key);

            // Check for ntdf_header in custom_fields (NTDF-RTMP streams)
            if let Some(ntdf_header) = metadata.custom_fields.get("ntdf_header") {
                log::info!(
                    "Found ntdf_header in metadata: {}... ({} chars)",
                    &ntdf_header[..ntdf_header.len().min(50)],
                    ntdf_header.len()
                );
                self.stream_registry
                    .set_ntdf_header(stream_key, ntdf_header.clone())
                    .await;

                // Set encryption mode to encrypted (NTDF stream detected)
                if self.encryption_mode == EncryptionMode::Pending {
                    self.encryption_mode = EncryptionMode::Encrypted;
                    log::info!(
                        "NTDF metadata received; enabling encrypted mode for {:?}",
                        self.stream_key
                    );
                }
                return Ok(());
            }
        }

        // No ntdf_header found - default to passthrough mode for standard RTMP streams
        if self.encryption_mode == EncryptionMode::Pending {
            self.encryption_mode = EncryptionMode::Passthrough;
            log::info!(
                "Standard metadata received (no ntdf_header); defaulting to passthrough mode for {:?}",
                self.stream_key
            );
        }

        Ok(())
    }

    /// Check if video data is a sequence header (AVC/HEVC decoder configuration)
    ///
    /// FLV video tag format:
    /// - Byte 0: Frame type (4 bits) + Codec ID (4 bits)
    ///   - Frame types: 1=keyframe, 2=inter, etc.
    ///   - Codec IDs: 7=AVC (H.264), 12=HEVC (H.265)
    /// - Byte 1: AVC packet type (0=sequence header, 1=NAL units, 2=end of sequence)
    fn is_video_sequence_header(data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }
        let frame_type = (data[0] >> 4) & 0x0F;
        let codec_id = data[0] & 0x0F;
        let avc_packet_type = data[1];

        // Keyframe (1) + AVC (7) or HEVC (12) + Sequence header (0)
        frame_type == 1 && (codec_id == 7 || codec_id == 12) && avc_packet_type == 0
    }

    /// Check if this is an NTDF header frame (magic bytes "NTDF" at offset 5)
    /// Format: [FLV header 5 bytes][Magic "NTDF" 4 bytes][length 2 bytes][header bytes]
    fn is_ntdf_header_frame(data: &[u8]) -> bool {
        // Need at least 9 bytes: 5 FLV header + 4 magic
        if data.len() < 9 {
            return false;
        }
        // Check for NTDF magic at offset 5 (0x4E 0x54 0x44 0x46 = "NTDF")
        data[5] == 0x4E && data[6] == 0x54 && data[7] == 0x44 && data[8] == 0x46
    }

    /// Check if audio data is a sequence header (AAC decoder configuration)
    ///
    /// FLV audio tag format:
    /// - Byte 0: Sound format (4 bits) + rate (2 bits) + size (1 bit) + type (1 bit)
    ///   - Sound format 10 = AAC
    /// - Byte 1: AAC packet type (0=sequence header, 1=raw data)
    fn is_audio_sequence_header(data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }
        let sound_format = (data[0] >> 4) & 0x0F;
        let aac_packet_type = data[1];

        // AAC (10) + Sequence header (0)
        sound_format == 10 && aac_packet_type == 0
    }

    /// Handle video data
    async fn handle_video_data(
        &mut self,
        data: &Bytes,
        timestamp: &RtmpTimestamp,
    ) -> Result<(), SessionError> {
        // Increment frame counter
        self.frame_count += 1;

        // Debug: log timestamps for first 10 frames and every 100th
        if self.frame_count <= 10 || self.frame_count % 100 == 0 {
            log::info!(
                "📹 Video frame #{}: timestamp={} ms, size={} bytes",
                self.frame_count,
                timestamp.value,
                data.len()
            );
        }

        match self.role {
            SessionRole::Publisher => {
                // Emit stream_started event on first video frame
                self.emit_stream_started_if_needed().await;

                // Check if this is a sequence header and cache it for late joiners
                if Self::is_video_sequence_header(data) {
                    if let Some(ref stream_key) = self.stream_key {
                        log::info!("Caching video sequence header for {}", stream_key);
                        self.stream_registry
                            .set_video_sequence_header(stream_key, data.to_vec())
                            .await;
                    }
                }

                // Check if this is an NTDF header frame (magic bytes "NTDF" at offset 5)
                if Self::is_ntdf_header_frame(data) {
                    log::info!(
                        "📤 NTDF header frame detected in video data ({} bytes), relaying to subscribers",
                        data.len()
                    );
                }

                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        // Encrypt video frame with Collection (server-side encryption)
                        if let Some(ref collection) = self.collection {
                            // Check rotation threshold
                            if rotation_threshold_reached(collection) {
                                log::warn!(
                                    "IV rotation threshold reached for stream {:?} - consider key rotation",
                                    self.stream_key
                                );
                            }

                            let encrypted = encrypt_item(collection, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

                            // Relay encrypted frame to subscribers
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Video,
                                timestamp: timestamp.value,
                                data: encrypted,
                            });
                        } else {
                            // Client-side encryption (NTDF): relay frames as-is
                            // The client has already encrypted the data before sending
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Video,
                                timestamp: timestamp.value,
                                data: data.to_vec(),
                            });
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Relay cleartext frame to subscribers
                        self.relay_frame(RelayFrame {
                            frame_type: FrameType::Video,
                            timestamp: timestamp.value,
                            data: data.to_vec(),
                        });
                    }
                    EncryptionMode::Pending => {
                        // First video frame before metadata - auto-set passthrough
                        if !self.metadata_received {
                            self.encryption_mode = EncryptionMode::Passthrough;
                            log::info!(
                                "Video data before metadata; defaulting to passthrough mode"
                            );
                            // Relay this frame
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Video,
                                timestamp: timestamp.value,
                                data: data.to_vec(),
                            });
                        }
                    }
                }
            }
            SessionRole::Subscriber => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        // Decrypt video frame with Decryptor
                        if let Some(ref decryptor) = self.decryptor {
                            let _decrypted = decrypt_item(decryptor, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;
                            // Would send decrypted frame to player
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Handle cleartext video
                        // Would send frame directly to player
                    }
                    EncryptionMode::Pending => {
                        // Waiting for mode determination
                    }
                }
            }
            SessionRole::Unknown => {
                log::warn!("Received video data with unknown role");
            }
        }

        Ok(())
    }

    /// Handle audio data
    async fn handle_audio_data(
        &mut self,
        data: &Bytes,
        timestamp: &RtmpTimestamp,
    ) -> Result<(), SessionError> {
        // Increment frame counter
        self.frame_count += 1;

        match self.role {
            SessionRole::Publisher => {
                // Check if this is a sequence header and cache it for late joiners
                if Self::is_audio_sequence_header(data) {
                    if let Some(ref stream_key) = self.stream_key {
                        log::info!("Caching audio sequence header for {}", stream_key);
                        self.stream_registry
                            .set_audio_sequence_header(stream_key, data.to_vec())
                            .await;
                    }
                }

                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        if let Some(ref collection) = self.collection {
                            // Server-side encryption
                            let encrypted = encrypt_item(collection, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Audio,
                                timestamp: timestamp.value,
                                data: encrypted,
                            });
                        } else {
                            // Client-side encryption (NTDF): relay frames as-is
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Audio,
                                timestamp: timestamp.value,
                                data: data.to_vec(),
                            });
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Relay cleartext audio
                        self.relay_frame(RelayFrame {
                            frame_type: FrameType::Audio,
                            timestamp: timestamp.value,
                            data: data.to_vec(),
                        });
                    }
                    EncryptionMode::Pending => {
                        // Pending - will be handled when mode is set
                    }
                }
            }
            SessionRole::Subscriber => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        if let Some(ref decryptor) = self.decryptor {
                            let _decrypted = decrypt_item(decryptor, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Handle cleartext audio directly
                    }
                    EncryptionMode::Pending => {}
                }
            }
            SessionRole::Unknown => {}
        }

        Ok(())
    }

    /// Set manifest for subscriber and create decryptor
    fn set_manifest_subscriber(&mut self, manifest: NanoTdfManifest) -> Result<(), SessionError> {
        // opentdf-rs derives the DEK itself and wants the key as PKCS#8 DER
        // (`EcdhKem::derive_key_with_private` accepts SEC1 DER or PKCS#8 DER),
        // so the encoding is produced here and dropped at the end of this call.
        // `SecretDocument` zeroizes on drop - the DER never becomes a `Vec`.
        let kas_private_key_der = self
            .kas_private_key
            .as_secret_key()
            .map_err(|e| SessionError::EncryptionError(e.to_string()))?
            .to_pkcs8_der()
            .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

        // Create decryptor from manifest header bytes and KAS private key
        let decryptor =
            create_decryptor_kas(&manifest.header_bytes, kas_private_key_der.as_bytes())
                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

        self.manifest = Some(manifest);
        self.decryptor = Some(decryptor);
        self.encryption_mode = EncryptionMode::Encrypted;

        log::debug!("Decryptor created successfully from manifest");
        Ok(())
    }

    /// Set collection for publisher (called when publisher provides manifest)
    pub fn set_collection(&mut self, collection: Arc<NanoTdfCollection>) {
        self.collection = Some(collection);
        self.encryption_mode = EncryptionMode::Encrypted;
        log::debug!("Collection set for publisher encryption");
    }

    /// Relay frame to all subscribers via broadcast channel
    fn relay_frame(&self, frame: RelayFrame) {
        if let Some(ref sender) = self.frame_sender {
            // Broadcast to all subscribers - ignore errors (no subscribers or lagging)
            let _ = sender.send(frame);
        }
    }

    /// Get current manifest if available
    pub fn get_manifest(&self) -> Option<&NanoTdfManifest> {
        self.manifest.as_ref()
    }

    /// Check if encryption is ready (collection for publisher, decryptor for subscriber)
    pub fn is_encryption_ready(&self) -> bool {
        match self.role {
            SessionRole::Publisher => self.collection.is_some(),
            SessionRole::Subscriber => self.decryptor.is_some(),
            SessionRole::Unknown => false,
        }
    }

    /// Get session role
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Get stream key
    pub fn stream_key(&self) -> Option<&str> {
        self.stream_key.as_deref()
    }

    /// Emit stream_started event if not already sent
    async fn emit_stream_started_if_needed(&mut self) {
        if self.started_event_sent {
            return;
        }

        if self.role != SessionRole::Publisher {
            return;
        }

        if let Some(ref stream_key) = self.stream_key {
            if let Some(ref broadcaster) = self.event_broadcaster {
                // Get manifest header if available (for NTDF streams)
                let manifest_header = self.manifest.as_ref().map(|m| {
                    base64::Engine::encode(&base64::prelude::BASE64_STANDARD, &m.header_bytes)
                });

                broadcaster
                    .stream_started(stream_key, manifest_header.as_deref(), None)
                    .await;

                self.started_event_sent = true;
                log::info!("Emitted stream_started event for {}", stream_key);
            }
        }
    }

    /// Extract ntdf_header from AMF0 values (from @setDataFrame or onMetaData)
    ///
    /// The ntdf_header is a base64-encoded NanoTDF header sent by NTDF-aware publishers.
    /// It can be found in:
    /// - An Object with "ntdf_header" key
    /// - A nested structure where the second value is an Object containing "ntdf_header"
    async fn extract_ntdf_header_from_amf(&mut self, values: &[Amf0Value]) {
        // Log what we received for debugging
        log::debug!("Extracting ntdf_header from {} AMF values", values.len());

        for (i, value) in values.iter().enumerate() {
            log::trace!("AMF value {}: {:?}", i, value);

            // Check if this value is an Object containing ntdf_header
            if let Some(ntdf_header) = Self::extract_ntdf_from_value(value) {
                log::info!(
                    "Found ntdf_header in AMF value {}: {}...",
                    i,
                    &ntdf_header[..ntdf_header.len().min(50)]
                );

                // Cache in registry for late joiners
                if let Some(ref stream_key) = self.stream_key {
                    self.stream_registry
                        .set_ntdf_header(stream_key, ntdf_header)
                        .await;
                }
                return;
            }
        }

        log::debug!("No ntdf_header found in AMF values");
    }

    /// Recursively extract ntdf_header from an Amf0Value
    fn extract_ntdf_from_value(value: &Amf0Value) -> Option<String> {
        match value {
            Amf0Value::Object(map) => {
                // Check if this object has ntdf_header
                if let Some(Amf0Value::Utf8String(header)) = map.get("ntdf_header") {
                    return Some(header.clone());
                }
                // Check nested objects
                for v in map.values() {
                    if let Some(header) = Self::extract_ntdf_from_value(v) {
                        return Some(header);
                    }
                }
                None
            }
            Amf0Value::StrictArray(arr) => {
                for v in arr {
                    if let Some(header) = Self::extract_ntdf_from_value(v) {
                        return Some(header);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_role() {
        assert_eq!(SessionRole::Unknown, SessionRole::Unknown);
        assert_ne!(SessionRole::Publisher, SessionRole::Subscriber);
    }

    #[test]
    fn test_relay_frame() {
        let frame = RelayFrame {
            frame_type: FrameType::Video,
            timestamp: 12345,
            data: vec![1, 2, 3, 4],
        };

        assert_eq!(frame.frame_type, FrameType::Video);
        assert_eq!(frame.timestamp, 12345);
        assert_eq!(frame.data.len(), 4);
    }
}
