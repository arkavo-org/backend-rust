/// C2PA Signing Server Module
///
/// Provides server-side C2PA manifest signing for video content.
/// Clients compute hash-exclusion ranges locally and send hashes to this server for signing.
///
/// This enables efficient workflows where multi-gigabyte video files don't need to be uploaded
/// for signing - only metadata and pre-computed hashes are transmitted.
use crate::modules::cwt_auth::{require_cwt, CwtAuthState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use c2pa::{Builder, HashRange, Reader, SigningAlg};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::Arc;

// ==================== Configuration ====================

/// C2PA signing configuration
pub struct C2paConfig {
    pub signing_key_path: String,
    pub signing_cert_path: String,
    pub _require_validation: bool, // Reserved for future use
    pub allowed_creators: Vec<String>,
}

impl C2paConfig {
    /// Load C2PA configuration from environment variables
    pub fn from_env() -> Result<Self, String> {
        use log::info;

        info!("Loading C2PA configuration from environment...");

        let signing_key_path = std::env::var("C2PA_SIGNING_KEY_PATH")
            .map_err(|_| "C2PA_SIGNING_KEY_PATH not set".to_string())?;

        info!("C2PA_SIGNING_KEY_PATH: {}", signing_key_path);

        let signing_cert_path = std::env::var("C2PA_SIGNING_CERT_PATH")
            .map_err(|_| "C2PA_SIGNING_CERT_PATH not set".to_string())?;

        info!("C2PA_SIGNING_CERT_PATH: {}", signing_cert_path);

        // Check if files exist and are readable
        if !std::path::Path::new(&signing_key_path).exists() {
            return Err(format!("C2PA signing key not found: {}", signing_key_path));
        }
        info!("C2PA signing key file exists");

        if !std::path::Path::new(&signing_cert_path).exists() {
            return Err(format!(
                "C2PA signing cert not found: {}",
                signing_cert_path
            ));
        }
        info!("C2PA signing cert file exists");

        let _require_validation = std::env::var("C2PA_REQUIRE_VALIDATION")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let allowed_creators = std::env::var("C2PA_ALLOWED_CREATORS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        info!("C2PA configuration loaded successfully");

        Ok(Self {
            signing_key_path,
            signing_cert_path,
            _require_validation,
            allowed_creators,
        })
    }
}

// ==================== Request/Response Types ====================

/// Hash exclusion range for ISOBMFF box-based hashing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExclusionRange {
    pub start: u64,
    pub end: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_type: Option<String>, // e.g., "uuid", "mdat"
}

/// Video container format
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerFormat {
    Mp4,
    Mov,
    Avi,
}

/// C2PA content metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct C2paMetadata {
    pub title: String,
    pub creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, // ISO 8601 format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
}

/// C2PA signing request
#[derive(Debug, Deserialize)]
pub struct C2paSignRequest {
    /// SHA-256 hash of the content (hex-encoded)
    pub content_hash: String,
    /// ISOBMFF box exclusion ranges
    pub exclusion_ranges: Vec<ExclusionRange>,
    /// Container format (mp4, mov, avi)
    pub container_format: ContainerFormat,
    /// Content metadata
    pub metadata: C2paMetadata,
}

/// C2PA signing response
#[derive(Debug, Serialize)]
pub struct C2paSignResponse {
    /// Signed C2PA manifest in JUMBF format (base64-encoded)
    pub manifest: String,
    /// Manifest hash for verification
    pub manifest_hash: String,
    /// Status message
    pub status: String,
}

/// C2PA validation request
#[derive(Debug, Deserialize)]
pub struct C2paValidateRequest {
    /// C2PA manifest (base64-encoded JUMBF data)
    pub manifest: String,
    /// Content hash to validate against (hex-encoded)
    pub content_hash: String,
}

/// Provenance chain entry
#[derive(Debug, Serialize)]
pub struct ProvenanceEntry {
    pub action: String, // e.g., "created", "edited"
    pub actor: String,
    pub timestamp: Option<String>,
    pub software: Option<String>,
}

/// C2PA validation response
#[derive(Debug, Serialize)]
pub struct C2paValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_chain: Option<Vec<ProvenanceEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<bool>,
}

// ==================== Shared State ====================

pub struct C2paSigningState {
    pub config: C2paConfig,
}

impl C2paSigningState {
    pub fn new(config: C2paConfig) -> Self {
        Self { config }
    }
}

// ==================== Router ====================

/// C2PA signing routes. Both require a CWT bearer: `/c2pa/v1/sign` signs a
/// caller-supplied manifest hash with this server's C2PA private key, so an
/// ungated route would be a signing oracle minting Arkavo-attributed
/// provenance for anyone who can reach the port. Neither route is in the
/// spec's public-route list.
pub fn router(state: Arc<C2paSigningState>, auth: Arc<CwtAuthState>) -> Router {
    Router::new()
        .route("/c2pa/v1/sign", post(sign_manifest))
        .route("/c2pa/v1/validate", post(validate_manifest))
        .layer(axum::middleware::from_fn_with_state(auth, require_cwt))
        .with_state(state)
}

// ==================== API Handlers ====================

/// POST /c2pa/v1/sign - Sign C2PA manifest with pre-computed hash
pub async fn sign_manifest(
    State(state): State<Arc<C2paSigningState>>,
    Json(req): Json<C2paSignRequest>,
) -> Response {
    info!(
        "C2PA signing request from creator: {}, format: {:?}",
        req.metadata.creator, req.container_format
    );

    // Validate creator if allowlist is configured
    if !state.config.allowed_creators.is_empty()
        && !state
            .config
            .allowed_creators
            .contains(&req.metadata.creator)
    {
        warn!(
            "C2PA signing denied: creator '{}' not in allowlist",
            req.metadata.creator
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Creator not authorized",
                "status": "denied"
            })),
        )
            .into_response();
    }

    // Validate hash format (should be hex-encoded SHA-256)
    if req.content_hash.len() != 64 || !req.content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Invalid content hash format: {}", req.content_hash);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid content hash format (expected 64 hex chars)",
                "status": "error"
            })),
        )
            .into_response();
    }

    // Build C2PA manifest
    match build_c2pa_manifest(&state.config, &req).await {
        Ok((manifest, manifest_hash)) => {
            info!("C2PA manifest signed successfully");
            (
                StatusCode::OK,
                Json(C2paSignResponse {
                    manifest,
                    manifest_hash,
                    status: "success".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("C2PA signing failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Signing failed: {}", e),
                    "status": "error"
                })),
            )
                .into_response()
        }
    }
}

/// POST /c2pa/v1/validate - Validate C2PA manifest
pub async fn validate_manifest(
    State(_state): State<Arc<C2paSigningState>>,
    Json(req): Json<C2paValidateRequest>,
) -> Response {
    info!("C2PA validation request");

    // Decode base64 manifest
    let manifest_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.manifest) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode manifest: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(C2paValidateResponse {
                        valid: false,
                        errors: vec![format!("Invalid base64 encoding: {}", e)],
                        creator: None,
                        provenance_chain: None,
                        ai_generated: None,
                    }),
                )
                    .into_response();
            }
        };

    // Parse and validate C2PA manifest
    match validate_c2pa_manifest(&manifest_bytes, &req.content_hash) {
        Ok(response) => {
            if response.valid {
                info!("C2PA manifest validation successful");
            } else {
                warn!("C2PA manifest validation failed: {:?}", response.errors);
            }
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("C2PA validation error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(C2paValidateResponse {
                    valid: false,
                    errors: vec![format!("Validation error: {}", e)],
                    creator: None,
                    provenance_chain: None,
                    ai_generated: None,
                }),
            )
                .into_response()
        }
    }
}

// ==================== C2PA Implementation ====================

/// Build and sign a C2PA manifest using the hashed-data signing workflow.
///
/// The client computes a content hash with exclusion ranges and sends it to the server.
/// The server constructs a C2PA manifest with assertions, signs it using the configured
/// credentials, and returns the signed JUMBF manifest bytes for the client to embed.
async fn build_c2pa_manifest(
    config: &C2paConfig,
    req: &C2paSignRequest,
) -> Result<(String, String), String> {
    info!("Loading C2PA signing credentials...");

    let cert_chain = std::fs::read(&config.signing_cert_path)
        .map_err(|e| format!("Failed to read certificate: {}", e))?;

    let private_key = std::fs::read(&config.signing_key_path)
        .map_err(|e| format!("Failed to read private key: {}", e))?;

    // Use "c2pa" format for sign_data_hashed_embeddable to produce standalone JUMBF.
    // The client is responsible for embedding the JUMBF into the actual container
    // format (MP4, MOV, etc.) at the correct location.
    let _container_format = match req.container_format {
        ContainerFormat::Mp4 => "video/mp4",
        ContainerFormat::Mov => "video/quicktime",
        ContainerFormat::Avi => "video/avi",
    };
    let mime_type = "c2pa";

    // Build a C2PA manifest with assertions
    let mut builder = Builder::new();

    builder
        .add_assertion(
            "c2pa.created",
            &serde_json::json!({
                "timestamp": req.metadata.timestamp.as_ref()
                    .unwrap_or(&chrono::Utc::now().to_rfc3339()),
            }),
        )
        .map_err(|e| format!("Failed to add created assertion: {}", e))?;

    builder
        .add_assertion(
            "c2pa.claim.creator",
            &serde_json::json!({
                "name": req.metadata.creator,
            }),
        )
        .map_err(|e| format!("Failed to add creator assertion: {}", e))?;

    if !req.metadata.title.is_empty() {
        builder
            .add_assertion(
                "dc.title",
                &serde_json::json!({
                    "title": req.metadata.title,
                }),
            )
            .map_err(|e| format!("Failed to add title assertion: {}", e))?;
    }

    if let Some(ai_generated) = req.metadata.ai_generated {
        builder
            .add_assertion(
                "c2pa.ai_generated",
                &serde_json::json!({
                    "ai_generated": ai_generated,
                }),
            )
            .map_err(|e| format!("Failed to add AI assertion: {}", e))?;
    }

    if let Some(ref software) = req.metadata.software {
        builder
            .add_assertion(
                "stds.exif",
                &serde_json::json!({
                    "Software": software,
                }),
            )
            .map_err(|e| format!("Failed to add software assertion: {}", e))?;
    }

    // Store content hash as a custom assertion so it can be retrieved during validation
    builder
        .add_assertion(
            "org.arkavo.c2pa.content_hash",
            &serde_json::json!({
                "hash": req.content_hash,
                "algorithm": "sha256",
                "exclusion_ranges": req.exclusion_ranges,
            }),
        )
        .map_err(|e| format!("Failed to add hash assertion: {}", e))?;

    // Build DataHash from client-provided hash and exclusion ranges.
    // Name must be "jumbf manifest" to match what sign_data_hashed_embeddable expects.
    let mut data_hash = c2pa::assertions::DataHash::new("jumbf manifest", "sha256");

    let content_hash_bytes = hex::decode(&req.content_hash)
        .map_err(|e| format!("Failed to decode content hash: {}", e))?;
    data_hash.set_hash(content_hash_bytes);

    for range in &req.exclusion_ranges {
        let length = range.end.saturating_sub(range.start);
        data_hash.add_exclusion(HashRange::new(range.start, length));
    }

    // Add DataHash as the required hash binding assertion (c2pa.hash.data).
    // This is required by sign_data_hashed_embeddable to indicate how the
    // manifest is bound to the asset's content.
    builder
        .add_assertion(c2pa::assertions::DataHash::LABEL, &data_hash)
        .map_err(|e| format!("Failed to add data hash assertion: {}", e))?;

    // Create signer using ES256 (ECDSA with P-256)
    info!("Creating C2PA signer with ES256...");
    let signer = c2pa::create_signer::from_keys(&cert_chain, &private_key, SigningAlg::Es256, None)
        .map_err(|e| format!("Failed to create signer: {}", e))?;

    // Sign with the hashed-data workflow: produces JUMBF bytes for client embedding
    info!("Signing C2PA manifest with data-hashed workflow...");
    let manifest_bytes = builder
        .sign_data_hashed_embeddable(&*signer, &data_hash, mime_type)
        .map_err(|e| format!("C2PA signing failed: {}", e))?;

    info!(
        "C2PA manifest signed: {} bytes of JUMBF data",
        manifest_bytes.len()
    );

    let manifest_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &manifest_bytes);

    // Compute manifest hash for verification
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&manifest_bytes);
    let manifest_hash = hex::encode(hasher.finalize());

    Ok((manifest_b64, manifest_hash))
}

/// Validate a C2PA manifest by parsing JUMBF data and verifying the signature chain.
///
/// Server-side validation verifies the COSE signature chain and extracts metadata.
/// Full asset-hash binding verification requires the actual asset (done client-side).
fn validate_c2pa_manifest(
    manifest_bytes: &[u8],
    expected_hash: &str,
) -> Result<C2paValidateResponse, String> {
    // Use Reader to parse JUMBF and verify signature chain.
    // We provide an empty stream since the actual asset is on the client side;
    // the Reader will still verify COSE signatures on the manifest itself.
    let empty_stream = Cursor::new(Vec::<u8>::new());
    let reader = Reader::from_manifest_data_and_stream(manifest_bytes, "video/mp4", empty_stream)
        .map_err(|e| format!("Failed to parse C2PA manifest: {}", e))?;

    let mut errors = Vec::new();
    let mut creator = None;
    let mut ai_generated = None;
    let mut provenance_chain = Vec::new();

    // Check validation status from c2pa-rs signature verification
    if let Some(statuses) = reader.validation_status() {
        for status in statuses {
            // validation_status returns errors/warnings - any entry indicates a problem
            errors.push(format!("C2PA validation: {}", status.code()));
        }
    }

    // Extract metadata from the active manifest
    if let Some(manifest) = reader.active_manifest() {
        // Extract assertions by iterating through all manifest assertions
        for assertion in manifest.assertions() {
            let label = assertion.label();

            if label == "c2pa.claim.creator" {
                if let Ok(data) = assertion.to_assertion::<serde_json::Value>() {
                    creator = data.get("name").and_then(|n| n.as_str()).map(String::from);
                }
            }

            if label == "c2pa.ai_generated" {
                if let Ok(data) = assertion.to_assertion::<serde_json::Value>() {
                    ai_generated = data.get("ai_generated").and_then(|v| v.as_bool());
                }
            }

            if label == "org.arkavo.c2pa.content_hash" {
                if let Ok(data) = assertion.to_assertion::<serde_json::Value>() {
                    if let Some(hash_value) = data.get("hash").and_then(|h| h.as_str()) {
                        if hash_value != expected_hash {
                            errors.push(format!(
                                "Hash mismatch: expected {}, got {}",
                                expected_hash, hash_value
                            ));
                        }
                    } else {
                        errors.push("Content hash assertion missing hash value".to_string());
                    }
                }
            }

            if label == "c2pa.created" {
                if let Ok(data) = assertion.to_assertion::<serde_json::Value>() {
                    let timestamp = data
                        .get("timestamp")
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    provenance_chain.push(ProvenanceEntry {
                        action: "created".to_string(),
                        actor: creator.clone().unwrap_or_default(),
                        timestamp,
                        software: None,
                    });
                }
            }

            if label == "stds.exif" {
                if let Ok(data) = assertion.to_assertion::<serde_json::Value>() {
                    if let Some(sw) = data.get("Software").and_then(|s| s.as_str()) {
                        // Update the last provenance entry with software info
                        if let Some(last) = provenance_chain.last_mut() {
                            last.software = Some(sw.to_string());
                        }
                    }
                }
            }
        }
    } else {
        errors.push("No active manifest found".to_string());
    }

    let chain = if provenance_chain.is_empty() {
        None
    } else {
        Some(provenance_chain)
    };

    Ok(C2paValidateResponse {
        valid: errors.is_empty(),
        errors,
        creator,
        provenance_chain: chain,
        ai_generated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusion_range_serialization() {
        let range = ExclusionRange {
            start: 100,
            end: 500,
            box_type: Some("uuid".to_string()),
        };
        let json = serde_json::to_string(&range).unwrap();
        assert!(json.contains("\"start\":100"));
        assert!(json.contains("\"end\":500"));
        assert!(json.contains("\"box_type\":\"uuid\""));
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = C2paMetadata {
            title: "Test Video".to_string(),
            creator: "test@example.com".to_string(),
            description: None,
            timestamp: Some("2025-10-26T00:00:00Z".to_string()),
            ai_generated: Some(true),
            software: Some("Arkavo KAS".to_string()),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"ai_generated\":true"));
    }

    /// Generate a CA + end-entity EC cert chain for C2PA signing tests.
    /// C2PA requires non-self-signed certificates.
    /// Returns (cert_chain_pem_path, end_entity_key_pem_path) in a temp directory.
    fn generate_test_certs() -> (std::path::PathBuf, std::path::PathBuf) {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let thread_id = format!("{:?}", std::thread::current().id());
        let dir = std::env::temp_dir().join(format!(
            "c2pa_test_certs_{}_{}",
            unique_id,
            thread_id.replace(|c: char| !c.is_alphanumeric(), "_")
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let ca_key_path = dir.join("ca_key.pem");
        let ca_cert_path = dir.join("ca_cert.pem");
        let ee_key_path = dir.join("ee_key.pem");
        let ee_csr_path = dir.join("ee_csr.pem");
        let ee_cert_path = dir.join("ee_cert.pem");
        let chain_path = dir.join("cert_chain.pem");

        // Generate CA key
        let status = std::process::Command::new("openssl")
            .args([
                "ecparam",
                "-genkey",
                "-name",
                "prime256v1",
                "-noout",
                "-out",
            ])
            .arg(&ca_key_path)
            .status()
            .expect("openssl must be available for tests");
        assert!(status.success(), "Failed to generate CA key");

        // Generate self-signed CA cert (CA=TRUE)
        let status = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&ca_key_path)
            .args(["-out"])
            .arg(&ca_cert_path)
            .args([
                "-days",
                "1",
                "-subj",
                "/CN=Test CA/O=Arkavo Test CA/C=US",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ])
            .status()
            .expect("openssl must be available");
        assert!(status.success(), "Failed to generate CA cert");

        // Generate end-entity key
        let status = std::process::Command::new("openssl")
            .args([
                "ecparam",
                "-genkey",
                "-name",
                "prime256v1",
                "-noout",
                "-out",
            ])
            .arg(&ee_key_path)
            .status()
            .expect("openssl must be available");
        assert!(status.success(), "Failed to generate EE key");

        // Generate CSR for end-entity
        let status = std::process::Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&ee_key_path)
            .args(["-out"])
            .arg(&ee_csr_path)
            .args(["-subj", "/CN=C2PA Test Signer/O=Arkavo Test/C=US"])
            .status()
            .expect("openssl must be available");
        assert!(status.success(), "Failed to generate CSR");

        // Write extensions config for the end-entity cert.
        // C2PA requires: digitalSignature key usage + emailProtection EKU.
        let ext_path = dir.join("ee_ext.cnf");
        std::fs::write(
            &ext_path,
            "keyUsage=critical,digitalSignature\n\
             basicConstraints=CA:FALSE\n\
             extendedKeyUsage=emailProtection\n\
             subjectKeyIdentifier=hash\n\
             authorityKeyIdentifier=keyid:always\n",
        )
        .unwrap();

        // Sign end-entity cert with CA
        let status = std::process::Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&ee_csr_path)
            .args(["-CA"])
            .arg(&ca_cert_path)
            .args(["-CAkey"])
            .arg(&ca_key_path)
            .args(["-CAcreateserial", "-out"])
            .arg(&ee_cert_path)
            .args(["-days", "1", "-extfile"])
            .arg(&ext_path)
            .status()
            .expect("openssl must be available");
        assert!(status.success(), "Failed to sign EE cert");

        // Create cert chain (end-entity + CA)
        let ee_cert = std::fs::read_to_string(&ee_cert_path).unwrap();
        let ca_cert = std::fs::read_to_string(&ca_cert_path).unwrap();
        std::fs::write(&chain_path, format!("{}{}", ee_cert, ca_cert)).unwrap();

        (chain_path, ee_key_path)
    }

    fn make_test_config() -> C2paConfig {
        let (cert_path, key_path) = generate_test_certs();
        C2paConfig {
            signing_key_path: key_path.to_str().unwrap().to_string(),
            signing_cert_path: cert_path.to_str().unwrap().to_string(),
            _require_validation: false,
            allowed_creators: vec![],
        }
    }

    fn make_test_request(content_hash: &str) -> C2paSignRequest {
        C2paSignRequest {
            content_hash: content_hash.to_string(),
            exclusion_ranges: vec![ExclusionRange {
                start: 100,
                end: 500,
                box_type: Some("uuid".to_string()),
            }],
            container_format: ContainerFormat::Mp4,
            metadata: C2paMetadata {
                title: "Test Video".to_string(),
                creator: "test@example.com".to_string(),
                description: Some("A test video".to_string()),
                timestamp: Some("2025-10-26T12:00:00Z".to_string()),
                ai_generated: Some(false),
                software: Some("Arkavo Test Suite".to_string()),
            },
        }
    }

    /// Round-trip test: sign a manifest and validate it, checking metadata preservation.
    #[tokio::test]
    async fn test_c2pa_sign_and_validate_round_trip() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign
        let (manifest_b64, manifest_hash) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        // Manifest should be non-empty base64
        assert!(!manifest_b64.is_empty(), "Manifest should not be empty");
        assert!(
            !manifest_hash.is_empty(),
            "Manifest hash should not be empty"
        );

        // Decode and validate
        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .expect("Should be valid base64");

        // Verify the manifest hash matches
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        let computed_hash = hex::encode(hasher.finalize());
        assert_eq!(manifest_hash, computed_hash, "Manifest hash should match");

        // Validate using c2pa-rs Reader
        let result =
            validate_c2pa_manifest(&manifest_bytes, hash).expect("Validation should not error");

        // Check metadata was preserved
        assert_eq!(
            result.creator.as_deref(),
            Some("test@example.com"),
            "Creator should be preserved"
        );
        assert_eq!(
            result.ai_generated,
            Some(false),
            "AI-generated flag should be preserved"
        );

        // Content hash should match
        assert!(
            !result.errors.iter().any(|e| e.contains("Hash mismatch")),
            "Content hash should match: {:?}",
            result.errors
        );
    }

    /// Test that validation detects a content hash mismatch.
    #[tokio::test]
    async fn test_c2pa_hash_mismatch_detected() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign with one hash
        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // Validate with a different hash
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = validate_c2pa_manifest(&manifest_bytes, wrong_hash)
            .expect("Validation should not error");

        assert!(
            result.errors.iter().any(|e| e.contains("Hash mismatch")),
            "Should detect hash mismatch, got errors: {:?}",
            result.errors
        );
    }

    /// Test that signing produces valid JUMBF (not JSON).
    #[tokio::test]
    async fn test_c2pa_produces_jumbf_not_json() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // JUMBF starts with a box header, not '{' (JSON) or other text
        assert!(
            manifest_bytes.len() > 8,
            "JUMBF manifest should be non-trivial size"
        );
        // Verify it's NOT plain JSON (the old fake implementation)
        let is_json = std::str::from_utf8(&manifest_bytes)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .is_some();
        assert!(!is_json, "Manifest should be JUMBF binary, not JSON");
    }

    /// Test signing with AI-generated flag set to true.
    #[tokio::test]
    async fn test_c2pa_ai_generated_flag() {
        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let mut req = make_test_request(hash);
        req.metadata.ai_generated = Some(true);

        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        let result =
            validate_c2pa_manifest(&manifest_bytes, hash).expect("Validation should not error");

        assert_eq!(
            result.ai_generated,
            Some(true),
            "AI-generated=true should be preserved"
        );
    }

    /// Test that invalid base64 is rejected during validation.
    #[test]
    fn test_c2pa_validate_invalid_jumbf() {
        // Random bytes that aren't valid JUMBF
        let invalid_bytes = b"this is not valid JUMBF data at all";
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";

        let result = validate_c2pa_manifest(invalid_bytes, hash);
        assert!(result.is_err(), "Should fail to parse invalid JUMBF");
    }

    /// c2patool interop: sign a manifest, write JUMBF to disk, validate with c2patool.
    /// Skipped if c2patool is not installed.
    #[tokio::test]
    async fn test_c2patool_interop_validation() {
        // Check if c2patool is available
        let c2patool_check = std::process::Command::new("c2patool")
            .arg("--version")
            .output();
        let c2patool_available = c2patool_check.map(|o| o.status.success()).unwrap_or(false);
        if !c2patool_available {
            eprintln!("SKIPPED: c2patool not installed");
            return;
        }

        let config = make_test_config();
        let hash = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        let req = make_test_request(hash);

        // Sign
        let (manifest_b64, _) = build_c2pa_manifest(&config, &req)
            .await
            .expect("Signing should succeed");

        let manifest_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &manifest_b64)
                .unwrap();

        // Write JUMBF to a .c2pa file for c2patool
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let jumbf_path = std::env::temp_dir().join(format!("c2pa_interop_{}.c2pa", unique_id));
        std::fs::write(&jumbf_path, &manifest_bytes).unwrap();

        // Run c2patool to read the manifest (detailed JSON output)
        let output = std::process::Command::new("c2patool")
            .arg(&jumbf_path)
            .arg("--detailed")
            .output()
            .expect("Failed to run c2patool");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // c2patool should be able to parse the JUMBF and produce JSON output
        assert!(
            output.status.success(),
            "c2patool should parse our JUMBF successfully.\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );

        // Verify the output is valid JSON with manifest data
        let c2pa_output: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "c2patool output should be valid JSON: {}\noutput: {}",
                e, stdout
            )
        });

        // Should contain a manifests section or active_manifest
        assert!(
            c2pa_output.get("manifests").is_some() || c2pa_output.get("active_manifest").is_some(),
            "c2patool output should contain manifest data: {}",
            stdout
        );

        // Verify our creator assertion is present somewhere in the output
        let output_str = stdout.to_string();
        assert!(
            output_str.contains("test@example.com"),
            "c2patool output should contain our creator: {}",
            stdout
        );

        // Clean up
        let _ = std::fs::remove_file(&jumbf_path);
    }
}

/// Route-level tests for the CWT gate on the C2PA signing routes.
///
/// `/c2pa/v1/sign` signs a caller-supplied hash with the server's C2PA private
/// key; ungated it is a signing oracle. The 401 is produced by the middleware
/// before the handler runs, so these need no real signing material — the state
/// below points at paths that do not exist and is never dereferenced.
#[cfg(test)]
mod route_tests {
    use super::*;
    use crate::modules::cwt_token::{test_support, CwtValidator};
    use tokio::net::TcpListener;

    fn signing_state() -> Arc<C2paSigningState> {
        Arc::new(C2paSigningState::new(C2paConfig {
            signing_key_path: "/nonexistent/key.pem".to_string(),
            signing_cert_path: "/nonexistent/cert.pem".to_string(),
            _require_validation: false,
            allowed_creators: vec![],
        }))
    }

    async fn spawn() -> (String, wiremock::MockServer) {
        let (_signer, set) = test_support::keypair_and_set();
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/.well-known/cose-keys"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_raw(set, "application/cbor"),
            )
            .mount(&mock)
            .await;
        let auth = Arc::new(crate::modules::cwt_auth::CwtAuthState {
            validator: Arc::new(CwtValidator::new(
                format!("{}/.well-known/cose-keys", mock.uri()),
                "https://identity.test".into(),
                "https://arks.test".into(),
            )),
        });
        let app = router(signing_state(), auth);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}"), mock)
    }

    #[tokio::test]
    async fn both_c2pa_routes_require_a_bearer() {
        let (base, _mock) = spawn().await;
        let c = reqwest::Client::new();
        for path in ["/c2pa/v1/sign", "/c2pa/v1/validate"] {
            let r = c
                .post(format!("{base}{path}"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 401, "{path} should require a bearer");
            // Plain-text body proves the middleware rejected it, not the handler.
            assert_eq!(r.text().await.unwrap(), "Missing Bearer CWT", "{path}");
        }
    }

    #[tokio::test]
    async fn c2pa_sign_with_invalid_bearer_is_401() {
        let (base, _mock) = spawn().await;
        let r = reqwest::Client::new()
            .post(format!("{base}/c2pa/v1/sign"))
            .bearer_auth("not-a-cwt")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        assert_eq!(r.text().await.unwrap(), "Invalid CWT");
    }
}
