# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust implementation of a Key Access Service (KAS) from the [OpenTDF specification](https://github.com/opentdf/spec). It provides secure key management, NanoTDF rewrap operations, and policy enforcement over WebSocket connections with NATS messaging and Redis caching.

**Binary name**: `arks` (ARKavo Server - KAS/DRM/C2PA real-time server)
**Library name**: `nanotdf`

## Development Commands

### Build
```bash
# Debug build
cargo build

# Release build (optimized for native CPU)
export RUSTFLAGS="-C target-cpu=native"
cargo build --release --bin arks

# Release build with FairPlay Streaming DRM (default)
./production/build.sh

# Release build without FairPlay
./production/build.sh --no-fairplay

# Release build with HTTP/3 (QUIC) support
cargo build --release --bin arks --features http3
```

**Quick Build Script:** The `production/build.sh` script automates release builds:
- With FairPlay (default): `./production/build.sh`
- Without FairPlay: `./production/build.sh --no-fairplay`
- Automatically detects platform and sets correct library paths
- Copies binary to `production/arks`
- Shows build summary with binary size and dependencies

### Testing
```bash
# Run all tests
cargo test --verbose

# Run a specific test
cargo test [test_name]
```

### Linting and Formatting
```bash
# Lint with clippy (same as CI)
cargo clippy --lib --bin arks --all-features -- -D warnings

# Check formatting (exclude vendor/fpssdk - Apple copyrighted code)
cargo fmt --check --package arkavo-rs --package fairplay-wrapper

# Apply formatting
cargo fmt --package arkavo-rs --package fairplay-wrapper
```

### Benchmarking
```bash
# Run benchmarks
cargo bench --bench benchmarks
```

### Running the Server
```bash
# Start dependencies
nats-server
redis-server

# Run the server
cargo run --bin arks
```

## Prerequisites

Install required dependencies:
```bash
brew install nats-server redis flatbuffers
```

### Key Generation (First Time Setup)

#### EC Key (Required - for NanoTDF)

Generate KAS EC private key:
```bash
openssl ecparam -genkey -name prime256v1 -noout -out recipient_private_key.pem
```

Validate the key:
```bash
openssl ec -in recipient_private_key.pem -text -noout
```

#### RSA Key (Optional - for Standard TDF / OpenTDFKit compatibility)

Generate KAS RSA-2048 private key:
```bash
openssl genrsa -out kas_rsa_private.pem 2048
```

Convert to PKCS#8 format (required for arks):
```bash
openssl pkcs8 -topk8 -inform PEM -outform PEM -in kas_rsa_private.pem -out kas_rsa_private_pkcs8.pem -nocrypt
```

Validate the key:
```bash
openssl rsa -in kas_rsa_private_pkcs8.pem -text -noout
```

Extract public key:
```bash
openssl rsa -in kas_rsa_private_pkcs8.pem -pubout -out kas_rsa_public.pem
```

#### TLS Certificates

Generate self-signed TLS certificates (for development):
```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=localhost"
```

### C2PA Signing Key Generation (Optional)

**Quick Setup (Recommended):**
```bash
./generate-c2pa-certs.sh
```

This generates:
- EC private key (P-256 curve, ES256 algorithm)
- Self-signed X.509 certificate valid for 1 year
- Proper file permissions (600 for private key)
- Location: Columbia, Maryland, US

**Manual Setup:**
```bash
# Generate EC private key (P-256 curve)
openssl ecparam -genkey -name prime256v1 -noout -out c2pa_private_key.pem

# Generate self-signed certificate (development only)
openssl req -new -x509 -key c2pa_private_key.pem -out c2pa_cert.pem -days 365 \
  -subj "/CN=Arkavo C2PA Signer/O=Arkavo/C=US/ST=Maryland/L=Columbia"
```

**Production:** Obtain certificates from a recognized CA or use the C2PA certificate infrastructure.

### FairPlay SDK Installation (Optional)

**Note:** FairPlay binaries are NOT included in this repository. See `docs/fairplay.md` for installation instructions.

Quick setup: Download SDK from Apple Developer Portal and copy `libfpscrypto` to `/usr/local/lib/`

## Architecture

### Core Components

**Binary** (`src/bin/main.rs`):
- Unified Axum server on single port (HTTP REST + WebSocket upgrade)
- Multi-threaded with optional TLS via rustls
- NATS integration for pub/sub messaging
- Redis integration for caching encrypted content
- Policy enforcement through pluggable contracts
- Handles ECDH key agreement, NanoTDF rewrap operations, and event routing

**Library** (`src/lib.rs`):
- NanoTDF binary parser implementing OpenTDF specification
- Supports Remote and Embedded policy types
- ECDSA signature verification with multiple curves (secp256r1, secp384r1, secp521r1, secp256k1)
- AES-GCM symmetric encryption modes

### Message Protocol

Binary messages use a type-byte prefix:
- `0x01`: PublicKey - ECDH key exchange
- `0x02`: KasPublicKey - KAS public key response
- `0x03`: Rewrap - NanoTDF rewrap request
- `0x04`: RewrappedKey - Rewrapped key response
- `0x05`: Nats - NATS message passthrough
- `0x06`: Event - FlatBuffers event handling

### Policy Contracts

Pluggable access control contracts in `src/bin/contracts/`:
- **Simple ABAC** (`contract_simple_abac.rs`): Attribute-based access control
- **Geofence** (`geo_fence_contract.rs`): 3D location-based access (lat/lon/altitude)
- **Content Rating** (`content_rating.rs`): Age-gated content filtering with rating categories (violent, sexual, profane, substance, hate, harm, mature, bully)
- **Media Policy** (`media_policy_contract.rs`): Streaming media DRM policy enforcement (subscriptions, rentals, geo-restrictions, concurrency, HDCP, device security)

Contracts are identified by unique SharedResource identifiers and enforce policy during rewrap operations.

### Event System

FlatBuffers-based event handling (schemas in `src/bin/schemas/`):
- **UserEvent**: Source-to-target user interactions with Redis retrieval
- **CacheEvent**: Store encrypted content in Redis with optional TTL and one-time access
- **RouteEvent**: Route events to specific user profiles via NATS subject `profile.<publicID>`

### Connection State

Each WebSocket connection maintains:
- Ephemeral ECDH shared secret with random salt
- JWT claims (subject/publicID and age verification)
- Bidirectional message channel for NATS subscription forwarding

### Cryptography

- **Key Agreement**: ECDH using P-256 (secp256r1) with custom x-coordinate extraction
- **Session Keys**: HKDF-SHA256 key derivation from shared secret
- **Symmetric Encryption**: AES-256-GCM for rewrapping data encryption keys (DEK)
- **TLS**: Minimum TLS 1.2, configurable certificate paths

## Configuration

Environment variables:
```bash
export PORT=8443                                   # Unified server port (HTTP + WebSocket)
export TLS_CERT_PATH=/path/to/fullchain.pem        # Optional, disables TLS if not set
export TLS_KEY_PATH=/path/to/privkey.pem
export KAS_KEY_PATH=/path/to/recipient_private_key.pem  # EC key for NanoTDF (required)
export KAS_RSA_KEY_PATH=/path/to/kas_rsa_private_pkcs8.pem  # RSA key for Standard TDF (optional)
export NATS_URL=nats://localhost:4222
export NATS_SUBJECT=nanotdf.messages
export REDIS_URL=redis://localhost:6379
export ENABLE_TIMING_LOGS=true                     # Performance logging
export RUST_LOG=info                               # Logging level

# Media DRM Configuration
export MAX_CONCURRENT_STREAMS=5                    # Max simultaneous streams per user
export ENABLE_MEDIA_ANALYTICS=true                 # Publish metrics to NATS
export MEDIA_METRICS_SUBJECT=media.metrics         # NATS subject for analytics events
export OAUTH_PUBLIC_KEY_PATH=/path/to/oauth_public.pem  # Optional JWT validation

# C2PA Content Authenticity Configuration (optional)
export C2PA_SIGNING_KEY_PATH=/path/to/c2pa_private_key.pem
export C2PA_SIGNING_CERT_PATH=/path/to/c2pa_cert.pem
export C2PA_REQUIRE_VALIDATION=true                # Enforce C2PA manifest validation
export C2PA_ALLOWED_CREATORS=creator1@example.com,creator2@example.com  # Optional creator whitelist

# FairPlay Streaming Configuration (optional, requires --features fairplay)
export FAIRPLAY_CREDENTIALS_PATH=/path/to/fps/credentials
# See "FairPlay SDK Installation" section above for library setup

# Chain Validation Configuration (optional - blockchain-based session validation)
export CHAIN_RPC_URL=ws://chain.arkavo.net          # Optional, disables chain validation if not set

# OpenTDF Platform Reverse Proxy Configuration (optional)
export OPENTDF_PLATFORM_URL=https://platform.svc:8443  # Upstream platform base URL
export KAS_PROXY_MODE=connect                          # off | connect | rest | both
```

**Note:** For RSA key support (Standard TDF / OpenTDFKit compatibility):
- RSA support is optional - server works with EC keys only if `KAS_RSA_KEY_PATH` is not set
- When configured, the server supports both EC (NanoTDF) and RSA (Standard TDF) rewrap operations
- Public key endpoint supports algorithm parameter: `/kas/v2/kas_public_key?algorithm=rsa`
- RSA keys must be in PKCS#8 PEM format (use `openssl pkcs8` command to convert)
- Compatible with OpenTDFKit iOS SDK and other Standard TDF clients

**Note:** For C2PA video content authenticity:
- C2PA signing is optional and disabled if environment variables are not set
- Generate signing keys as described in the "C2PA Signing Key Generation" section above
- See `docs/c2pa_video_drm.md` for detailed C2PA integration documentation
- C2PA works with the existing TDF3 media DRM system for authenticated, encrypted video delivery

**Note:** For FairPlay Streaming integration (Apple DRM):
- Install libfpscrypto library as described in the "FairPlay SDK Installation" section above
- Set FAIRPLAY_CREDENTIALS_PATH to your FairPlay credentials directory
- Build with `cargo build --features fairplay`

**Note:** For Chain Validation (blockchain-based session validation):
- Chain validation is optional and disabled if `CHAIN_RPC_URL` is not set
- When enabled, rewrap requests require a `chain_session_id` in the JWT payload
- The KAS queries the arkavo-node blockchain to validate session grants
- Session data is cached with a 6-second TTL for performance

**Note:** For OpenTDF Platform reverse-proxy:
- Proxying is optional and disabled when `KAS_PROXY_MODE` is `off` or unset.
- `connect` forwards `/kas.AccessService/*` ConnectRPC routes.
- `rest` forwards `/kas/v2/rewrap` and `/kas/v2/kas_public_key`, replacing the local OpenTDF-compat shim.
- `both` forwards all of the above.
- `/ws` (NanoTDF) always stays local. See `docs/platform-proxy.md`.

**Note:** For HTTP/3 (QUIC) support:
- Optional and disabled unless built with `--features http3`.
- Only spawned when TLS is enabled; binds UDP on the same `$PORT` as the TCP listener.
- Serves the HTTP request/response surface (rewrap, kas_public_key, media, `.well-known`); `/ws` stays on TCP/HTTP-1.1 (classic WebSockets can't ride HTTP/3).
- TCP responses advertise `Alt-Svc: h3=":$PORT"`. **Open UDP ingress** on `$PORT` (firewall/LB/security-groups).
- 0-RTT is disabled (replay safety for non-idempotent rewrap/key-request). See `docs/http3.md`.

## FlatBuffers Schema Compilation

If modifying schemas (typically not needed):
```bash
flatc --binary --rust idl/event.fbs
flatc --binary --rust idl/entity.fbs
flatc --binary --rust idl/metadata.fbs
```

Generated files are in `src/bin/schemas/`.

## Code Organization

- `src/lib.rs` - NanoTDF parser library
- `src/bin/main.rs` - WebSocket and HTTP server binary
- `src/bin/contracts/` - Policy enforcement modules
  - `c2pa_policy_contract.rs` - C2PA content authenticity validation
  - `media_policy_contract.rs` - Media DRM policy enforcement (includes C2PA integration)
  - `content_rating.rs` - Age-gated content filtering
  - `geo_fence_contract.rs` - Location-based access control
- `src/bin/schemas/` - FlatBuffers generated code
- `src/session_manager.rs` - Media playback session tracking (includes C2PA metadata)
- `src/media_metrics.rs` - Analytics and performance monitoring (includes C2PA events)
- `src/modules/c2pa_signing.rs` - C2PA signing server for video content authenticity
- `src/modules/http_rewrap.rs` - OpenTDF-compatible RESTful rewrap endpoint
- `src/modules/media_api.rs` - Media DRM-specific API endpoints
- `src/modules/fairplay.rs` - FairPlay Streaming integration (optional feature)
- `src/modules/crypto.rs` - Cryptographic primitives
- `vendor/fpssdk/` - Apple FairPlay SDK Rust module (optional)
- `crates/fairplay-wrapper/` - Safe Rust wrapper for FairPlay SDK (optional)
- `docs/c2pa_video_drm.md` - C2PA + TDF3 integration documentation
- `tests/` - Integration tests (includes `c2pa_video_tests.rs`)
- `benches/` - Performance benchmarks

## Media DRM Architecture

### Overview

The server implements a TDF3-based DRM system for HLS/DASH streaming media. Each media segment is individually protected as a TDF3 object, enabling policy-driven, secure media delivery.

### API Endpoints

**OpenTDF Compatibility:**
- `GET /kas/v2/kas_public_key` - Retrieve KAS public key
- `POST /kas/v2/rewrap` - OpenTDF rewrap endpoint (JWT-signed requests)

**C2PA Content Authenticity Endpoints:**
- `POST /c2pa/v1/sign` - Sign C2PA manifest with pre-computed hash
- `POST /c2pa/v1/validate` - Validate C2PA manifest
(See `docs/c2pa_video_drm.md` for detailed API documentation)

**Media DRM Endpoints:**
- `POST /media/v1/session/start` - Initialize playback session
- `POST /media/v1/key-request` - Request wrapped DEK for media segment (optimized fast path)
- `POST /media/v1/session/:session_id/heartbeat` - Update session activity
- `DELETE /media/v1/session/:session_id` - Terminate playback session

### Session Management

**Session Lifecycle:**
1. Client calls `/media/v1/session/start` with user/asset identifiers
2. Server validates concurrency limits and creates session in Redis
3. Client requests segment keys via `/media/v1/key-request`
4. Client sends periodic heartbeats to keep session alive (5-minute timeout)
5. Client terminates session when playback ends

**Session State:**
- `Starting` - Session created, not yet playing
- `Playing` - Active playback
- `Paused` - Playback paused
- `Stopped` - Playback finished

Sessions automatically expire after 5 minutes without heartbeat.

### Policy Enforcement

The **Media Policy Contract** (`src/bin/contracts/media_policy_contract.rs`) validates:

**Subscription Requirements:**
- Active subscription status
- Subscription tier (free, basic, premium)
- Content access level (e.g., UHD requires premium)

**Rental Windows:**
- Time-limited access from purchase (e.g., 7 days)
- Playback window from first play (e.g., 48 hours)
- First-play tracking stored in Redis

**Concurrency Limits:**
- Maximum simultaneous streams per user (configurable)
- Real-time session counting via Redis

**Geo-restrictions:**
- IP-based country filtering
- Content regional availability

**Device Security:**
- HDCP Type 0/1 requirements (HD/UHD content)
- Security level validation (baseline/main)
- Virtual machine detection and blocking

### Performance Metrics

**Key Delivery:**
- Target: < 50ms P95 latency
- Measured via in-memory sliding window (last 1000 requests)
- Exposed via `/metrics` endpoint (planned)

**Analytics Events:**
Published to NATS topics under `media.metrics.*`:
- `key_request` - Key delivery success/failure with latency
- `session_start` - Playback session initiated
- `session_end` - Playback session terminated
- `policy_denial` - Access denied with reason
- `concurrency_limit` - Concurrent stream limit hit
- `rental_window` - Rental first-play or expiry events

### TDF3 Media Workflow

**Content Preparation:**
1. Encrypt each HLS/DASH segment with unique DEK
2. Wrap segment as TDF3 object with embedded KAS URL
3. Generate HLS manifest referencing TDF3 segments

**Playback Flow:**
1. Client starts session → receives `session_id`
2. Client fetches HLS manifest
3. For each segment:
   - Client extracts NanoTDF header
   - Client requests key via `/media/v1/key-request` (sends header + session_id)
   - Server validates session, rewraps DEK, returns wrapped key
   - Client decrypts segment and plays
4. Client sends heartbeats during playback
5. Client terminates session on finish/error

### Rental Window Implementation

**Purchase Flow:**
- User purchases rental → server stores `purchase_timestamp`
- Rental duration: 7 days from purchase (configurable)

**First Play:**
- First key request sets `first_play_timestamp` in Redis
- Playback duration: 48 hours from first play (configurable)

**Validation:**
- Each key request checks both windows
- Access denied if either window expired

### Example Configuration

```bash
# Start dependencies
nats-server
redis-server

# Configure unified server (single port for HTTP + WebSocket)
export PORT=8443
export MAX_CONCURRENT_STREAMS=2
export ENABLE_MEDIA_ANALYTICS=true
export MEDIA_METRICS_SUBJECT=media.metrics

# Run server
./run-arks.sh
```

**Server Endpoints:**
- WebSocket: `ws://localhost:8443/ws`
- HTTP API: `http://localhost:8443/`
- KAS Public Key: `http://localhost:8443/kas/v2/kas_public_key`
- Media Key Request: `http://localhost:8443/media/v1/key-request`

## Important: Vendor Directory

- `vendor/fpssdk/` contains Apple copyrighted FairPlay SDK code — **NEVER modify these files**
- Do not run `cargo fmt --all` as it will reformat vendor code; use `cargo fmt --package arkavo-rs --package fairplay-wrapper` instead
- CI uses `cargo fmt --check --package arkavo-rs --package fairplay-wrapper` to avoid formatting vendor files

## Security Notes

- Private keys (KAS, TLS) must never be committed to version control
- JWT signature validation is disabled for development - enable in production via `OAUTH_PUBLIC_KEY_PATH`
- Self-signed certificates are for development only
- Session IDs should be treated as secrets (contain user_id + asset_id)
- Apple App Site Association file (`apple-app-site-association.json`) is served at `/.well-known/apple-app-site-association`
- put documentation under /docs .  for short-term (status-like) docs don't commit.