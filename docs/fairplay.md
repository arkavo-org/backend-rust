# FairPlay Streaming Integration

Apple FairPlay Streaming support for DRM-protected media delivery to Apple devices (iOS, tvOS, macOS, Safari).

**SDK Version:** 26
**Feature Flag:** `fairplay` (disabled by default)
**Status:** ✅ **Production Ready** - Implementation complete and all compilation issues resolved

## Overview

This integration provides dual-protocol DRM support:

- **TDF3** (NanoTDF): OpenTDF-based DRM for all platforms
- **FairPlay**: Apple-specific DRM for iOS/tvOS/macOS/Safari

Both protocols share unified session management and policy enforcement.

## Prerequisites

### 1. Apple FairPlay Streaming Agreement

Production deployment requires a valid Apple FairPlay Streaming agreement. Contact Apple Developer Relations.

### 2. FairPlay SDK

**SDK Rust Module:**
The SDK Rust module is included in `vendor/fpssdk/` (committed to repository).

**Cryptographic Library (libfpscrypto):**
The prebuilt binaries are **NOT** included in the repository for license compliance and security reasons. You must install them separately:

1. **Download FairPlay Streaming Server SDK 26** from [Apple Developer Portal](https://developer.apple.com/streaming/fps/)
2. **Extract to** `vendor/FairPlay_Streaming_Server_SDK_26/` (gitignored)
3. **Install libfpscrypto library**:

   **Option A: System-wide installation (recommended)**
   ```bash
   # macOS
   sudo cp vendor/FairPlay_Streaming_Server_SDK_26/Development/lib/macos/libfpscrypto.dylib /usr/local/lib/

   # Linux x86_64
   sudo cp vendor/FairPlay_Streaming_Server_SDK_26/Development/lib/linux/x86_64/libfpscrypto.so /usr/local/lib/

   # Linux ARM64
   sudo cp vendor/FairPlay_Streaming_Server_SDK_26/Development/lib/linux/aarch64/libfpscrypto.so /usr/local/lib/
   ```

   **Option B: Custom location**
   ```bash
   export FPSSDK_LIB_PATH=/path/to/fairplay/lib
   ```

   **Option C: Temporary build**
   ```bash
   LIBRARY_PATH=/path/to/fairplay/lib cargo build --features fairplay
   ```

4. **Credentials** are in `Development/Key_Server_Module/credentials/`

### 3. Credentials

- **Development credentials**: For testing (included with SDK)
- **Production credentials**: Obtain from Apple Developer Portal

⚠️ **Never commit credentials to version control**

## Building

**Prerequisites:** Install libfpscrypto as described above.

```bash
# Build WITHOUT FairPlay (default)
cargo build

# Build WITH FairPlay
cargo build --features fairplay

# If library not in system path, use LIBRARY_PATH
LIBRARY_PATH=/usr/local/lib cargo build --features fairplay

# Run with FairPlay
export FAIRPLAY_CREDENTIALS_PATH=./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials
# macOS runtime (if library not in system path)
export DYLD_LIBRARY_PATH=/usr/local/lib
cargo run --features fairplay

# Test with FairPlay (when tests are updated)
cargo test --features fairplay
```

**Build Output:**
You should see one of:
- `Using FairPlay SDK from system path: /usr/local/lib`
- `Using FairPlay SDK from FPSSDK_LIB_PATH: /custom/path`
- `Using FairPlay SDK from prebuilt directory: ...` (legacy, if binaries still present)

## Configuration

### Environment Variables

```bash
# Required: Path to FairPlay credentials directory
export FAIRPLAY_CREDENTIALS_PATH=/path/to/credentials
```

**Default path (if not set):**
```
./vendor/FairPlay_Streaming_Server_SDK_26/Development/Key_Server_Module/credentials
```

### Credentials Directory Structure

The credentials directory must contain:
- `certificates.json` or `test_certificates.json`
- FPS certificate files (`*.bin`)

## Architecture

### Crate Structure

```
arkavo-rs/
├── vendor/fpssdk/              # Apple's SDK Rust module (committed)
│   ├── src/lib.rs             # FFI bindings (66+ files)
│   ├── build.rs               # Links libfpscrypto.dylib
│   ├── prebuilt/macos/libfpscrypto.dylib
│   └── Cargo.toml
├── crates/fairplay-wrapper/    # Safe Rust wrapper
│   ├── src/lib.rs             # FairPlayKeyServer, SpcRequest, CkcResponse
│   └── Cargo.toml
├── src/modules/fairplay.rs     # FairPlayHandler (integration layer)
└── src/modules/media_api.rs    # Protocol detection & routing
```

### Protocol Auto-Detection

The `/media/v1/key-request` endpoint automatically detects protocol from request payload:

| Protocol | Required Fields |
|----------|----------------|
| **TDF3** | `nanotdf_header` + `client_public_key` |
| **FairPlay** | `spc_data` |

### Unified Session Management

Both protocols use the same `PlaybackSession` structure:

```rust
pub struct PlaybackSession {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub protocol: MediaProtocol,  // TDF3 or FairPlay
    pub segment_index: Option<u32>,
    pub state: SessionState,
    // ... other fields
}
```

## API Endpoints

### Start Playback Session

```http
POST /media/v1/session/start
Content-Type: application/json

{
  "userId": "user_123",
  "assetId": "asset_456",
  "clientIp": "192.168.1.100",
  "protocol": "fairplay"  // or "tdf3"
}
```

**Response:**
```json
{
  "sessionId": "user_123:asset_456:uuid",
  "status": "active",
  "expiresAt": 1234567890
}
```

### Request Key (Auto-detects Protocol)

#### FairPlay Request

```http
POST /media/v1/key-request
Content-Type: application/json

{
  "sessionId": "session_id",
  "userId": "user_123",
  "assetId": "asset_456",
  "segmentIndex": 0,
  "spcData": "base64_encoded_spc_from_client"
}
```

**Response:**
```json
{
  "sessionPublicKey": "",
  "wrappedKey": "base64_encoded_ckc",
  "status": "success",
  "metadata": {
    "protocol": "fairplay",
    "latency_ms": 12,
    "sdk_version": "26.0.0"
  }
}
```

#### TDF3 Request

```http
POST /media/v1/key-request
Content-Type: application/json

{
  "sessionId": "session_id",
  "userId": "user_123",
  "assetId": "asset_456",
  "segmentIndex": 0,
  "nanotdfHeader": "base64_encoded_header",
  "clientPublicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### Session Heartbeat

```http
POST /media/v1/session/:sessionId/heartbeat
Content-Type: application/json

{
  "state": "playing",
  "segmentIndex": 5
}
```

### End Session

```http
DELETE /media/v1/session/:sessionId
```

## Client Workflow

### FairPlay Playback Flow

1. **Initialize Session**
   ```
   Client → POST /media/v1/session/start → Server
   Client ← session_id ← Server
   ```

2. **Generate SPC** (client-side using native FairPlay APIs)
   ```swift
   // iOS/tvOS/macOS example
   let contentKeyRequest = AVContentKeyRequest(...)
   let spcData = try await contentKeyRequest.makeStreamingContentKeyRequestData(...)
   ```

3. **Request CKC**
   ```
   Client → POST /media/v1/key-request {spcData: base64(spc)} → Server
   Server validates session, enforces policy
   Server → FairPlay SDK → processes SPC → generates CKC
   Client ← {wrappedKey: base64(ckc)} ← Server
   ```

4. **Process CKC** (client-side)
   ```swift
   let ckcData = Data(base64Encoded: response.wrappedKey)
   contentKeyRequest.processContentKeyResponse(AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckcData))
   ```

5. **Play Content** + Send periodic heartbeats

6. **End Session** when playback completes

## Policy Enforcement

The Media Policy Contract (`src/bin/contracts/media_policy_contract.rs`) validates all requests:

### Subscription Requirements
- Active subscription status
- Subscription tier (free, basic, premium)
- Content access level (e.g., UHD requires premium)

### Rental Windows
- **Purchase window**: 7 days from purchase timestamp
- **Playback window**: 48 hours from first play
- First-play tracking stored in Redis

### Concurrency Limits
- Maximum simultaneous streams per user (configurable via `MAX_CONCURRENT_STREAMS`)
- Real-time session counting via Redis

### Geo-restrictions
- IP-based country filtering
- Content regional availability

### Device Security
- **HDCP requirements**: Type 0 (HD), Type 1 (UHD)
- **Security level**: Baseline, Main
- **VM detection**: Block virtual machines for premium content

## Performance

### Target Metrics
- **Key delivery latency**: < 50ms P95
- **Session creation**: < 100ms
- **SDK processing**: < 20ms (SPC → CKC)

### Monitoring

Analytics events published to NATS (`media.metrics.*`):

- `key_request` - Success/failure with latency
- `session_start` - Playback initiated
- `session_end` - Playback terminated
- `policy_denial` - Access denied with reason
- `concurrency_limit` - Stream limit hit
- `rental_window` - First play or expiry events

## Security Considerations

### Credentials Management
- Store credentials in secure, access-controlled directories
- Use different credentials for development vs. production
- Rotate production credentials periodically
- Never log credential contents

### Key Management
- Content keys (DEKs) should be randomly generated per asset/segment
- DEKs never transmitted in plaintext
- FairPlay CKC contains encrypted DEK
- Key rotation recommended for long-lived content

### Network Security
- Use TLS for all API endpoints
- Every media endpoint except `GET /media/v1/certificate` requires an
  `Authorization: Bearer <CWT>`; there is no way to disable the check. Point
  `CWT_KEYS_URL`, `CWT_EXPECTED_ISSUER` and `CWT_EXPECTED_AUDIENCE` at your
  production identity service so tokens are verified against the right keys,
  issuer and audience
- Implement rate limiting on key request endpoints
- Monitor for anomalous request patterns

## Troubleshooting

### SDK Initialization Fails

**Symptom:** `Failed to initialize FairPlay handler`

**Causes:**
- Credentials path incorrect or inaccessible
- Missing `certificates.json` or certificate files
- Invalid certificate format

**Solution:**
```bash
# Check credentials directory
ls -la $FAIRPLAY_CREDENTIALS_PATH

# Verify files exist
test -f $FAIRPLAY_CREDENTIALS_PATH/test_certificates.json && echo "Found"
```

### Key Request Returns Error

**Symptom:** `errorDomain: FairPlayStreaming, errorCode: -42XXX`

**Common Errors:**
- `-42652`: Certificate invalid or expired
- `-42650`: SPC format invalid
- `-42660`: Content ID mismatch

**Solution:**
- Verify SPC is base64-encoded correctly
- Check certificate validity period
- Ensure content_id matches asset_id

### Session Not Found

**Symptom:** `Session not found or expired`

**Causes:**
- Session expired (5-minute timeout without heartbeat)
- Session ID incorrect
- Redis connection lost

**Solution:**
- Implement heartbeat every 60-120 seconds during playback
- Check Redis connectivity
- Verify session_id matches what was returned from `/session/start`

## Known Issues

### ~~Compilation Issues~~ (RESOLVED)

~~**Issue #24** - Previously documented compilation failures have been resolved.~~

**Root Causes Identified:**
1. Missing `Arc` import in `src/modules/fairplay.rs`
2. Missing `Engine` trait import for base64 in `src/modules/media_api.rs`
3. `!Send` error from `Box<dyn Error>` held across `.await` points

**Resolution Applied:**
- Added `use std::sync::Arc;` to fairplay module
- Added `use base64::Engine;` for proper trait access
- Refactored error handling to convert `Box<dyn Error>` to `String` before any async operations
- Used `Pin<Box<dyn Future<...> + Send>>` return type for feature-gated handler

**Status:** ✅ **FIXED**
- Compiles successfully WITHOUT `fairplay` feature
- Compiles successfully WITH `--features fairplay`
- All tests pass with both configurations

### Test Suite Status

**Status:** ✅ **All tests passing**

The `PlaybackSession` struct includes the `protocol: MediaProtocol` field for dual-protocol support (TDF3/FairPlay).

## License & Compliance

See `THIRD-PARTY-LICENSES.md` for complete Apple FairPlay SDK licensing terms.

### Key Requirements

1. **Valid FairPlay Streaming Agreement** with Apple
2. **Production credentials** from Apple Developer Portal
3. **Test certificates** must not be used in production
4. **Compliance** with all Apple terms and conditions
5. **Confidentiality** of FairPlay credentials and keys

### Resources

- [Apple FairPlay Streaming](https://developer.apple.com/streaming/fps/)
- [FairPlay Streaming Programming Guide](https://developer.apple.com/documentation/avfoundation/content_playback_and_fairplay_streaming)
- [WWDC Sessions on FairPlay](https://developer.apple.com/videos/)

---

**Questions or Issues?** See GitHub issues or contact the arkavo team.
