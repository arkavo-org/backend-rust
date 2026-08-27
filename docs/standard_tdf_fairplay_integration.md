# Standard TDF + FairPlay Integration

OpenTDF Standard TDF format for FairPlay DRM key delivery on Apple devices.

## Overview

This integration enables **policy-driven DRM** for Apple devices by combining:
- **OpenTDF Standard TDF**: Open-standard key wrapping with manifest.json
- **FairPlay Streaming**: Apple's native DRM for iOS/tvOS/macOS

Content keys are wrapped using RSA-2048 in OpenTDF format, then delivered via FairPlay's CKC (Content Key Context) to Apple clients.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Standard TDF + FairPlay Architecture                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Content Provider                     Arkavo Server (KAS + FairPlay)   │
│   ┌─────────────────┐                  ┌─────────────────────────────┐  │
│   │ 1. Generate DEK │                  │ POST /media/v1/key-request  │  │
│   │    (16 bytes)   │                  │                             │  │
│   │ 2. Encrypt HLS  │                  │ ┌─────────────────────────┐ │  │
│   │    segments     │                  │ │ Parse manifest.json     │ │  │
│   │ 3. RSA-OAEP     │                  │ │ Extract wrappedKey      │ │  │
│   │    wrap DEK     │                  │ └───────────┬─────────────┘ │  │
│   │ 4. Create TDF   │                  │             │               │  │
│   │    manifest.json│                  │             ▼               │  │
│   └─────────────────┘                  │ ┌─────────────────────────┐ │  │
│                                        │ │ RSA-OAEP Decrypt        │ │  │
│   Apple Client                         │ │ (KAS RSA private key)   │ │  │
│   ┌─────────────────┐                  │ └───────────┬─────────────┘ │  │
│   │ AVPlayer        │                  │             │               │  │
│   │ generates SPC   │───spc_data──────►│             │ DEK (16 bytes)│  │
│   │                 │                  │             ▼               │  │
│   │ App provides    │                  │ ┌─────────────────────────┐ │  │
│   │ TDF manifest    │──tdf_manifest───►│ │ FairPlay SDK            │ │  │
│   └────────┬────────┘                  │ │ (wrap DEK → CKC)        │ │  │
│            │                           │ └───────────┬─────────────┘ │  │
│            │                           │             │               │  │
│            │◄───────────ckc_data───────┤◄────────────┘               │  │
│            ▼                           └─────────────────────────────┘  │
│   ┌─────────────────┐                                                   │
│   │ Decrypt & play  │                                                   │
│   │ HLS segments    │                                                   │
│   └─────────────────┘                                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Standard TDF Structure

### ZIP Archive Format

```
movie.tdf (ZIP archive)
├── manifest.json          ← Policy + RSA-wrapped DEK
└── 0.payload              ← Encrypted HLS segments (AES-128-CBC)
```

### manifest.json Format

```json
{
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "https://platform.arkavo.net",
        "protocol": "kas",
        "wrappedKey": "BASE64_RSA_OAEP_ENCRYPTED_DEK",
        "policyBinding": {
          "alg": "HS256",
          "hash": "BASE64_HMAC_OF_POLICY"
        }
      }
    ],
    "method": {
      "algorithm": "AES-128-CBC",
      "iv": "BASE64_INITIALIZATION_VECTOR"
    },
    "policy": "BASE64_ENCODED_POLICY_JSON"
  },
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "mimeType": "video/mp2t"
  }
}
```

### Policy Object (decoded from base64)

```json
{
  "uuid": "unique-policy-id",
  "body": {
    "dataAttributes": [],
    "dissem": ["user@example.com"]
  }
}
```

## Content Packaging Workflow

### 1. Generate Content Key (DEK)

```bash
# Generate random 16-byte AES-128 key
openssl rand -hex 16 > content_key.txt
# Example: a1b2c3d4e5f6789012345678abcdef00
```

### 2. Get KAS RSA Public Key

```bash
curl -s "https://platform.arkavo.net/kas/v2/kas_public_key?algorithm=rsa" \
  | jq -r '.public_key' > kas_rsa_public.pem
```

### 3. Wrap DEK with RSA-OAEP

```bash
# Convert hex key to binary
echo "a1b2c3d4e5f6789012345678abcdef00" | xxd -r -p > content_key.bin

# Encrypt with RSA-OAEP (SHA-1 padding per OpenTDF spec)
openssl pkeyutl -encrypt -pubin -inkey kas_rsa_public.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 \
  -in content_key.bin -out wrapped_key.bin

# Base64 encode for manifest
# -A / -w0: GNU base64 wraps at 76 cols, which corrupts the manifest field
openssl base64 -A < wrapped_key.bin > wrapped_key.b64
```

### 4. Encrypt HLS Segments

```bash
# Encrypt each segment with AES-128-CBC
openssl enc -aes-128-cbc -in segment.ts -out segment.ts.enc \
  -K $(cat content_key.txt) -iv 00000000000000000000000000000000
```

### 5. Create manifest.json

```python
import json
import base64

manifest = {
    "encryptionInformation": {
        "type": "split",
        "keyAccess": [{
            "type": "wrapped",
            "url": "https://platform.arkavo.net",
            "protocol": "kas",
            "wrappedKey": open("wrapped_key.b64").read().strip()
        }],
        "method": {
            "algorithm": "AES-128-CBC",
            "iv": base64.b64encode(bytes(16)).decode()
        }
    },
    "payload": {
        "type": "reference",
        "url": "0.payload",
        "mimeType": "video/mp2t"
    }
}

with open("manifest.json", "w") as f:
    json.dump(manifest, f)
```

## Playback Key Delivery Flow

### 1. Start Playback Session

> **These examples run against production and `/media/v1/*` currently takes no
> caller authentication** — `session_start` and `media_key_request` accept a
> caller-supplied `userId`/`assetId` with no `Authorization` extractor, and
> `/media/v1/*` is always served locally (never proxied). Treat the session id
> as a bearer secret, and do not expose these routes to untrusted networks
> until an auth extractor is added.

```bash
curl -X POST https://platform.arkavo.net/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user123",
    "assetId": "movie456",
    "protocol": "fairplay"
  }'
```

Response:
```json
{
  "sessionId": "abc123-session-id",
  "status": "created"
}
```

### 2. Request Content Key (with TDF manifest)

```bash
# Base64 encode manifest.json
MANIFEST_B64=$(base64 < manifest.json)

curl -X POST https://platform.arkavo.net/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "abc123-session-id",
    "userId": "user123",
    "assetId": "movie456",
    "spcData": "BASE64_SPC_FROM_AVPLAYER",
    "tdfManifest": "'$MANIFEST_B64'"
  }'
```

### 3. Alternative: Direct Wrapped Key

If you only have the wrapped key (not full manifest):

```bash
curl -X POST https://platform.arkavo.net/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "abc123-session-id",
    "userId": "user123",
    "assetId": "movie456",
    "spcData": "BASE64_SPC_FROM_AVPLAYER",
    "tdfWrappedKey": "BASE64_RSA_WRAPPED_DEK"
  }'
```

### Response

```json
{
  "sessionPublicKey": "-----BEGIN PUBLIC KEY-----...",
  "wrappedKey": "BASE64_FAIRPLAY_CKC",
  "status": "success"
}
```

The `wrappedKey` contains the FairPlay CKC to pass back to AVPlayer.

## iOS/tvOS Client Integration

### AVContentKeySession Setup

```swift
import AVFoundation

class FairPlayHandler: NSObject, AVContentKeySessionDelegate {
    let session: AVContentKeySession
    let tdfManifest: String  // Base64-encoded manifest.json

    func contentKeySession(_ session: AVContentKeySession,
                          didProvide keyRequest: AVContentKeyRequest) {

        // Get SPC from AVPlayer
        keyRequest.makeStreamingContentKeyRequestData(
            forApp: certificateData,
            contentIdentifier: contentId
        ) { spcData, error in
            guard let spc = spcData else { return }

            // Request CKC from Arkavo server with TDF manifest
            self.requestCKC(spc: spc, manifest: self.tdfManifest) { ckc in
                let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckc)
                keyRequest.processContentKeyResponse(keyResponse)
            }
        }
    }

    func requestCKC(spc: Data, manifest: String, completion: @escaping (Data) -> Void) {
        let request: [String: Any] = [
            "sessionId": sessionId,
            "userId": userId,
            "assetId": assetId,
            "spcData": spc.base64EncodedString(),
            "tdfManifest": manifest
        ]

        // POST to /media/v1/key-request
        // Parse response.wrappedKey as CKC
    }
}
```

## Server Configuration

### Required Environment Variables

```bash
# RSA key for Standard TDF (required for this integration)
export KAS_RSA_KEY_PATH=/path/to/kas_rsa_private_pkcs8.pem

# FairPlay credentials (required)
export FAIRPLAY_CREDENTIALS_PATH=/path/to/fps/credentials

# Optional
export PORT=8443
export REDIS_URL=redis://localhost:6379
```

### Generate RSA Key Pair

```bash
# Generate RSA-2048 private key
openssl genrsa -out kas_rsa_private.pem 2048

# Convert to PKCS#8 format (required)
openssl pkcs8 -topk8 -inform PEM -outform PEM \
  -in kas_rsa_private.pem -out kas_rsa_private_pkcs8.pem -nocrypt

# Extract public key (for content packaging)
openssl rsa -in kas_rsa_private_pkcs8.pem -pubout -out kas_rsa_public.pem
```

## Security Model

### Key Protection

1. **RSA-2048**: Content keys wrapped with 2048-bit RSA-OAEP
2. **SHA-1 Padding**: OpenTDF spec requires SHA-1 for OAEP (legacy compatibility)
3. **Per-Asset Keys**: Each asset has unique DEK
4. **Policy Binding**: HMAC prevents manifest tampering

### Access Control

The server enforces policies via `media_policy_contract.rs`:
- Subscription validation
- Rental window enforcement
- Geo-restriction checks
- Concurrent stream limits
- HDCP requirements

### Production Requirements

- RSA key must be configured (`KAS_RSA_KEY_PATH`)
- Production builds reject requests without `tdfManifest` or `tdfWrappedKey`
- Debug builds allow fallback for development only

## API Reference

### GET /kas/v2/kas_public_key

Get KAS public key for content packaging.

```
GET /kas/v2/kas_public_key?algorithm=rsa
```

Response:
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "kid": "r1"
}
```

### POST /media/v1/session/start

Initialize playback session.

```json
{
  "userId": "string",
  "assetId": "string",
  "protocol": "fairplay"
}
```

### POST /media/v1/key-request

Request content key with TDF manifest.

```json
{
  "sessionId": "string",
  "userId": "string",
  "assetId": "string",
  "spcData": "base64-fairplay-spc",
  "tdfManifest": "base64-manifest-json",
  "tdfWrappedKey": "base64-rsa-wrapped-dek"  // Alternative to tdfManifest
}
```

## Comparison: Standard TDF vs NanoTDF

| Feature | Standard TDF | NanoTDF |
|---------|-------------|---------|
| Format | ZIP + manifest.json | Binary header |
| Key Wrapping | RSA-2048 OAEP | ECDH + HKDF |
| Use Case | Video assets, REST API | Streaming, WebSocket |
| Policy | JSON in manifest | Embedded binary |
| Size Overhead | ~1KB manifest | ~100 bytes header |

This integration uses **Standard TDF** because:
1. Compatible with OpenTDFKit iOS SDK
2. RSA key wrapping is simpler for video packaging
3. JSON manifest is human-readable for debugging
4. Matches existing rewrap endpoint infrastructure

## Troubleshooting

### "RSA key not configured"

Set `KAS_RSA_KEY_PATH` environment variable:
```bash
export KAS_RSA_KEY_PATH=/path/to/kas_rsa_private_pkcs8.pem
```

### "Invalid RSA-wrapped key size"

Wrapped key must be 256 bytes (RSA-2048). Verify:
```bash
base64 -d < wrapped_key.b64 | wc -c
# Should output: 256
```

### "Missing wrappedKey in manifest"

Manifest must have `encryptionInformation.keyAccess[0].wrappedKey`:
```bash
cat manifest.json | jq '.encryptionInformation.keyAccess[0].wrappedKey'
```

### Debug Mode Fallback

In debug builds, requests without TDF manifest use a zero-filled placeholder key (INSECURE). This is logged as a warning:
```
⚠️  No TDF manifest/wrapped key for asset X - using INSECURE fallback (dev only)!
```

Production builds reject such requests with HTTP 400.
