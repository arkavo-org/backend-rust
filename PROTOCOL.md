# Protocol Documentation

This document describes the custom binary WebSocket protocol used by this KAS implementation.

## Overview

This implementation uses a **custom binary protocol over WebSocket** rather than the standard OpenTDF REST API. This design choice enables:
- Full-duplex real-time communication for event streaming
- Efficient binary message format
- Session-based ECDH key agreement
- NATS pub/sub integration

**⚠️ Important for OpenTDF Interoperability:** This custom protocol diverges from the standard OpenTDF specification. When testing with the OpenTDF SDK or platform, ensure they are configured to use this custom binary WebSocket protocol rather than expecting standard REST/JSON endpoints.

## Connection Flow

```
Client                                  Server
  |                                       |
  |-------- WebSocket Connect ---------->|  (Authorization: Bearer <CWT>)
  |                                       |
  |-------- PublicKey (0x01) ----------->|  (ECDH key agreement)
  |<------- PublicKey (0x01) -------------|  (with salt)
  |                                       |
  |-------- Rewrap (0x03) --------------->|  (NanoTDF rewrap request)
  |<------- RewrappedKey (0x04) ----------|  (or Error 0xFF)
  |                                       |
  |<------- Nats (0x05) ------------------|  (Server push via NATS)
  |<------- Event (0x06) -----------------|  (FlatBuffers events)
  |                                       |
```

## Message Format

All binary messages use a single-byte type prefix:

```
+--------+------------------+
| Type   | Payload          |
| (1B)   | (variable)       |
+--------+------------------+
```

### Message Types

| Type | Name | Direction | Description |
|------|------|-----------|-------------|
| 0x01 | PublicKey | Bidirectional | ECDH public key exchange |
| 0x02 | KasPublicKey | Server → Client | KAS static public key |
| 0x03 | Rewrap | Client → Server | NanoTDF rewrap request |
| 0x04 | RewrappedKey | Server → Client | Rewrapped DEK response |
| 0x05 | Nats | Server → Client | NanoTDF from NATS |
| 0x06 | Event | Bidirectional | FlatBuffers event |
| 0xFF | Error | Server → Client | JSON error response |

## Authentication

### CWT Bearer Token

The WebSocket upgrade requires an `Authorization` header containing a base64url-encoded
COSE_Sign1 CWT:

```http
Authorization: Bearer <base64url-cose-sign1-cwt>
```

**Configuration:**
- `CWT_KEYS_URL`: COSE key set endpoint for signature verification
- `CWT_EXPECTED_ISSUER`: required `iss` claim
- `CWT_EXPECTED_AUDIENCE`: required `aud` claim

**Supported Algorithm:** ES256 over P-256 COSE keys

## ECDH Key Agreement (0x01)

Establishes a shared secret for session encryption.

### Client → Server

```
+--------+----------------------------------+
| 0x01   | Client P-256 Public Key (33B)    |
+--------+----------------------------------+
```

- Compressed SEC1 format (0x02 or 0x03 prefix + 32 bytes x-coordinate)

### Server → Client

```
+--------+----------------------------------+----------+
| 0x01   | Server P-256 Public Key (33B)    | Salt(32B)|
+--------+----------------------------------+----------+
```

- Server generates ephemeral key pair
- Returns compressed public key + random salt
- Both derive shared secret via ECDH
- Salt used for HKDF key derivation

## NanoTDF Rewrap (0x03 / 0x04)

### Request: Client → Server

```
+--------+---------------------------+
| 0x03   | NanoTDF Binary Data       |
+--------+---------------------------+
```

Payload is a complete NanoTDF object per [OpenTDF spec](https://github.com/opentdf/spec).

**NanoTDF Header Structure:**
```
- Magic Number: "L1L" (0x4C 0x31 0x4C)
- Version: 0x01
- KAS ResourceLocator
- ECC Mode & Binding
- Symmetric & Payload Config
- Policy (Remote or Embedded)
- Ephemeral Key (33B compressed P-256)
```

### Response: Server → Client (Success)

```
+--------+------------------+----------+------------------+
| 0x04   | TDF Ephemeral    | Nonce    | Wrapped DEK      |
|        | Key (33B)        | (12B)    | (48B with tag)   |
+--------+------------------+----------+------------------+
```

**Rewrap Process:**
1. Parse NanoTDF header
2. Extract TDF ephemeral public key
3. Perform ECDH with KAS private key → `dek_shared_secret`
4. Evaluate policy/contracts (deny if policy fails)
5. Derive encryption key: `HKDF-SHA256(session_secret, salt, "rewrappedKey")`
6. Encrypt `dek_shared_secret` with AES-256-GCM
7. Return TDF ephemeral key + nonce + ciphertext

### Response: Server → Client (Error)

```
+--------+---------------------------+
| 0xFF   | JSON Error Payload        |
+--------+---------------------------+
```

See Error Responses section below.

## Policy Enforcement

### Remote Policy

```
ResourceLocator {
  protocol: HTTP/HTTPS/WS/WSS,
  body: "kas.example.com/policy"
}
```

**Current Implementation:** Parsed but not fetched. Remote policies require implementation.

### Embedded Policy

Embedded policies contain FlatBuffers metadata with optional contract enforcement.

**Contract Inference:**
- If `metadata.rating()` present → Content Rating Contract (5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB)
- If no rating → No contract enforcement

### Contracts

Three pluggable contracts are implemented:

#### 1. Content Rating (5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB)

Enforces age-based content restrictions using FlatBuffers rating metadata.

**Rating Levels:** None, Mild, Moderate, Severe

**Categories:** violent, sexual, profane, substance, hate, harm, mature, bully

**Age Levels:**
- Kids (<13): Only None/Mild violence allowed
- Teens (13-17): None/Mild content, no substance/hate/harm/bully
- Adults (18+): All content allowed

#### 2. Geofence (5H6sLwXKBv3cdm5VVRxrvA8p5cux2Rrni5CQ4GRyYKo4b9B4)

3D location-based access control.

**Note:** Currently uses hardcoded test coordinates. Production requires coordinate extraction from rewrap request.

#### 3. Simple ABAC (5Cqk3ERPToSMuY8UoKJtcmo4fs1iVyQpq6ndzWzpzWezAF1W)

Attribute-based access using JWT claims subject.

## NATS Integration (0x05)

### Server → Client

```
+--------+---------------------------+
| 0x05   | NanoTDF or Event Data     |
+--------+---------------------------+
```

**Subscriptions:**
1. Global: `nanotdf.messages` (configurable via `NATS_SUBJECT`)
2. User-specific: `profile.<publicID>` (after JWT authentication)

Messages received from NATS are forwarded to WebSocket clients with 0x05 prefix.

### Client → Server (Publish)

```
+--------+---------------------------+
| 0x05   | NanoTDF to Publish        |
+--------+---------------------------+
```

Server publishes payload to configured NATS subject. **Max size:** 16MB.

## Events (0x06)

FlatBuffers-based event system for caching and routing.

### Event Types

#### UserEvent
Retrieves encrypted content from Redis:
```
Event {
  action: "get",
  data: UserEvent {
    source_type: "user",
    target_type: "content",
    source_id: <user_id>,
    target_id: <content_id>  // Redis key
  }
}
```

Response: Content from Redis or "Event not found"

#### CacheEvent
Stores encrypted content in Redis:
```
Event {
  action: "cache",
  data: CacheEvent {
    target_id: <redis_key>,
    target_payload: <encrypted_data>,
    ttl: <seconds>,          // 0 = no expiration
    one_time_access: bool
  }
}
```

Response: Cached payload

#### RouteEvent
Routes event to specific user via NATS:
```
Event {
  action: "route",
  data: RouteEvent {
    target_id: <public_id_bytes>  // bs58 encoded
  }
}
```

Publishes to `profile.<public_id>` NATS subject.

**Event Detection:** Messages starting with "L1L" (0x4C 0x31 0x4C) are treated as NanoTDF (type 0x05), otherwise as FlatBuffers events (type 0x06).

## Error Responses (0xFF)

JSON-formatted errors for debugging:

```json
{
  "error_type": "invalid_format" | "policy_denied" | "crypto_error" | "server_error",
  "message": "Human-readable error description",
  "details": "Optional additional information"
}
```

### Error Types

| error_type | Description | Example |
|------------|-------------|---------|
| invalid_format | Malformed message/data | "Invalid public key size: 32 bytes (expected 33 for compressed P-256)" |
| policy_denied | Policy/contract rejected access | "Content not suitable for age level: Kids" |
| crypto_error | Cryptographic operation failed | "Invalid P-256 public key: invalid point encoding" |
| server_error | Internal server error | "NATS client not available" |

## Cryptography Details

### ECDH Key Agreement
- **Curve:** P-256 (secp256r1)
- **Key Format:** Compressed SEC1 (33 bytes)
- **Shared Secret:** x-coordinate only (32 bytes)

### Session Key Derivation
```
HKDF-SHA256(
  secret: session_shared_secret,
  salt: random_32_bytes,
  info: "rewrappedKey"
) → 32-byte AES key
```

### DEK Encryption
- **Algorithm:** AES-256-GCM
- **Nonce:** 12 bytes (random)
- **Output:** ciphertext + 16-byte authentication tag

### TLS
- **Minimum Version:** TLS 1.2
- **Certificate:** Configurable via `TLS_CERT_PATH` / `TLS_KEY_PATH`
- **Optional:** TLS can be disabled if cert path not provided

## Comparison with Standard OpenTDF

| Feature | Standard OpenTDF | This Implementation |
|---------|------------------|---------------------|
| Transport | REST/HTTP | WebSocket |
| Protocol | JSON | Custom Binary |
| Authentication | Bearer Token (HTTP header) | CWT Bearer token (WebSocket upgrade) |
| Rewrap Endpoint | POST /kas/v2/rewrap | Binary message type 0x03 |
| Key Agreement | Per-request or cached | Session-based ECDH |
| Push Events | Not supported | NATS pub/sub + type 0x05/0x06 |
| Error Format | HTTP status + JSON | Binary type 0xFF + JSON |
| Policy Fetch | HTTP GET remote policy | Not implemented |

## Testing Recommendations

1. **CWT Configuration:** Set `CWT_KEYS_URL`, `CWT_EXPECTED_ISSUER`, and `CWT_EXPECTED_AUDIENCE` for WebSocket authentication
2. **NATS Availability:** Ensure NATS server is running or expect NATS-related errors
3. **Redis Caching:** Events require Redis for UserEvent/CacheEvent
4. **Test Vectors:** Use OpenTDF NanoTDF test vectors for rewrap validation
5. **Error Handling:** Check for type 0xFF error responses, not HTTP status codes
6. **Key Agreement:** Verify ECDH shared secret computation matches OpenTDF SDK
7. **Binary Protocol:** Ensure client library supports custom WebSocket binary protocol

## Example Message Flows

### Successful Rewrap

```
C→S: [0x01][33-byte compressed P-256 public key]
S→C: [0x01][33-byte compressed P-256 public key][32-byte salt]

C→S: [0x03][NanoTDF with embedded content rating policy]
S→C: [0x04][33B TDF ephemeral key][12B nonce][48B wrapped DEK]
```

### Policy Denial

```
C→S: [0x03][NanoTDF with age-restricted content]
S→C: [0xFF]{"error_type":"policy_denied","message":"Content not suitable for age level: Kids"}
```

### Session Error

```
C→S: [0x03][NanoTDF without prior key agreement]
S→C: [0xFF]{"error_type":"invalid_format","message":"Session not established - perform key agreement first"}
```

## Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| PORT | 8080 | WebSocket server port |
| TLS_CERT_PATH | ./fullchain.pem | TLS certificate (optional) |
| TLS_KEY_PATH | ./privkey.pem | TLS private key (optional) |
| KAS_KEY_PATH | ./recipient_private_key.pem | KAS EC private key (required) |
| CWT_KEYS_URL | https://identity.arkavo.net/.well-known/cose-keys | COSE key set URL for WebSocket CWT validation |
| CWT_EXPECTED_ISSUER | https://identity.arkavo.net | Required CWT issuer |
| CWT_EXPECTED_AUDIENCE | https://100.arkavo.net | Required CWT audience |
| NATS_URL | nats://localhost:4222 | NATS server URL |
| NATS_SUBJECT | nanotdf.messages | Default NATS subscription subject |
| REDIS_URL | redis://localhost:6379 | Redis connection string |
| ENABLE_TIMING_LOGS | false | Log performance metrics |
| RUST_LOG | - | Log level (info, debug, trace) |

## Future Enhancements

- Remote policy fetching via HTTP
- Policy binding verification (ECDSA/GMAC)
- Contract ID field in metadata schema
- Explicit contract selection mechanism
- OpenTDF REST API compatibility mode
- mTLS client certificate authentication
