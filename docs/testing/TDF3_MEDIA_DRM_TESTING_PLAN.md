# TDF3 Media DRM Testing Plan

## Overview

This document outlines a comprehensive testing plan for the TDF3-based Media DRM implementation in arkavo-rs. The system provides an open, secure alternative to proprietary DRM systems (FairPlay, Widevine, PlayReady) using TDF3/NanoTDF as the protection format.

**Target System:** arkavo-rs KAS with Media DRM extensions
**Issue:** [#21 - KAS for TDF3-based Media DRM Workflow](https://github.com/arkavo-org/arkavo-rs/issues/21)
**Branch:** `feature/tdf3-media-drm`

---

## Test Environment Setup

### Prerequisites

```bash
# Install dependencies
brew install nats-server redis flatbuffers

# Generate KAS private key
openssl ecparam -genkey -name prime256v1 -noout -out recipient_private_key.pem

# Generate self-signed TLS certs (development only)
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

### Environment Configuration

```bash
# Core configuration
export PORT=8443
export HTTP_PORT=8080
export WS_PORT=8443
export KAS_KEY_PATH=recipient_private_key.pem
export NATS_URL=nats://localhost:4222
export REDIS_URL=redis://localhost:6379
export RUST_LOG=info

# Media DRM configuration
export MAX_CONCURRENT_STREAMS=5
export ENABLE_MEDIA_ANALYTICS=true
export MEDIA_METRICS_SUBJECT=media.metrics
export SESSION_HEARTBEAT_TIMEOUT=300  # 5 minutes

# Optional: Enable TLS
export TLS_CERT_PATH=fullchain.pem
export TLS_KEY_PATH=privkey.pem

# CWT bearer authentication (defaults shown). Every route except
# GET /media/v1/certificate requires `Authorization: Bearer <CWT>`;
# the check cannot be disabled.
export CWT_KEYS_URL=https://identity.arkavo.net/.well-known/cose-keys
export CWT_EXPECTED_ISSUER=https://identity.arkavo.net
export CWT_EXPECTED_AUDIENCE=https://100.arkavo.net
```

### Start Services

```bash
# Terminal 1: NATS
nats-server

# Terminal 2: Redis
redis-server

# Terminal 3: Subscribe to analytics events
nats sub "media.metrics.>"

# Terminal 4: Arkavo KAS
cargo run --bin arks
```

---

## Test Phases

### Phase 1: Unit Tests

**Objective:** Validate individual components in isolation

#### 1.1 Media Policy Contract Tests

```bash
cargo test --lib media_policy_contract
```

**Test Cases:**
- ✅ Subscription validation (active, expired, tier requirements)
- ✅ Concurrency limit enforcement
- ✅ Rental window validation (purchase + playback windows)
- ✅ Geo-restriction enforcement
- ✅ HDCP requirement validation (Type 0, Type 1)
- ✅ Device security level checks
- ✅ Virtual machine detection

**Expected Results:**
- All policy contract unit tests pass
- Edge cases handled (expired subscriptions, exceeded limits, etc.)

#### 1.2 Session Manager Tests

```bash
cargo test --lib session_manager
```

**Test Cases:**
- Session creation and storage in Redis
- Heartbeat updates and TTL refresh
- Session expiry detection
- Concurrent session counting
- First-play timestamp tracking
- Session cleanup

**Expected Results:**
- Sessions persist in Redis with correct TTL
- Expired sessions are properly cleaned up
- First-play timestamps are immutable

#### 1.3 Media Metrics Tests

```bash
cargo test --lib media_metrics
```

**Test Cases:**
- ✅ Latency tracking and percentile calculation
- Event serialization to JSON
- NATS publishing (if client available)
- Request timer accuracy

**Expected Results:**
- P50/P95/P99 latencies calculated correctly
- Events serialize with proper structure

---

### Phase 2: Integration Tests

**Objective:** Test component interactions and API endpoints

#### 2.1 Session Lifecycle Tests

**Scenario:** Complete session from start to finish

```bash
# 1. Start session
curl -X POST http://localhost:8080/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-001",
    "asset_id": "movie-12345",
    "client_ip": "192.168.1.100",
    "geo_region": "US"
  }'

# Expected: 200 OK, returns session_id

# 2. Send heartbeat
curl -X POST http://localhost:8080/media/v1/session/{session_id}/heartbeat \
  -H "Content-Type: application/json" \
  -d '{"state": "playing", "segment_index": 5}'

# Expected: 200 OK, session refreshed

# 3. Terminate session
curl -X DELETE http://localhost:8080/media/v1/session/{session_id}

# Expected: 204 No Content
```

**Validation:**
- Check NATS for `session_start` and `session_end` events
- Verify Redis keys created and cleaned up
- Confirm analytics logged to stdout

#### 2.2 Concurrency Limit Tests

**Scenario:** Enforce maximum concurrent streams

```bash
# Create MAX_CONCURRENT_STREAMS sessions for same user
for i in {1..5}; do
  curl -X POST http://localhost:8080/media/v1/session/start \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"user-001\",\"asset_id\":\"asset-$i\",\"client_ip\":\"192.168.1.100\"}"
done

# Attempt one more (should fail)
curl -X POST http://localhost:8080/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-001","asset_id":"asset-6","client_ip":"192.168.1.100"}'

# Expected: 429 Too Many Requests
# Expected NATS event: concurrency_limit
```

**Validation:**
- First N sessions succeed
- (N+1)th session rejected with 429
- `concurrency_limit` event published to NATS

#### 2.3 Key Request Tests

**Scenario:** Request wrapped DEK for media segment

**Prerequisites:**
- Create a TDF3-protected media segment
- Extract NanoTDF header (base64-encoded)
- Generate client ephemeral key pair

```bash
# 1. Start session (from 2.1)
SESSION_ID="..." # from session start response

# 2. Request key for segment
curl -X POST http://localhost:8080/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "'"$SESSION_ID"'",
    "user_id": "user-001",
    "asset_id": "movie-12345",
    "segment_index": 0,
    "client_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "nanotdf_header": "AwAAAC8AAQAgABC..."
  }'

# Expected: 200 OK
# Returns: {
#   "session_public_key": "...",
#   "wrapped_key": "...",  // base64(nonce + encrypted_dek)
#   "status": "success",
#   "metadata": {"latency_ms": 15, "segment_index": 0}
# }
```

**Validation:**
- Response latency < 50ms (P95 target)
- `wrapped_key` is valid base64
- `key_request` event published to NATS with latency
- Session heartbeat automatically updated

#### 2.4 Rental Window Tests

**Scenario:** Enforce time-based rental access

**Setup in Redis:**
```bash
# Simulate rental purchase (7 days from purchase, 48h from first play)
redis-cli SET "rental:user-001:rental-movie" "1704067200"  # Jan 1, 2024 00:00:00
redis-cli EXPIRE "rental:user-001:rental-movie" 604800  # 7 days
```

**Test Cases:**

1. **Within rental window (no first play yet):**
   - Request key → should succeed
   - First play timestamp should be set
   - Check `rental_window` NATS event (action: first_play)

2. **Within playback window (< 48h from first play):**
   - Request key → should succeed
   - First play timestamp unchanged

3. **Outside playback window (> 48h from first play):**
   - Request key → should fail with policy denial
   - Check `policy_denial` NATS event (reason: rental_window_expired)

4. **Outside rental window (> 7 days from purchase):**
   - Redis key expired
   - Request key → should fail
   - Check `rental_window` NATS event (action: expired)

#### 2.5 Session Timeout Tests

**Scenario:** Sessions expire after 5 minutes without heartbeat

```bash
# 1. Start session
curl -X POST http://localhost:8080/media/v1/session/start ...
# Note the session_id

# 2. Wait 6 minutes (SESSION_HEARTBEAT_TIMEOUT + 1)
sleep 360

# 3. Attempt to use expired session
curl -X POST http://localhost:8080/media/v1/key-request \
  -H "Content-Type: application/json" \
  -d '{"session_id":"expired-session-id", ...}'

# Expected: 404 Not Found (session not found or expired)
```

**Validation:**
- Session removed from Redis after timeout
- Subsequent requests fail with session_not_found
- User can create new session

---

### Phase 3: Performance Tests

**Objective:** Validate system meets performance targets

#### 3.1 Key Delivery Latency Test

**Target:** < 50ms P95 latency

**Test Script:** (`tests/performance/key_delivery_bench.sh`)

```bash
#!/bin/bash
# Create session
SESSION_ID=$(curl -s -X POST http://localhost:8080/media/v1/session/start \
  -H "Content-Type: application/json" \
  -d '{"user_id":"perf-user","asset_id":"test-asset","client_ip":"127.0.0.1"}' \
  | jq -r '.session_id')

# Request 1000 keys
for i in {1..1000}; do
  curl -w "%{time_total}\n" -o /dev/null -s \
    -X POST http://localhost:8080/media/v1/key-request \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\",\"user_id\":\"perf-user\",\"asset_id\":\"test-asset\",\"segment_index\":$i,\"client_public_key\":\"...\",\"nanotdf_header\":\"...\"}"
done | awk '{sum+=$1; arr[NR]=$1} END {
  asort(arr);
  print "P50:", arr[int(NR*0.5)]*1000 "ms";
  print "P95:", arr[int(NR*0.95)]*1000 "ms";
  print "P99:", arr[int(NR*0.99)]*1000 "ms";
  print "Avg:", sum/NR*1000 "ms"
}'
```

**Success Criteria:**
- P95 < 50ms
- P99 < 100ms
- No failed requests

#### 3.2 Concurrent Sessions Stress Test

**Target:** Support 1000+ concurrent sessions per instance

```bash
# Use Apache Bench or similar
ab -n 10000 -c 100 -p session_start.json \
  -T application/json \
  http://localhost:8080/media/v1/session/start

# Monitor Redis memory usage
redis-cli INFO memory

# Monitor NATS message throughput
nats stream info METRICS
```

**Success Criteria:**
- All requests handled successfully
- Redis memory usage stays within bounds
- No session data corruption
- NATS events published reliably

#### 3.3 Sustained Load Test

**Scenario:** Simulate realistic streaming load over 30 minutes

```bash
# Use k6 or locust
k6 run --vus 100 --duration 30m streaming_load.js
```

**Load Profile:**
- 100 concurrent users
- Each user: start session → request 100 segment keys → terminate
- Randomized think time (1-5s between segments)
- 10% of users hit concurrency limit (retry logic)

**Metrics to Track:**
- Key delivery P95/P99 latencies
- Session creation/termination rates
- Redis connection pool utilization
- NATS publish throughput
- Error rates by type

**Success Criteria:**
- P95 latency remains < 50ms throughout
- Error rate < 0.1%
- No memory leaks (stable RSS over time)
- All analytics events captured

---

### Phase 4: Security & Compliance Tests

**Objective:** Ensure security and audit requirements

#### 4.1 JWT Validation Test

**With OAuth Public Key Configured:**

```bash
# 1. Generate JWT with invalid signature
INVALID_JWT="eyJhbGc..."

curl -X POST http://localhost:8080/media/v1/key-request \
  -H "Authorization: Bearer $INVALID_JWT" \
  ...

# Expected: 401 Unauthorized (authentication_failed)
```

#### 4.2 Session Hijacking Prevention

**Test:** Attempt to use another user's session

```bash
# User A creates session
SESSION_A=$(curl ... -d '{"user_id":"alice",...}' | jq -r '.session_id')

# User B attempts to use Alice's session
curl -X POST http://localhost:8080/media/v1/key-request \
  -d "{\"session_id\":\"$SESSION_A\",\"user_id\":\"bob\",...}"

# Expected: 401 Unauthorized (user_id mismatch)
```

#### 4.3 Audit Logging Verification

**Validate Structured Logs:**

```bash
# Run test workflow
./run_test_workflow.sh

# Check logs for required events
cat arkavo.log | grep -E "(SESSION_START|KEY_REQUEST|POLICY_DENIAL|SESSION_END)"

# Verify log format:
# - Timestamp
# - Event type
# - User ID
# - Session ID
# - Asset ID
# - Result/reason
# - Latency (for key requests)
```

**Success Criteria:**
- All events logged with required fields
- Log entries parsable as structured data
- No PII in logs (user IDs are hashed/anonymized)

---

### Phase 5: End-to-End Workflow Tests

**Objective:** Validate complete streaming workflows

#### 5.1 Happy Path: Successful Streaming Session

**Steps:**

1. User purchases subscription
2. Client requests session start
3. Client fetches HLS manifest
4. Client requests keys for segments 0-10
5. Client plays segments, sends heartbeats
6. Client finishes playback, terminates session

**Validation:**
- All key requests succeed within latency SLA
- Analytics events published in correct order:
  - `session_start`
  - `key_request` × 11 (segments 0-10)
  - `session_end`
- Session cleaned up from Redis
- No errors in logs

#### 5.2 Rental Expiry During Playback

**Steps:**

1. User purchases rental (48h playback window)
2. User starts playback (first play recorded)
3. User pauses after 1 hour
4. Simulate 47 hours passing (adjust Redis TTL)
5. User resumes → key requests succeed
6. Simulate 2 more hours (total 49h)
7. User tries to resume → denied

**Validation:**
- Keys delivered for first 47 hours
- Access denied after 48-hour window
- `policy_denial` event with reason: `rental_window_expired`
- User receives clear error message

#### 5.3 Concurrency Limit with Graceful Degradation

**Steps:**

1. User has 2-stream limit
2. User starts stream on TV (session 1)
3. User starts stream on phone (session 2)
4. User tries to start stream on laptop (session 3) → denied
5. User stops TV stream (terminates session 1)
6. User retries laptop stream → succeeds

**Validation:**
- Sessions 1 and 2 created successfully
- Session 3 denied with clear error
- After terminating session 1, session 3 succeeds
- `concurrency_limit` event published on denial
- UI shows which devices are active (if implemented)

---

## Test Automation

### Continuous Integration Tests

**GitHub Actions Workflow:** `.github/workflows/media-drm-tests.yml`

```yaml
name: Media DRM Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
      nats:
        image: nats:latest
        ports:
          - 4222:4222

    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run unit tests
        run: cargo test --lib --verbose

      - name: Run integration tests
        run: cargo test --test media_drm_tests --verbose

      - name: Build release binary
        run: cargo build --release --bin arkavo
```

### Local Test Suite

**Script:** `scripts/run_media_drm_tests.sh`

```bash
#!/bin/bash
set -e

echo "=== Starting Media DRM Test Suite ==="

# Start dependencies
echo "Starting Redis and NATS..."
redis-server --daemonize yes
nats-server -D &
NATS_PID=$!

sleep 2

# Configure environment
export MAX_CONCURRENT_STREAMS=2
export ENABLE_MEDIA_ANALYTICS=true
export REDIS_URL=redis://localhost:6379

# Run tests
echo "Running unit tests..."
cargo test --lib media_policy_contract
cargo test --lib session_manager
cargo test --lib media_metrics

echo "Running integration tests..."
cargo test --test media_drm_tests

echo "Starting arkavo server..."
cargo run --bin arks &
SERVER_PID=$!
sleep 5

# API integration tests
echo "Testing session lifecycle..."
./tests/integration/test_session_lifecycle.sh

echo "Testing concurrency limits..."
./tests/integration/test_concurrency_limits.sh

echo "Testing key delivery..."
./tests/integration/test_key_delivery.sh

# Cleanup
kill $SERVER_PID
kill $NATS_PID
redis-cli shutdown

echo "=== All tests passed! ==="
```

---

## Success Criteria Summary

### Functional Requirements
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ Session lifecycle works end-to-end
- ✅ Policy enforcement works correctly
- ✅ Rental windows enforced accurately
- ✅ Concurrency limits enforced

### Performance Requirements
- ✅ Key delivery P95 < 50ms
- ✅ Support 1000+ concurrent sessions
- ✅ Sustained load over 30 minutes
- ✅ No memory leaks under load

### Security Requirements
- ✅ JWT validation (when enabled)
- ✅ Session hijacking prevented
- ✅ Audit logs complete and parsable

### Reliability Requirements
- ✅ Graceful Redis connection handling
- ✅ NATS reconnection on failure
- ✅ Session cleanup on timeout
- ✅ Error messages clear and actionable

---

## Known Limitations & Future Work

### Current Limitations
1. **Policy Cache:** Not yet implemented - policies evaluated on every request
2. **Geo-IP Lookup:** Client must provide geo_region; no automatic IP→country lookup
3. **Device Fingerprinting:** Device capabilities must be client-provided
4. **Metrics Endpoint:** `/metrics` endpoint not yet exposed for Prometheus scraping
5. **Rate Limiting:** No per-user rate limiting beyond concurrency

### Planned Enhancements
1. Redis policy cache with configurable TTL
2. Integration with MaxMind GeoIP2 for geo-restriction
3. Device attestation via client certificates
4. Prometheus metrics exporter
5. Per-user rate limiting (requests per second)
6. GraphQL API for session management
7. Admin dashboard for session monitoring

---

## Test Deliverables

1. ✅ Unit test suite (in code)
2. ✅ Integration test placeholders (`tests/media_drm_tests.rs`)
3. ✅ Testing plan document (this file)
4. ⏳ Test automation scripts (`scripts/run_media_drm_tests.sh`)
5. ⏳ Performance benchmark scripts (`tests/performance/`)
6. ⏳ CI/CD workflow (`.github/workflows/media-drm-tests.yml`)

---

## References

- **Issue:** https://github.com/arkavo-org/arkavo-rs/issues/21
- **OpenTDF Spec:** https://github.com/opentdf/spec
- **FairPlay SDK:** `FairPlay_Streaming_Server_SDK_5.1/SDK Guide.md`
- **Architecture:** `CLAUDE.md` (Media DRM Architecture section)

---

**Last Updated:** 2025-10-05
**Version:** 1.0
**Author:** Claude Code
