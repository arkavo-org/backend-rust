//! CBOR Web Token validation for WebSocket authentication.

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ciborium::value::Value;
use coset::iana;
use coset::{
    Algorithm, CborSerializable, CoseKey, CoseKeySet, CoseSign1, RegisteredLabelWithPrivate,
    TaggedCborSerializable,
};
use log::info;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use reqwest::header::CACHE_CONTROL;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

const DEFAULT_KEY_CACHE_TTL: Duration = Duration::from_secs(600);
/// Minimum interval between forced key-set refreshes triggered by an
/// `UnknownKeyId`. Without this, a flood of tokens carrying a bogus `kid`
/// turns into one upstream GET per request. Trade-off: a genuine key
/// rotation can 401 for up to this long.
const FORCED_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct CwtClaims {
    pub subject: String,
    pub issuer: String,
    pub audience: String,
    // Read by `cwt_auth::require_cwt`, which nothing mounts yet — a later
    // change hangs it on the rewrap and media routers. Until then clippy
    // `--bin arks` without `--tests` would treat these as dead.
    /// RFC 8693 `act` chain: the `sub` of each actor that forwarded this
    /// token, innermost first.
    pub actors: Vec<String>,
    pub account_id: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Error)]
pub enum CwtTokenError {
    #[error("invalid authorization header format")]
    InvalidAuthorizationHeader,
    #[error("invalid token encoding")]
    InvalidTokenEncoding,
    #[error("invalid COSE_Sign1 token: {0}")]
    InvalidCoseSign1(String),
    #[error("missing CWT payload")]
    MissingPayload,
    #[error("unsupported CWT signing algorithm")]
    UnsupportedAlgorithm,
    #[error("missing key id")]
    MissingKeyId,
    #[error("unknown key id")]
    UnknownKeyId,
    #[error("invalid COSE key set: {0}")]
    InvalidKeySet(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("missing required claim: {0}")]
    MissingClaim(&'static str),
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("failed to fetch COSE keys: {0}")]
    KeyFetch(String),
    #[error("system clock is before Unix epoch")]
    InvalidSystemTime,
}

#[derive(Clone)]
pub struct CwtValidator {
    keys_url: String,
    expected_issuer: String,
    expected_audience: String,
    client: reqwest::Client,
    cache: Arc<RwLock<CachedKeySet>>,
}

#[derive(Clone, Default)]
struct CachedKeySet {
    keys: Vec<CoseKey>,
    expires_at: Option<Instant>,
    /// Set whenever a forced refresh actually reaches the network. Guards
    /// against a flood of bad-`kid` tokens each triggering their own GET.
    last_forced_refresh: Option<Instant>,
}

/// Build the reqwest client used to fetch the COSE key set. A bounded
/// timeout is required: `validate_authorization_header` awaits this inline,
/// so a hung `CWT_KEYS_URL` would otherwise stall every gated request
/// forever.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

impl CwtValidator {
    pub fn new(keys_url: String, expected_issuer: String, expected_audience: String) -> Self {
        Self {
            keys_url,
            expected_issuer,
            expected_audience,
            client: build_http_client(),
            cache: Arc::new(RwLock::new(CachedKeySet::default())),
        }
    }

    #[cfg(test)]
    fn from_key_set(
        expected_issuer: String,
        expected_audience: String,
        key_set: CoseKeySet,
    ) -> Self {
        Self {
            keys_url: "http://localhost/.well-known/cose-keys".to_string(),
            expected_issuer,
            expected_audience,
            client: build_http_client(),
            cache: Arc::new(RwLock::new(CachedKeySet {
                keys: key_set.0,
                expires_at: Some(Instant::now() + DEFAULT_KEY_CACHE_TTL),
                last_forced_refresh: None,
            })),
        }
    }

    pub async fn refresh_keys(&self, force: bool) -> Result<(), CwtTokenError> {
        if force {
            let mut cache = self.cache.write().await;
            if let Some(last) = cache.last_forced_refresh {
                if last.elapsed() < FORCED_REFRESH_COOLDOWN {
                    return Err(CwtTokenError::UnknownKeyId);
                }
            }
            cache.last_forced_refresh = Some(Instant::now());
        } else {
            let cache = self.cache.read().await;
            if !cache.keys.is_empty()
                && cache
                    .expires_at
                    .is_some_and(|expiry| expiry > Instant::now())
            {
                return Ok(());
            }
        }

        let response = self
            .client
            .get(&self.keys_url)
            .send()
            .await
            .map_err(|e| CwtTokenError::KeyFetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CwtTokenError::KeyFetch(format!(
                "GET {} returned {}",
                self.keys_url,
                response.status()
            )));
        }

        let ttl = response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_max_age)
            .unwrap_or(DEFAULT_KEY_CACHE_TTL);

        let body = response
            .bytes()
            .await
            .map_err(|e| CwtTokenError::KeyFetch(e.to_string()))?;
        let key_set = parse_key_set(&body)?;

        let mut cache = self.cache.write().await;
        cache.keys = key_set.0;
        cache.expires_at = Some(Instant::now() + ttl);
        info!("Loaded {} CWT verification key(s)", cache.keys.len());
        Ok(())
    }

    pub async fn validate_authorization_header(
        &self,
        auth_header: &str,
    ) -> Result<CwtClaims, CwtTokenError> {
        // RFC 7235 §2.1: the auth-scheme token is case-insensitive, so
        // `bearer <tok>` / `BEARER <tok>` must be accepted, not just
        // `Bearer <tok>`.
        let mut parts = auth_header.splitn(2, ' ');
        let scheme = parts
            .next()
            .ok_or(CwtTokenError::InvalidAuthorizationHeader)?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(CwtTokenError::InvalidAuthorizationHeader);
        }
        let token = parts
            .next()
            .ok_or(CwtTokenError::InvalidAuthorizationHeader)?;
        if token.trim().is_empty() || token.contains(char::is_whitespace) {
            return Err(CwtTokenError::InvalidAuthorizationHeader);
        }

        self.refresh_keys(false).await?;
        match self.validate_token_with_cached_keys(token).await {
            Err(CwtTokenError::UnknownKeyId) => {
                self.refresh_keys(true).await?;
                self.validate_token_with_cached_keys(token).await
            }
            result => result,
        }
    }

    /// Validate a raw (no `Bearer ` prefix) CWT. Used for `X-Actor-Token`.
    ///
    /// Called by `cwt_auth::require_cwt`.
    pub async fn validate_bearer(&self, token: &str) -> Result<CwtClaims, CwtTokenError> {
        self.validate_authorization_header(&format!("Bearer {token}"))
            .await
    }

    async fn validate_token_with_cached_keys(
        &self,
        token: &str,
    ) -> Result<CwtClaims, CwtTokenError> {
        let keys = {
            let cache = self.cache.read().await;
            cache.keys.clone()
        };
        validate_token(token, &keys, &self.expected_issuer, &self.expected_audience)
    }
}

pub fn parse_key_set(data: &[u8]) -> Result<CoseKeySet, CwtTokenError> {
    CoseKeySet::from_slice(data).map_err(|e| CwtTokenError::InvalidKeySet(e.to_string()))
}

fn validate_token(
    token: &str,
    keys: &[CoseKey],
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<CwtClaims, CwtTokenError> {
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .or_else(|_| URL_SAFE.decode(token))
        .map_err(|_| CwtTokenError::InvalidTokenEncoding)?;
    let sign1 = CoseSign1::from_tagged_slice(&token_bytes)
        .or_else(|_| CoseSign1::from_slice(&token_bytes))
        .map_err(|e| CwtTokenError::InvalidCoseSign1(e.to_string()))?;

    require_es256(&sign1)?;
    let kid = key_id(&sign1)?;
    let key = keys
        .iter()
        .find(|key| key.key_id == kid)
        .ok_or(CwtTokenError::UnknownKeyId)?;
    require_es256_key(key)?;

    let sec1 = key
        .to_sec1_octet_string()
        .map_err(|e| CwtTokenError::InvalidKeySet(e.to_string()))?;
    let public_key = PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| CwtTokenError::InvalidKeySet("invalid P-256 public key".into()))?;
    let verifying_key = VerifyingKey::from(public_key);
    sign1
        .verify_signature(b"", |signature, tbs| {
            let signature =
                Signature::from_slice(signature).map_err(|_| CwtTokenError::InvalidSignature)?;
            verifying_key
                .verify(tbs, &signature)
                .map_err(|_| CwtTokenError::InvalidSignature)
        })
        .map_err(|_| CwtTokenError::InvalidSignature)?;

    let payload = sign1
        .payload
        .as_deref()
        .ok_or(CwtTokenError::MissingPayload)?;
    let claims = parse_claims(payload)?;
    validate_claims(claims, expected_issuer, expected_audience)
}

fn require_es256(sign1: &CoseSign1) -> Result<(), CwtTokenError> {
    let alg = sign1
        .protected
        .header
        .alg
        .as_ref()
        .or(sign1.unprotected.alg.as_ref())
        .ok_or(CwtTokenError::UnsupportedAlgorithm)?;
    if is_es256(alg) {
        Ok(())
    } else {
        Err(CwtTokenError::UnsupportedAlgorithm)
    }
}

fn require_es256_key(key: &CoseKey) -> Result<(), CwtTokenError> {
    if key.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
        return Err(CwtTokenError::InvalidKeySet("CWT key is not EC2".into()));
    }
    if let Some(alg) = &key.alg {
        if !is_es256(alg) {
            return Err(CwtTokenError::UnsupportedAlgorithm);
        }
    }
    Ok(())
}

fn is_es256(alg: &Algorithm) -> bool {
    matches!(
        alg,
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)
    )
}

fn key_id(sign1: &CoseSign1) -> Result<&[u8], CwtTokenError> {
    let protected = &sign1.protected.header.key_id;
    if !protected.is_empty() {
        return Ok(protected);
    }
    let unprotected = &sign1.unprotected.key_id;
    if !unprotected.is_empty() {
        return Ok(unprotected);
    }
    Err(CwtTokenError::MissingKeyId)
}

/// `aud` as decoded from CBOR: authnz-rs mints it as a list, but a bare text
/// value is accepted too.
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

/// Claims as decoded straight off the CBOR wire, before cross-checking
/// against the expected issuer/audience or the clock.
#[derive(Default)]
struct RawClaims {
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<AudienceClaim>,
    exp: Option<f64>,
    nbf: Option<f64>,
    actors: Vec<String>,
    account_id: Option<String>,
    roles: Vec<String>,
}

/// Decode the CWT claims payload as a CBOR map, by hand.
///
/// `coset::cwt::ClaimsSet` models `aud` (CBOR map key `3`) as `Option<String>`
/// (see `coset` 0.4.2 `src/cwt/mod.rs`). authnz-rs mints `aud` as a CBOR
/// *array* of the intended audiences, so `ClaimsSet::from_slice` fails
/// `try_as_string()` on that key and returns `Err` for the *entire* claims
/// set — every other claim is lost with it. Walking the map ourselves lets
/// `aud` be either shape, and picks up the `act`/`arkavo_*` text claims in
/// the same pass.
///
/// `coset`'s own claim-name decoding rejects a key that is neither an
/// integer nor text, and separately polices duplicate keys (`ciborium`
/// itself does not) — see `authzen::cwt_verify::parse_claims` for the same
/// hardening applied to the union CWT verifier. Both are preserved here so
/// this rewrite doesn't loosen what a malformed or adversarial claims map
/// can get past validation.
fn parse_claims(payload: &[u8]) -> Result<RawClaims, CwtTokenError> {
    let value: Value = ciborium::de::from_reader(payload)
        .map_err(|e| CwtTokenError::InvalidCoseSign1(format!("invalid CWT claims: {e}")))?;
    let Value::Map(entries) = value else {
        return Err(CwtTokenError::InvalidCoseSign1(
            "CWT claims payload is not a map".into(),
        ));
    };

    let mut claims = RawClaims::default();
    let mut seen = std::collections::HashSet::new();
    for (key, value) in entries {
        let seen_key = match &key {
            Value::Integer(i) => format!("i:{}", i128::from(*i)),
            Value::Text(t) => format!("t:{t}"),
            _ => {
                return Err(CwtTokenError::InvalidCoseSign1(
                    "CWT claim key is neither integer nor text".into(),
                ))
            }
        };
        if !seen.insert(seen_key) {
            return Err(CwtTokenError::InvalidCoseSign1(
                "duplicate CWT claim key".into(),
            ));
        }
        match key {
            // RFC 8392 §3.1 registered claim keys.
            Value::Integer(i) => match i128::from(i) {
                1 => {
                    if let Value::Text(s) = value {
                        claims.issuer = Some(s);
                    }
                }
                2 => {
                    if let Value::Text(s) = value {
                        claims.subject = Some(s);
                    }
                }
                3 => match value {
                    Value::Text(s) => claims.audience = Some(AudienceClaim::One(s)),
                    Value::Array(items) => {
                        claims.audience = Some(AudienceClaim::Many(text_array(items)));
                    }
                    _ => {}
                },
                4 => claims.exp = Some(numeric_seconds(&value)?),
                5 => claims.nbf = Some(numeric_seconds(&value)?),
                _ => {}
            },
            Value::Text(name) => match name.as_str() {
                "act" => {
                    if let Value::Array(items) = value {
                        for item in items {
                            if let Value::Map(fields) = item {
                                for (k, v) in fields {
                                    if let (Value::Text(k), Value::Text(v)) = (k, v) {
                                        if k == "sub" {
                                            claims.actors.push(v);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                "arkavo_account_id" => {
                    if let Value::Text(s) = value {
                        claims.account_id = Some(s);
                    }
                }
                "arkavo_roles" => {
                    if let Value::Array(items) = value {
                        claims.roles = text_array(items);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(claims)
}

/// Drop non-text entries rather than fail the whole decode: an `act`/`aud`
/// array is meaningful even if one exotic entry can't be read as text.
fn text_array(items: Vec<Value>) -> Vec<String> {
    items
        .into_iter()
        .filter_map(|item| match item {
            Value::Text(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// RFC 8392 NumericDate: a CBOR integer or float count of seconds.
///
/// Fail-closed: a present `exp`/`nbf` that isn't a well-formed NumericDate
/// (wrong CBOR type, integer too large for `i64`, or a non-finite float
/// such as NaN/±inf) must reject the whole claims set rather than silently
/// treat the claim as absent — an absent `nbf` legitimately disables the
/// not-before check, but a malformed one must not be able to reach that
/// same "no check" outcome.
fn numeric_seconds(value: &Value) -> Result<f64, CwtTokenError> {
    match value {
        Value::Integer(i) => i64::try_from(*i).map(|v| v as f64).map_err(|_| {
            CwtTokenError::InvalidCoseSign1("NumericDate integer out of range".into())
        }),
        Value::Float(f) if f.is_finite() => Ok(*f),
        Value::Float(_) => Err(CwtTokenError::InvalidCoseSign1(
            "NumericDate float is not finite".into(),
        )),
        _ => Err(CwtTokenError::InvalidCoseSign1(
            "NumericDate claim is not a number".into(),
        )),
    }
}

fn validate_claims(
    claims: RawClaims,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<CwtClaims, CwtTokenError> {
    let issuer = claims.issuer.ok_or(CwtTokenError::MissingClaim("iss"))?;
    if issuer != expected_issuer {
        return Err(CwtTokenError::IssuerMismatch);
    }

    let subject = claims.subject.ok_or(CwtTokenError::MissingClaim("sub"))?;

    let audience_claim = claims.audience.ok_or(CwtTokenError::MissingClaim("aud"))?;
    let audience = match &audience_claim {
        AudienceClaim::One(a) if a == expected_audience => Some(a.clone()),
        AudienceClaim::One(_) => None,
        AudienceClaim::Many(list) => list
            .iter()
            .find(|a| a.as_str() == expected_audience)
            .cloned(),
    }
    .ok_or(CwtTokenError::AudienceMismatch)?;

    let now = current_timestamp()?;
    let exp = claims.exp.ok_or(CwtTokenError::MissingClaim("exp"))?;
    if exp <= now {
        return Err(CwtTokenError::Expired);
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now {
            return Err(CwtTokenError::NotYetValid);
        }
    }

    Ok(CwtClaims {
        subject,
        issuer,
        audience,
        actors: claims.actors,
        account_id: claims.account_id,
        roles: claims.roles,
    })
}

fn current_timestamp() -> Result<f64, CwtTokenError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CwtTokenError::InvalidSystemTime)?
        .as_secs_f64())
}

fn parse_max_age(cache_control: &str) -> Option<Duration> {
    cache_control
        .split(',')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::cwt::{ClaimsSet, Timestamp};
    use coset::CoseKeyBuilder;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    const ISSUER: &str = "https://identity.arkavo.net";
    const AUDIENCE: &str = "https://100.arkavo.net";

    #[test]
    fn parses_identity_cose_key_set_shape() {
        let bytes = hex::decode("81a60102025820d8313ee9b4c04c461a0eb00c5f26ce08f7abd670157c48d6b5824ecf7a1ba1b9032620012158209ad9d1e0320d8fa55210fc4ab44fa76233ef36aba2474c71d19c386d4115945c2258203cb9550f3653db28acf03ba0573c18a7a74599fda27c882879ff46020541ba8c").unwrap();
        let key_set = parse_key_set(&bytes).unwrap();
        assert_eq!(key_set.0.len(), 1);
        assert_eq!(
            key_set.0[0].kty,
            coset::KeyType::Assigned(iana::KeyType::EC2)
        );
        assert_eq!(
            key_set.0[0].alg,
            Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256))
        );
        assert!(!key_set.0[0].key_id.is_empty());
    }

    #[tokio::test]
    async fn validates_happy_path_cwt() {
        let (validator, token) = validator_and_token(AUDIENCE, now_plus(300), None);
        let claims = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap();
        assert_eq!(claims.subject, "test-subject");
    }

    #[tokio::test]
    async fn rejects_expired_cwt() {
        let (validator, token) = validator_and_token(AUDIENCE, now_plus(-30), None);
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(matches!(err, CwtTokenError::Expired));
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let (validator, token) = validator_and_token("https://wrong.example", now_plus(300), None);
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(matches!(err, CwtTokenError::AudienceMismatch));
    }

    #[tokio::test]
    async fn rejects_not_yet_valid_cwt() {
        let (validator, token) = validator_and_token(AUDIENCE, now_plus(300), Some(now_plus(60)));
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(matches!(err, CwtTokenError::NotYetValid));
    }

    // `validates_happy_path_cwt` above pins the scalar `aud` shape. These two
    // pin the list-valued shape authnz-rs actually mints (spec §5.1).
    #[tokio::test]
    async fn accepts_audience_array_containing_expected() {
        let (signer, key_set_bytes) = test_support::keypair_and_set();
        let validator = CwtValidator::from_key_set(
            ISSUER.to_string(),
            AUDIENCE.to_string(),
            parse_key_set(&key_set_bytes).unwrap(),
        );
        let token = signer.mint_with_array_aud(
            &[("iss", ISSUER), ("sub", "test-subject")],
            &["https://other.example", AUDIENCE],
        );
        let claims = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap();
        assert_eq!(claims.audience, AUDIENCE);
    }

    #[tokio::test]
    async fn rejects_audience_array_missing_expected() {
        let (signer, key_set_bytes) = test_support::keypair_and_set();
        let validator = CwtValidator::from_key_set(
            ISSUER.to_string(),
            AUDIENCE.to_string(),
            parse_key_set(&key_set_bytes).unwrap(),
        );
        let token = signer.mint_with_array_aud(
            &[("iss", ISSUER), ("sub", "test-subject")],
            &["https://other.example", "https://another.example"],
        );
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(matches!(err, CwtTokenError::AudienceMismatch));
    }

    #[tokio::test]
    async fn forced_refresh_within_cooldown_is_skipped() {
        let (_signer, key_set_bytes) = test_support::keypair_and_set();
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/.well-known/cose-keys"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(key_set_bytes, "application/cbor"),
            )
            .mount(&mock)
            .await;
        let validator = CwtValidator::new(
            format!("{}/.well-known/cose-keys", mock.uri()),
            ISSUER.to_string(),
            AUDIENCE.to_string(),
        );
        validator.refresh_keys(true).await.unwrap();
        // Same-instant retry: the fetch above just ran, so this one must be
        // skipped by the cooldown rather than hitting the mock again.
        let err = validator.refresh_keys(true).await.unwrap_err();
        assert!(matches!(err, CwtTokenError::UnknownKeyId));
    }

    // `ciborium` does not police duplicate map keys on its own — coset's own
    // `ClaimsSet::from_cbor_value` does, and the manual walk in `parse_claims`
    // must preserve that or a token with two `iss` entries would silently
    // resolve to whichever one the loop saw last.
    #[tokio::test]
    async fn rejects_duplicate_claim_key() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let kid = vec![1, 2, 3, 4];
        let public_point = verifying_key.to_encoded_point(false);
        let x = public_point.x().unwrap().to_vec();
        let y = public_point.y().unwrap().to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .key_id(kid.clone())
            .algorithm(iana::Algorithm::ES256)
            .build();
        let validator = CwtValidator::from_key_set(
            ISSUER.to_string(),
            AUDIENCE.to_string(),
            CoseKeySet(vec![key]),
        );

        let payload_map = coset::cbor::value::Value::Map(vec![
            (
                coset::cbor::value::Value::Integer(1.into()),
                coset::cbor::value::Value::Text(ISSUER.to_string()),
            ),
            (
                coset::cbor::value::Value::Integer(1.into()),
                coset::cbor::value::Value::Text("https://impostor.example".to_string()),
            ),
            (
                coset::cbor::value::Value::Integer(2.into()),
                coset::cbor::value::Value::Text("test-subject".to_string()),
            ),
            (
                coset::cbor::value::Value::Integer(3.into()),
                coset::cbor::value::Value::Text(AUDIENCE.to_string()),
            ),
            (
                coset::cbor::value::Value::Integer(4.into()),
                coset::cbor::value::Value::Integer(now_plus(300).into()),
            ),
        ]);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&payload_map, &mut payload).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |tbs| {
                let signature: Signature = signing_key.sign(tbs);
                Ok::<_, CwtTokenError>(signature.to_bytes().to_vec())
            })
            .unwrap()
            .build();
        let token = URL_SAFE_NO_PAD.encode(sign1.to_tagged_vec().unwrap());

        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(matches!(err, CwtTokenError::InvalidCoseSign1(_)));
    }

    // Finding #1: the old `coset` path rejected the whole claims set (via
    // `Timestamp::from_cbor_value`'s type error) when `nbf` wasn't a
    // NumericDate. The rewrite must fail closed the same way, not treat a
    // non-numeric `nbf` as absent (which would skip the not-before check
    // entirely and accept a token before its validity window opens).
    #[tokio::test]
    async fn rejects_non_numeric_nbf() {
        let (validator, token) = raw_claims_token(vec![
            (Value::Integer(1.into()), Value::Text(ISSUER.to_string())),
            (
                Value::Integer(2.into()),
                Value::Text("test-subject".to_string()),
            ),
            (Value::Integer(3.into()), Value::Text(AUDIENCE.to_string())),
            (
                Value::Integer(4.into()),
                Value::Integer(now_plus(300).into()),
            ),
            (
                Value::Integer(5.into()),
                Value::Text("not-a-numeric-date".to_string()),
            ),
        ]);
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CwtTokenError::InvalidCoseSign1(_)),
            "non-numeric nbf must be rejected, not silently ignored: {err:?}"
        );
    }

    // Finding #2: a non-finite `exp` (NaN) makes `exp <= now` false, so the
    // token would never expire if `numeric_seconds` accepted it.
    #[tokio::test]
    async fn rejects_nan_exp() {
        let (validator, token) = raw_claims_token(vec![
            (Value::Integer(1.into()), Value::Text(ISSUER.to_string())),
            (
                Value::Integer(2.into()),
                Value::Text("test-subject".to_string()),
            ),
            (Value::Integer(3.into()), Value::Text(AUDIENCE.to_string())),
            (Value::Integer(4.into()), Value::Float(f64::NAN)),
        ]);
        let err = validator
            .validate_authorization_header(&format!("Bearer {token}"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CwtTokenError::InvalidCoseSign1(_)),
            "NaN exp must be rejected, not accepted: {err:?}"
        );
    }

    // Finding #4: RFC 7235 §2.1 makes the auth-scheme token case-insensitive.
    #[tokio::test]
    async fn accepts_lowercase_bearer_scheme() {
        let (validator, token) = validator_and_token(AUDIENCE, now_plus(300), None);
        let claims = validator
            .validate_authorization_header(&format!("bearer {token}"))
            .await
            .unwrap();
        assert_eq!(claims.subject, "test-subject");
    }

    /// Sign an arbitrary CBOR claims map, bypassing `coset::cwt::ClaimsSet`
    /// so tests can put non-NumericDate values in `exp`/`nbf`.
    fn raw_claims_token(payload_map: Vec<(Value, Value)>) -> (CwtValidator, String) {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let kid = vec![1, 2, 3, 4];
        let public_point = verifying_key.to_encoded_point(false);
        let x = public_point.x().unwrap().to_vec();
        let y = public_point.y().unwrap().to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .key_id(kid.clone())
            .algorithm(iana::Algorithm::ES256)
            .build();
        let validator = CwtValidator::from_key_set(
            ISSUER.to_string(),
            AUDIENCE.to_string(),
            CoseKeySet(vec![key]),
        );

        let payload_value = Value::Map(payload_map);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&payload_value, &mut payload).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |tbs| {
                let signature: Signature = signing_key.sign(tbs);
                Ok::<_, CwtTokenError>(signature.to_bytes().to_vec())
            })
            .unwrap()
            .build();
        let token = URL_SAFE_NO_PAD.encode(sign1.to_tagged_vec().unwrap());
        (validator, token)
    }

    fn validator_and_token(audience: &str, exp: i64, nbf: Option<i64>) -> (CwtValidator, String) {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let kid = vec![1, 2, 3, 4];
        let public_point = verifying_key.to_encoded_point(false);
        let x = public_point.x().unwrap().to_vec();
        let y = public_point.y().unwrap().to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .key_id(kid.clone())
            .algorithm(iana::Algorithm::ES256)
            .build();
        let validator = CwtValidator::from_key_set(
            ISSUER.to_string(),
            AUDIENCE.to_string(),
            CoseKeySet(vec![key]),
        );
        let token = signed_token(&signing_key, &kid, audience, exp, nbf);
        (validator, token)
    }

    fn signed_token(
        signing_key: &SigningKey,
        kid: &[u8],
        audience: &str,
        exp: i64,
        nbf: Option<i64>,
    ) -> String {
        let mut claims = ClaimsSet {
            issuer: Some(ISSUER.to_string()),
            subject: Some("test-subject".to_string()),
            audience: Some(audience.to_string()),
            expiration_time: Some(Timestamp::WholeSeconds(exp)),
            issued_at: Some(Timestamp::WholeSeconds(now_plus(-5))),
            ..ClaimsSet::default()
        };
        claims.not_before = nbf.map(Timestamp::WholeSeconds);
        let payload = claims.to_vec().unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |tbs| {
                let signature: Signature = signing_key.sign(tbs);
                Ok::<_, CwtTokenError>(signature.to_bytes().to_vec())
            })
            .unwrap()
            .build();
        URL_SAFE_NO_PAD.encode(sign1.to_tagged_vec().unwrap())
    }

    fn now_plus(offset_secs: i64) -> i64 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
            + offset_secs
    }
}

/// CWT-minting helpers shared by this module's tests and by
/// `cwt_auth`'s middleware tests. `pub(crate)` so `cwt_auth.rs` can reach
/// them under `#[cfg(test)]`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use coset::cwt::{ClaimName, ClaimsSet, Timestamp};
    use coset::{CoseKeyBuilder, CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};

    /// Signs test CWTs with an ephemeral ES256 key.
    pub(crate) struct Signer {
        key: SigningKey,
        kid: Vec<u8>,
    }

    /// A fresh `Signer` plus the CBOR-encoded `CoseKeySet` bytes a validator
    /// would fetch from `/.well-known/cose-keys` to verify its tokens.
    pub(crate) fn keypair_and_set() -> (Signer, Vec<u8>) {
        let signing_key = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let kid = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let public_point = verifying_key.to_encoded_point(false);
        let x = public_point.x().unwrap().to_vec();
        let y = public_point.y().unwrap().to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .key_id(kid.clone())
            .algorithm(iana::Algorithm::ES256)
            .build();
        let set_bytes = CoseKeySet(vec![key]).to_vec().unwrap();
        (
            Signer {
                key: signing_key,
                kid,
            },
            set_bytes,
        )
    }

    impl Signer {
        /// Mint a CWT from `(claim, value)` text pairs. Recognizes `"iss"`,
        /// `"sub"`, `"aud"`; `exp` is always set to now+300.
        pub(crate) fn mint(&self, claims: &[(&str, &str)]) -> String {
            self.build(claims, None, &[])
        }

        /// Like [`Self::mint`], but also sets `act` to
        /// `[{"sub": actor}, ...]` for each of `actors`.
        pub(crate) fn mint_with_act(&self, claims: &[(&str, &str)], actors: &[&str]) -> String {
            self.build(claims, None, actors)
        }

        /// Like [`Self::mint`], but `aud` is minted as a CBOR array of
        /// `audiences` rather than a bare text value (any `"aud"` pair in
        /// `claims` is ignored). This is the shape authnz-rs actually mints.
        pub(crate) fn mint_with_array_aud(
            &self,
            claims: &[(&str, &str)],
            audiences: &[&str],
        ) -> String {
            self.build(claims, Some(audiences), &[])
        }

        fn build(
            &self,
            claims: &[(&str, &str)],
            array_aud: Option<&[&str]>,
            actors: &[&str],
        ) -> String {
            let mut set = ClaimsSet {
                expiration_time: Some(Timestamp::WholeSeconds(now_plus(300))),
                ..ClaimsSet::default()
            };
            for (name, value) in claims {
                match *name {
                    "iss" => set.issuer = Some((*value).to_string()),
                    "sub" => set.subject = Some((*value).to_string()),
                    "aud" if array_aud.is_none() => set.audience = Some((*value).to_string()),
                    _ => {}
                }
            }
            if let Some(list) = array_aud {
                set.rest.push((
                    ClaimName::Assigned(iana::CwtClaimName::Aud),
                    Value::Array(list.iter().map(|a| Value::Text((*a).to_string())).collect()),
                ));
            }
            if !actors.is_empty() {
                let act = Value::Array(
                    actors
                        .iter()
                        .map(|actor| {
                            Value::Map(vec![(
                                Value::Text("sub".to_string()),
                                Value::Text((*actor).to_string()),
                            )])
                        })
                        .collect(),
                );
                set.rest.push((ClaimName::Text("act".to_string()), act));
            }

            let payload = set.to_vec().unwrap();
            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .key_id(self.kid.clone())
                .build();
            let sign1 = CoseSign1Builder::new()
                .protected(protected)
                .payload(payload)
                .try_create_signature(b"", |tbs| {
                    let signature: Signature = self.key.sign(tbs);
                    Ok::<_, CwtTokenError>(signature.to_bytes().to_vec())
                })
                .unwrap()
                .build();
            URL_SAFE_NO_PAD.encode(sign1.to_tagged_vec().unwrap())
        }
    }

    fn now_plus(offset_secs: i64) -> i64 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
            + offset_secs
    }
}
