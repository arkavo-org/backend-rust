//! CBOR Web Token validation for WebSocket authentication.

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use coset::cwt::{ClaimsSet, Timestamp};
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

#[derive(Debug, Clone)]
pub struct CwtClaims {
    pub subject: String,
    pub issuer: String,
    pub audience: String,
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
}

impl CwtValidator {
    pub fn new(keys_url: String, expected_issuer: String, expected_audience: String) -> Self {
        Self {
            keys_url,
            expected_issuer,
            expected_audience,
            client: reqwest::Client::new(),
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
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(CachedKeySet {
                keys: key_set.0,
                expires_at: Some(Instant::now() + DEFAULT_KEY_CACHE_TTL),
            })),
        }
    }

    pub async fn refresh_keys(&self, force: bool) -> Result<(), CwtTokenError> {
        if !force {
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
        let token = auth_header
            .strip_prefix("Bearer ")
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
    let claims = ClaimsSet::from_slice(payload)
        .map_err(|e| CwtTokenError::InvalidCoseSign1(format!("invalid CWT claims: {e}")))?;
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

fn validate_claims(
    claims: ClaimsSet,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<CwtClaims, CwtTokenError> {
    let issuer = claims.issuer.ok_or(CwtTokenError::MissingClaim("iss"))?;
    if issuer != expected_issuer {
        return Err(CwtTokenError::IssuerMismatch);
    }

    let subject = claims.subject.ok_or(CwtTokenError::MissingClaim("sub"))?;
    let audience = claims.audience.ok_or(CwtTokenError::MissingClaim("aud"))?;
    if audience != expected_audience {
        return Err(CwtTokenError::AudienceMismatch);
    }

    let now = current_timestamp()?;
    let exp = claims
        .expiration_time
        .ok_or(CwtTokenError::MissingClaim("exp"))?;
    if timestamp_seconds(&exp) <= now {
        return Err(CwtTokenError::Expired);
    }
    if let Some(nbf) = claims.not_before {
        if timestamp_seconds(&nbf) > now {
            return Err(CwtTokenError::NotYetValid);
        }
    }

    Ok(CwtClaims {
        subject,
        issuer,
        audience,
    })
}

fn current_timestamp() -> Result<f64, CwtTokenError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CwtTokenError::InvalidSystemTime)?
        .as_secs_f64())
}

fn timestamp_seconds(timestamp: &Timestamp) -> f64 {
    match timestamp {
        Timestamp::WholeSeconds(value) => *value as f64,
        Timestamp::FractionalSeconds(value) => *value,
    }
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
