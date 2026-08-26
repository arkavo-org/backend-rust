//! COSE_Key Set cache (catalog CwtVerifier algorithm: 60s min refresh, 10s fetch).

use crate::modules::authzen::cwt_verify::VerifyError;
use ciborium::value::Value;
use coset::AsCborValue;
use p256::ecdsa::VerifyingKey;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const KEY_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);
const KEY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

struct KeyCache {
    keys: HashMap<Vec<u8>, VerifyingKey>,
    last_fetch: Option<Instant>,
}

pub struct CoseKeyCache {
    cose_keys_url: Option<String>,
    http: reqwest::Client,
    cache: RwLock<KeyCache>,
}

fn bounded_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(KEY_FETCH_TIMEOUT)
        .build()
        .expect("reqwest client")
}

impl CoseKeyCache {
    pub fn new(cose_keys_url: String) -> Self {
        Self {
            cose_keys_url: Some(cose_keys_url),
            http: bounded_http_client(),
            cache: RwLock::new(KeyCache {
                keys: HashMap::new(),
                last_fetch: None,
            }),
        }
    }

    #[cfg(test)]
    pub fn with_static_keys(keys: Vec<(Vec<u8>, VerifyingKey)>) -> Self {
        Self {
            cose_keys_url: None,
            http: bounded_http_client(),
            cache: RwLock::new(KeyCache {
                keys: keys.into_iter().collect(),
                last_fetch: None,
            }),
        }
    }

    pub async fn resolve(&self, kid: &[u8]) -> Result<VerifyingKey, VerifyError> {
        if let Some(k) = self.lookup(kid).await {
            return Ok(k);
        }
        self.refresh_keys().await?;
        self.lookup(kid).await.ok_or(VerifyError::UnknownKid)
    }

    async fn lookup(&self, kid: &[u8]) -> Option<VerifyingKey> {
        self.cache.read().await.keys.get(kid).copied()
    }

    async fn refresh_keys(&self) -> Result<(), VerifyError> {
        let Some(url) = &self.cose_keys_url else {
            return Ok(());
        };
        {
            let mut cache = self.cache.write().await;
            if let Some(last) = cache.last_fetch {
                if last.elapsed() < KEY_REFRESH_MIN_INTERVAL {
                    return Ok(());
                }
            }
            cache.last_fetch = Some(Instant::now());
        }

        let resp = self.http.get(url).send().await.map_err(|e| {
            log::warn!("cose-keys GET {url}: {e}");
            VerifyError::KeySet
        })?;
        if !resp.status().is_success() {
            log::warn!("cose-keys GET {url}: HTTP {}", resp.status());
            return Err(VerifyError::KeySet);
        }
        let body = resp.bytes().await.map_err(|e| {
            log::warn!("cose-keys body: {e}");
            VerifyError::KeySet
        })?;
        let keys = parse_cose_key_set(&body).map_err(|e| {
            log::warn!("cose-keys parse: {e}");
            VerifyError::KeySet
        })?;
        log::info!("Refreshed COSE key set ({} keys)", keys.len());
        self.cache.write().await.keys = keys.into_iter().collect();
        Ok(())
    }
}

pub fn parse_cose_key_set(bytes: &[u8]) -> Result<Vec<(Vec<u8>, VerifyingKey)>, String> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|e| e.to_string())?;
    let Value::Array(entries) = value else {
        return Err("key set is not a CBOR array".into());
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = match coset::CoseKey::from_cbor_value(entry) {
            Ok(k) => k,
            Err(e) => {
                log::warn!("Skipping unparseable COSE key in set: {e:?}");
                continue;
            }
        };
        match p256_from_cose_key(&key) {
            Ok(vk) if !key.key_id.is_empty() => out.push((key.key_id.clone(), vk)),
            Ok(_) => log::warn!("Skipping COSE key without kid"),
            Err(e) => log::warn!("Skipping non-P-256 COSE key: {e}"),
        }
    }
    if out.is_empty() {
        return Err("no usable P-256 keys in key set".into());
    }
    Ok(out)
}

fn p256_from_cose_key(key: &coset::CoseKey) -> Result<VerifyingKey, String> {
    use coset::iana::{Ec2KeyParameter, EnumI64};

    if key.kty != coset::KeyType::Assigned(coset::iana::KeyType::EC2) {
        return Err("kty is not EC2".into());
    }
    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    let mut crv_ok = false;
    for (label, value) in &key.params {
        match label {
            coset::Label::Int(l) if *l == Ec2KeyParameter::Crv as i64 => {
                crv_ok = matches!(
                    value,
                    Value::Integer(i)
                        if i128::from(*i) == i128::from(coset::iana::EllipticCurve::P_256.to_i64())
                );
            }
            coset::Label::Int(l) if *l == Ec2KeyParameter::X as i64 => {
                if let Value::Bytes(b) = value {
                    x = Some(b);
                }
            }
            coset::Label::Int(l) if *l == Ec2KeyParameter::Y as i64 => {
                if let Value::Bytes(b) = value {
                    y = Some(b);
                }
            }
            _ => {}
        }
    }
    if !crv_ok {
        return Err("crv is not P-256".into());
    }
    let (x, y) = (
        x.ok_or_else(|| "missing x".to_string())?,
        y.ok_or_else(|| "missing y".to_string())?,
    );
    if x.len() != 32 || y.len() != 32 {
        return Err("x/y are not 32 bytes".into());
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authzen::cwt_verify::test_support::keypair;

    #[test]
    fn key_set_roundtrip() {
        let (_, vk) = keypair();
        let point = vk.to_encoded_point(false);
        let cose_key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .key_id(b"kid-1".to_vec())
        .build();
        let set = Value::Array(vec![cose_key.to_cbor_value().unwrap()]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&set, &mut bytes).unwrap();
        let keys = parse_cose_key_set(&bytes).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, b"kid-1".to_vec());
        assert_eq!(keys[0].1, vk);
    }

    #[tokio::test]
    async fn static_keys_resolve() {
        let (_, vk) = keypair();
        let cache = CoseKeyCache::with_static_keys(vec![(b"kid-1".to_vec(), vk)]);
        assert_eq!(cache.resolve(b"kid-1").await.unwrap(), vk);
        assert_eq!(
            cache.resolve(b"missing").await.unwrap_err(),
            VerifyError::UnknownKid
        );
    }
}
