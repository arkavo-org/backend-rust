//! Union CWT verifier (draft-arkavo-authzen-cwt-00 PR 2b).
//! Stricter than either `authnz-rs::cwt::verify` or catalog `CwtVerifier`.
//! Wired by the AuthZEN facade; clippy `--bin arks` without `--tests` would
//! otherwise treat these as dead.

#![allow(dead_code)]

use crate::modules::authzen::cwt_subject::{Aud, DecodedClaims};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use std::collections::HashSet;

const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];
pub const SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    UnsupportedAlg,
    MissingProtectedKid,
    UnknownKid,
    Signature,
    Expired,
    NotYetValid,
    MissingClaim(&'static str),
    DuplicateKey,
    Issuer,
    Audience,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOpts<'a> {
    pub expected_iss: Option<&'a str>,
    pub expected_aud: Option<&'a str>,
    pub expected_kid: Option<&'a [u8]>,
    pub now: i64,
}

/// Verify unpadded-base64url CWT (tag 61 + COSE_Sign1 ES256).
pub fn verify_header_token(
    token_b64: &str,
    key: &VerifyingKey,
    opts: VerifyOpts<'_>,
) -> Result<DecodedClaims, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token_b64.trim())
        .map_err(|_| VerifyError::Malformed)?;
    verify_tagged_bytes(&bytes, key, opts)
}

pub fn verify_tagged_bytes(
    bytes: &[u8],
    key: &VerifyingKey,
    opts: VerifyOpts<'_>,
) -> Result<DecodedClaims, VerifyError> {
    let inner = bytes
        .strip_prefix(&CWT_TAG_PREFIX)
        .ok_or(VerifyError::Malformed)?;
    let sign1 = CoseSign1::from_slice(inner).map_err(|_| VerifyError::Malformed)?;
    match sign1.protected.header.alg {
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256)) => {}
        _ => return Err(VerifyError::UnsupportedAlg),
    }
    if sign1.protected.header.key_id.is_empty() {
        return Err(VerifyError::MissingProtectedKid);
    }
    if let Some(want) = opts.expected_kid {
        if sign1.protected.header.key_id.as_slice() != want {
            return Err(VerifyError::UnknownKid);
        }
    }
    sign1
        .verify_signature(b"", |sig, data| {
            let sig = Signature::from_slice(sig).map_err(|_| ())?;
            key.verify(data, &sig).map_err(|_| ())
        })
        .map_err(|_| VerifyError::Signature)?;
    let payload = sign1.payload.as_deref().ok_or(VerifyError::Malformed)?;
    let claims = parse_claims(payload)?;
    if let Some(want) = opts.expected_iss {
        if claims.iss != want {
            return Err(VerifyError::Issuer);
        }
    }
    if let Some(want) = opts.expected_aud {
        let ok = match &claims.aud {
            Aud::One(s) => s == want,
            Aud::Many(v) => v.iter().any(|s| s == want),
        };
        if !ok {
            return Err(VerifyError::Audience);
        }
    }
    if claims.iat > claims.exp {
        return Err(VerifyError::Malformed);
    }
    if (claims.exp as i64) <= opts.now - SKEW_SECS {
        return Err(VerifyError::Expired);
    }
    if (claims.iat as i64) > opts.now + SKEW_SECS {
        return Err(VerifyError::NotYetValid);
    }
    Ok(claims)
}

fn parse_claims(payload: &[u8]) -> Result<DecodedClaims, VerifyError> {
    let value: Value = ciborium::de::from_reader(payload).map_err(|_| VerifyError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(VerifyError::Malformed);
    };
    let mut seen = HashSet::new();
    let mut iss = None;
    let mut sub = None;
    let mut aud = None;
    let mut exp = None;
    let mut iat = None;
    let mut cti = None;
    let mut email = None;
    let mut email_verified = None;
    let mut idp = None;
    let mut arkavo_account_id = None;
    let mut arkavo_roles = None;
    let mut arkavo_entitlements = None;
    let mut client_id = None;
    let mut arkavo_patreon = None;
    for (k, v) in entries {
        let key_id = match &k {
            Value::Integer(i) => format!("i:{}", i128::from(*i)),
            Value::Text(t) => format!("t:{t}"),
            _ => return Err(VerifyError::Malformed),
        };
        if !seen.insert(key_id) {
            return Err(VerifyError::DuplicateKey);
        }
        match k {
            Value::Integer(key) => match (i128::from(key), v) {
                (1, Value::Text(s)) => iss = Some(s),
                (2, Value::Text(s)) => sub = Some(s),
                (3, Value::Text(s)) => aud = Some(Aud::One(s)),
                (3, Value::Array(a)) => {
                    let mut v = Vec::new();
                    for item in a {
                        let Value::Text(s) = item else {
                            return Err(VerifyError::Malformed);
                        };
                        v.push(s);
                    }
                    aud = Some(Aud::Many(v));
                }
                (4, Value::Integer(n)) => {
                    exp = u64::try_from(i128::from(n)).ok();
                }
                (6, Value::Integer(n)) => {
                    iat = u64::try_from(i128::from(n)).ok();
                }
                (7, Value::Bytes(b)) => cti = Some(b),
                _ => {}
            },
            Value::Text(key) => match (key.as_str(), v) {
                ("email", Value::Text(s)) => email = Some(s),
                ("email_verified", Value::Bool(b)) => email_verified = Some(b),
                ("idp", Value::Text(s)) => idp = Some(s),
                ("arkavo_account_id", Value::Text(s)) => arkavo_account_id = Some(s),
                ("client_id", Value::Text(s)) => client_id = Some(s),
                ("arkavo_roles", Value::Array(a)) => {
                    arkavo_roles = Some(text_array(a)?);
                }
                ("arkavo_entitlements", Value::Array(a)) => {
                    arkavo_entitlements = Some(text_array(a)?);
                }
                ("arkavo_patreon", m @ Value::Map(_)) => {
                    arkavo_patreon = Some(cbor_to_json(&m));
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(DecodedClaims {
        iss: iss.ok_or(VerifyError::MissingClaim("iss"))?,
        sub: sub.ok_or(VerifyError::MissingClaim("sub"))?,
        aud: aud.ok_or(VerifyError::MissingClaim("aud"))?,
        exp: exp.ok_or(VerifyError::MissingClaim("exp"))?,
        iat: iat.ok_or(VerifyError::MissingClaim("iat"))?,
        cti: cti.ok_or(VerifyError::MissingClaim("cti"))?,
        email,
        email_verified,
        idp,
        arkavo_account_id,
        arkavo_roles,
        arkavo_entitlements,
        client_id,
        arkavo_patreon,
    })
}

fn text_array(a: Vec<Value>) -> Result<Vec<String>, VerifyError> {
    a.into_iter()
        .map(|v| match v {
            Value::Text(s) => Ok(s),
            _ => Err(VerifyError::Malformed),
        })
        .collect()
}

fn cbor_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Integer(i) => {
            let n = i128::from(*i);
            serde_json::json!(n)
        }
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(cbor_to_json).collect()),
        Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                if let Value::Text(ks) = k {
                    obj.insert(ks.clone(), cbor_to_json(val));
                }
            }
            serde_json::Value::Object(obj)
        }
        Value::Bytes(b) => serde_json::Value::String(URL_SAFE_NO_PAD.encode(b)),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use coset::{iana, CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    pub fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_slice(&[0x17u8; 32]).expect("scalar");
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    pub fn mint(
        key: &SigningKey,
        kid: &[u8],
        iss: &str,
        sub: &str,
        aud: &str,
        iat: i64,
        exp: i64,
        cti: &[u8],
    ) -> String {
        mint_map(
            key,
            kid,
            vec![
                (Value::Integer(1.into()), Value::Text(iss.into())),
                (Value::Integer(2.into()), Value::Text(sub.into())),
                (Value::Integer(3.into()), Value::Text(aud.into())),
                (Value::Integer(4.into()), Value::Integer(exp.into())),
                (Value::Integer(6.into()), Value::Integer(iat.into())),
                (Value::Integer(7.into()), Value::Bytes(cti.to_vec())),
            ],
        )
    }

    pub fn mint_map(key: &SigningKey, kid: &[u8], entries: Vec<(Value, Value)>) -> String {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut payload).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |to_sign| {
                let sig: Signature = key.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build();
        let inner = sign1.to_vec().unwrap();
        let mut out = Vec::with_capacity(CWT_TAG_PREFIX.len() + inner.len());
        out.extend_from_slice(&CWT_TAG_PREFIX);
        out.extend_from_slice(&inner);
        URL_SAFE_NO_PAD.encode(out)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{keypair, mint, mint_map};
    use super::*;
    use ciborium::value::Value;

    const NOW: i64 = 1_900_000_000;
    const KID: &[u8] = b"kid-1";

    fn opts() -> VerifyOpts<'static> {
        VerifyOpts {
            expected_iss: Some("https://identity.test"),
            expected_aud: Some("arkavo"),
            expected_kid: Some(KID),
            now: NOW,
        }
    }

    fn token(sk: &p256::ecdsa::SigningKey) -> String {
        mint(
            sk,
            KID,
            "https://identity.test",
            "arkavo:u1",
            "arkavo",
            NOW,
            NOW + 3600,
            &[7u8; 16],
        )
    }

    #[test]
    fn verify_roundtrip() {
        let (sk, vk) = keypair();
        let claims = verify_header_token(&token(&sk), &vk, opts()).unwrap();
        assert_eq!(claims.sub, "arkavo:u1");
        assert_eq!(claims.cti, vec![7u8; 16]);
        match claims.aud {
            Aud::One(s) => assert_eq!(s, "arkavo"),
            Aud::Many(_) => panic!("expected single aud"),
        }
    }

    #[test]
    fn reject_untagged() {
        let (sk, vk) = keypair();
        let t = token(&sk);
        let raw = URL_SAFE_NO_PAD.decode(&t).unwrap();
        let inner = &raw[2..];
        let b64 = URL_SAFE_NO_PAD.encode(inner);
        assert!(matches!(
            verify_header_token(&b64, &vk, opts()),
            Err(VerifyError::Malformed)
        ));
    }

    #[test]
    fn reject_expired_inclusive_skew() {
        let (sk, vk) = keypair();
        let t = mint(
            &sk,
            KID,
            "https://identity.test",
            "arkavo:u1",
            "arkavo",
            NOW - 120,
            NOW - 60,
            &[1u8; 16],
        );
        // exp == now - 60 → Expired (union uses <=)
        assert!(matches!(
            verify_header_token(&t, &vk, opts()),
            Err(VerifyError::Expired)
        ));
    }

    #[test]
    fn reject_iat_after_exp() {
        let (sk, vk) = keypair();
        let t = mint(
            &sk,
            KID,
            "https://identity.test",
            "arkavo:u1",
            "arkavo",
            NOW + 10,
            NOW,
            &[1u8; 16],
        );
        assert!(matches!(
            verify_header_token(&t, &vk, opts()),
            Err(VerifyError::Malformed)
        ));
    }

    #[test]
    fn reject_missing_cti() {
        let (sk, vk) = keypair();
        let t = mint_map(
            &sk,
            KID,
            vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("https://identity.test".into()),
                ),
                (Value::Integer(2.into()), Value::Text("arkavo:u1".into())),
                (Value::Integer(3.into()), Value::Text("arkavo".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
            ],
        );
        assert!(matches!(
            verify_header_token(&t, &vk, opts()),
            Err(VerifyError::MissingClaim("cti"))
        ));
    }

    #[test]
    fn reject_unknown_kid() {
        let (sk, vk) = keypair();
        let t = token(&sk);
        let mut o = opts();
        o.expected_kid = Some(b"other");
        assert!(matches!(
            verify_header_token(&t, &vk, o),
            Err(VerifyError::UnknownKid)
        ));
    }

    #[test]
    fn reject_wrong_aud() {
        let (sk, vk) = keypair();
        let t = mint(
            &sk,
            KID,
            "https://identity.test",
            "arkavo:u1",
            "other",
            NOW,
            NOW + 3600,
            &[1u8; 16],
        );
        assert!(matches!(
            verify_header_token(&t, &vk, opts()),
            Err(VerifyError::Audience)
        ));
    }

    #[test]
    fn reject_duplicate_integer_keys() {
        let (sk, vk) = keypair();
        let t = mint_map(
            &sk,
            KID,
            vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("https://identity.test".into()),
                ),
                (
                    Value::Integer(1.into()),
                    Value::Text("https://evil.test".into()),
                ),
                (Value::Integer(2.into()), Value::Text("arkavo:u1".into())),
                (Value::Integer(3.into()), Value::Text("arkavo".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
                (Value::Integer(7.into()), Value::Bytes(vec![1u8; 16])),
            ],
        );
        assert!(matches!(
            verify_header_token(&t, &vk, opts()),
            Err(VerifyError::DuplicateKey)
        ));
    }
}
