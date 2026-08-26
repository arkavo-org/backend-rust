//! Verification-agnostic CWT → `$token` / SARC projection (draft-arkavo-authzen-cwt-00 PR 2).
//! Wired by the AuthZEN facade; clippy `--bin arks` without `--tests` would
//! otherwise treat these as dead.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};

pub const DEVICECHECK_AUD: &str = "arkavo:devicecheck";

/// Strip a single leading `arkavo:` prefix. Does not strip `apple:` or `client:`.
pub fn subject_id_bind(s: &str) -> &str {
    s.strip_prefix("arkavo:").unwrap_or(s)
}

#[derive(Debug, Clone)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

/// Already-verified CWT claims. Mapping only — no COSE verify here.
#[derive(Debug, Clone)]
pub struct DecodedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Aud,
    pub exp: u64,
    pub iat: u64,
    pub cti: Vec<u8>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub idp: Option<String>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub arkavo_patreon: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceObject {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    MissingField(&'static str),
    BothDeviceAndDevices,
    EmptyDevices,
}

/// `$token` map: text claim names, no integer keys, no `cnf`.
pub fn token_map(claims: &DecodedClaims) -> Value {
    let mut m = Map::new();
    m.insert("iss".into(), json!(claims.iss));
    m.insert("sub".into(), json!(claims.sub));
    m.insert(
        "aud".into(),
        match &claims.aud {
            Aud::One(s) => json!(s),
            Aud::Many(v) => json!(v),
        },
    );
    m.insert("exp".into(), json!(claims.exp));
    m.insert("iat".into(), json!(claims.iat));
    m.insert("cti".into(), json!(URL_SAFE_NO_PAD.encode(&claims.cti)));
    insert_opt_str(&mut m, "email", claims.email.as_deref());
    if let Some(v) = claims.email_verified {
        m.insert("email_verified".into(), json!(v));
    }
    insert_opt_str(&mut m, "idp", claims.idp.as_deref());
    insert_opt_str(
        &mut m,
        "arkavo_account_id",
        claims.arkavo_account_id.as_deref(),
    );
    if let Some(roles) = &claims.arkavo_roles {
        m.insert("arkavo_roles".into(), json!(roles));
    }
    if let Some(ents) = &claims.arkavo_entitlements {
        m.insert("arkavo_entitlements".into(), json!(ents));
    }
    insert_opt_str(&mut m, "client_id", claims.client_id.as_deref());
    if let Some(patreon) = &claims.arkavo_patreon {
        m.insert("arkavo_patreon".into(), sanitize_patreon(patreon));
    }
    Value::Object(m)
}

fn insert_opt_str(m: &mut Map<String, Value>, k: &str, v: Option<&str>) {
    if let Some(s) = v {
        m.insert(k.into(), json!(s));
    }
}

fn sanitize_patreon(p: &Value) -> Value {
    let Some(obj) = p.as_object() else {
        return p.clone();
    };
    let mut out = obj.clone();
    if out.get("role").and_then(Value::as_str) == Some("consumer") {
        out.remove("campaign_id");
    }
    Value::Object(out)
}

/// AuthZEN subject (`type=identity`, `id` as minted).
pub fn subject(claims: &DecodedClaims) -> Value {
    let mut properties = Map::new();
    properties.insert("iss".into(), json!(claims.iss));
    insert_opt_str(&mut properties, "email", claims.email.as_deref());
    if let Some(v) = claims.email_verified {
        properties.insert("email_verified".into(), json!(v));
    }
    insert_opt_str(&mut properties, "idp", claims.idp.as_deref());
    insert_opt_str(
        &mut properties,
        "arkavo_account_id",
        claims.arkavo_account_id.as_deref(),
    );
    if let Some(roles) = &claims.arkavo_roles {
        properties.insert("arkavo_roles".into(), json!(roles));
    }
    if let Some(ents) = &claims.arkavo_entitlements {
        properties.insert("arkavo_entitlements".into(), json!(ents));
    }
    if let Some(patreon) = &claims.arkavo_patreon {
        properties.insert("arkavo_patreon".into(), sanitize_patreon(patreon));
    }
    json!({
        "type": "identity",
        "id": claims.sub,
        "properties": properties,
    })
}

pub fn devices_bind(pe_sub: &str, device_sub: &str) -> bool {
    subject_id_bind(pe_sub) == subject_id_bind(device_sub)
}

pub fn allowlist_device(obj: &Value) -> Result<DeviceObject, DeviceError> {
    let map = obj.as_object().ok_or(DeviceError::MissingField("sub"))?;
    let req = |k: &'static str| -> Result<String, DeviceError> {
        map.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or(DeviceError::MissingField(k))
    };
    Ok(DeviceObject {
        sub: req("sub")?,
        iss: req("iss")?,
        aud: req("aud")?,
        kid: req("kid")?,
    })
}

pub fn device_to_value(d: &DeviceObject) -> Value {
    json!({
        "sub": d.sub,
        "iss": d.iss,
        "aud": d.aud,
        "kid": d.kid,
    })
}

/// Environment allowlist: `{region}` plus optional `kind`. Other keys dropped.
pub fn allowlist_environment(obj: &Value) -> Value {
    let mut out = Map::new();
    if let Some(map) = obj.as_object() {
        if let Some(r) = map.get("region") {
            out.insert("region".into(), r.clone());
        }
        if let Some(k) = map.get("kind") {
            out.insert("kind".into(), k.clone());
        }
    }
    Value::Object(out)
}

pub fn devices_from_context(context: &Value) -> Result<Vec<DeviceObject>, DeviceError> {
    let Some(obj) = context.as_object() else {
        return Ok(vec![]);
    };
    let has_device = obj.contains_key("device");
    let has_devices = obj.contains_key("devices");
    if has_device && has_devices {
        return Err(DeviceError::BothDeviceAndDevices);
    }
    if has_device {
        return Ok(vec![allowlist_device(&obj["device"])?]);
    }
    if has_devices {
        let arr = obj["devices"].as_array().ok_or(DeviceError::EmptyDevices)?;
        if arr.is_empty() {
            return Err(DeviceError::EmptyDevices);
        }
        arr.iter().map(allowlist_device).collect()
    } else {
        Ok(vec![])
    }
}

/// `context.agent` fallbacks (COAZ-MCP CWT profile override 3).
pub fn context_agent(claims: &DecodedClaims, platform_audience: Option<&str>) -> Option<String> {
    if let Some(id) = claims.client_id.as_deref().filter(|s| !s.is_empty()) {
        return Some(id.to_string());
    }
    if let Some(rest) = claims.sub.strip_prefix("client:") {
        if !rest.is_empty() {
            return Some(rest.to_string());
        }
    }
    let members: Vec<&str> = match &claims.aud {
        Aud::One(s) => vec![s.as_str()],
        Aud::Many(v) => v.iter().map(String::as_str).collect(),
    };
    let filtered: Vec<&str> = members
        .into_iter()
        .filter(|a| {
            *a != "arkavo" && *a != DEVICECHECK_AUD && platform_audience.is_none_or(|p| *a != p)
        })
        .collect();
    if filtered.len() == 1 {
        Some(filtered[0].to_string())
    } else {
        None
    }
}

/// Lowercase slug matching OpenTDF attribute-value charset.
pub fn mcp_server_slug(resource_id: &str, override_slug: Option<&str>) -> String {
    if let Some(s) = override_slug.filter(|s| !s.is_empty()) {
        return s.to_ascii_lowercase();
    }
    let stripped = resource_id
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let mut out = String::new();
    for c in stripped.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if (c == '-' || c == '_' || c == '.') && !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

pub fn tool_value_slug(tool_name: &str) -> String {
    tool_name.replace('.', "_").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc_pe() -> DecodedClaims {
        DecodedClaims {
            iss: "https://identity.arkavo.net".into(),
            sub: "arkavo:550e8400-e29b-41d4-a716-446655440000".into(),
            aud: Aud::Many(vec![
                "https://mcp.arkavo.net".into(),
                "https://platform.arkavo.net".into(),
            ]),
            exp: 1_780_000_000,
            iat: 1_779_996_400,
            cti: vec![0u8; 16],
            email: Some("a@example.com".into()),
            email_verified: Some(true),
            idp: Some("arkavo".into()),
            arkavo_account_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            arkavo_roles: Some(vec!["member".into()]),
            arkavo_entitlements: None,
            client_id: None,
            arkavo_patreon: None,
        }
    }

    #[test]
    fn bind_strips_only_arkavo_prefix() {
        assert_eq!(
            subject_id_bind("arkavo:550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            subject_id_bind("550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(subject_id_bind("apple:abc"), "apple:abc");
        assert_eq!(
            subject_id_bind("client:catalog-node"),
            "client:catalog-node"
        );
        assert!(devices_bind(
            "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(devices_bind(
            "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "arkavo:550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!devices_bind("apple:abc", "abc"));
        assert!(!devices_bind("client:x", "x"));
    }

    #[test]
    fn token_map_text_names_omits_cnf() {
        let v = token_map(&oidc_pe());
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("iss"));
        assert!(obj.contains_key("sub"));
        assert!(obj.contains_key("aud"));
        assert!(obj.contains_key("exp"));
        assert!(obj.contains_key("iat"));
        assert!(obj.contains_key("cti"));
        assert_eq!(obj.get("cnf"), None);
        assert!(!obj.keys().any(|k| k.chars().all(|c| c.is_ascii_digit())));
        assert_eq!(obj["cti"], json!(URL_SAFE_NO_PAD.encode([0u8; 16])));
        assert_eq!(
            obj["sub"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(obj["aud"].as_array().unwrap().len() == 2);
        let mut one = oidc_pe();
        one.aud = Aud::One("arkavo".into());
        assert_eq!(token_map(&one)["aud"], json!("arkavo"));
    }

    #[test]
    fn consumer_patreon_omits_campaign_id() {
        let mut c = oidc_pe();
        c.arkavo_patreon = Some(json!({
            "role": "consumer",
            "patreon_user_id": "12345678",
            "campaign_id": "87654321",
            "memberships": [],
            "verified_at": 1779996400,
            "cache_expires_at": 1780000000
        }));
        let p = token_map(&c)["arkavo_patreon"].clone();
        assert_eq!(p["role"], json!("consumer"));
        assert!(p.get("campaign_id").is_none());
        let mut creator = oidc_pe();
        creator.arkavo_patreon = Some(json!({
            "role": "creator",
            "patreon_user_id": "99990001",
            "campaign_id": "87654321",
            "memberships": [],
            "verified_at": 1779996400,
            "cache_expires_at": 1780000000
        }));
        assert_eq!(
            token_map(&creator)["arkavo_patreon"]["campaign_id"],
            json!("87654321")
        );
    }

    #[test]
    fn subject_keeps_minted_sub() {
        let s = subject(&oidc_pe());
        assert_eq!(s["type"], json!("identity"));
        assert_eq!(
            s["id"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(s["properties"]["iss"], json!("https://identity.arkavo.net"));
    }

    #[test]
    fn device_allowlist_drops_unknown_and_requires_fields() {
        let raw = json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA",
            "email": "nope@example.com",
            "patreon_user_id": "x"
        });
        let d = allowlist_device(&raw).unwrap();
        let v = device_to_value(&d);
        assert_eq!(v["sub"], raw["sub"]);
        assert!(v.get("email").is_none());
        assert!(v.get("patreon_user_id").is_none());
        assert_eq!(
            allowlist_device(&json!({"sub":"a","iss":"i","aud":"arkavo:devicecheck"})),
            Err(DeviceError::MissingField("kid"))
        );
    }

    #[test]
    fn devices_from_context_zero_one_many() {
        assert!(devices_from_context(&json!({})).unwrap().is_empty());
        let one = json!({
            "device": {
                "sub": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://identity.arkavo.net",
                "aud": "arkavo:devicecheck",
                "kid": "cGhvbmUta2lk"
            }
        });
        assert_eq!(devices_from_context(&one).unwrap().len(), 1);
        let two = json!({
            "devices": [
                {
                    "sub": "550e8400-e29b-41d4-a716-446655440000",
                    "iss": "https://identity.arkavo.net",
                    "aud": "arkavo:devicecheck",
                    "kid": "cGhvbmUta2lk"
                },
                {
                    "sub": "550e8400-e29b-41d4-a716-446655440000",
                    "iss": "https://identity.arkavo.net",
                    "aud": "arkavo:devicecheck",
                    "kid": "d2F0Y2gta2lk"
                }
            ]
        });
        let ds = devices_from_context(&two).unwrap();
        assert_eq!(ds[0].kid, "cGhvbmUta2lk");
        assert_eq!(ds[1].kid, "d2F0Y2gta2lk");
        let both = json!({"device": two["devices"][0], "devices": two["devices"]});
        assert_eq!(
            devices_from_context(&both),
            Err(DeviceError::BothDeviceAndDevices)
        );
        assert_eq!(
            devices_from_context(&json!({"devices": []})),
            Err(DeviceError::EmptyDevices)
        );
    }

    #[test]
    fn environment_allowlist_drops_ers_keys() {
        let env = allowlist_environment(&json!({
            "region": "us-east-1",
            "kind": "environment",
            "sub": "injected",
            "email": "x@y.z",
            "arkavo_patreon": {},
            "patreon_access_token": "t",
            "patreon_user_id": "1",
            "preferred_username": "u"
        }));
        let obj = env.as_object().unwrap();
        assert_eq!(obj["region"], json!("us-east-1"));
        assert_eq!(obj["kind"], json!("environment"));
        assert_eq!(obj.len(), 2);
    }

    #[test]
    fn agent_fallbacks() {
        let mut c = oidc_pe();
        c.client_id = Some("agent-app".into());
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("agent-app")
        );
        c.client_id = None;
        c.sub = "client:catalog-node".into();
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("catalog-node")
        );
        c.sub = "arkavo:550e8400-e29b-41d4-a716-446655440000".into();
        // multi-aud minus platform leaves mcp
        assert_eq!(
            context_agent(&c, Some("https://platform.arkavo.net")).as_deref(),
            Some("https://mcp.arkavo.net")
        );
        c.aud = Aud::Many(vec![
            "https://mcp.arkavo.net".into(),
            "https://other.example".into(),
            "https://platform.arkavo.net".into(),
        ]);
        assert_eq!(context_agent(&c, Some("https://platform.arkavo.net")), None);
    }

    #[test]
    fn slugs() {
        assert_eq!(
            mcp_server_slug("https://mcp.arkavo.net", None),
            "mcp_arkavo_net"
        );
        assert_eq!(
            mcp_server_slug("https://mcp.arkavo.net", Some("custom_slug")),
            "custom_slug"
        );
        assert_eq!(tool_value_slug("git.commit"), "git_commit");
        assert_eq!(tool_value_slug("filesystem_read"), "filesystem_read");
    }
}
