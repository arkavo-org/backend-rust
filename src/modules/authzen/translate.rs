//! SARC ↔ OpenTDF v2 proto-JSON (claims-mode entity chain only).

use crate::modules::authzen::cwt_subject::{
    allowlist_environment, device_to_value, devices_bind, devices_from_context, tool_value_slug,
    DeviceError, DEVICECHECK_AUD,
};
use serde_json::{json, Map, Value};

const MCP_TOOL_FQN_PREFIX: &str = "https://arkavo.net/attr/mcp-tool/value/";
const MCP_SERVER_FQN_PREFIX: &str = "https://arkavo.net/attr/mcp-server/value/";
pub const MAX_CHAIN: usize = 8;
pub const MAX_EVALUATIONS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslateError {
    Malformed(&'static str),
    ChainCap,
    IllegalAction,
    PepFqns,
    IllegalResourceId,
}

impl TranslateError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Malformed(m) => m,
            Self::ChainCap => "entity chain exceeds 8",
            Self::IllegalAction => "mapped action is not a valid OpenTDF identifier",
            Self::PepFqns => "attribute_value_fqns not allowed for this resource.type",
            Self::IllegalResourceId => "resource.id is not a valid OpenTDF identifier",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMap {
    Ok(Value),
    DenyClosed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceMap {
    Fqns {
        ephemeral_id: String,
        fqns: Vec<String>,
    },
    DenyClosed {
        ephemeral_id: String,
        message: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionOut {
    pub ephemeral_id: String,
    pub permit: bool,
    pub required_obligations: Vec<String>,
}

/// OpenTDF identifier charset after lowercasing.
pub fn opentdf_identifier_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mid = |c: u8| alnum(c) || c == b'_' || c == b'-';
    if !alnum(b[0]) {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    alnum(b[b.len() - 1]) && b[1..b.len() - 1].iter().copied().all(mid)
}

pub fn map_action(authzen_name: &str) -> Result<String, TranslateError> {
    if authzen_name.is_empty() {
        return Err(TranslateError::Malformed("action.name"));
    }
    let lower = authzen_name.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "read" => "read".to_string(),
        "tools/call" | "execute_tool" => "execute_tool".to_string(),
        "tools/list" => "tools_list".to_string(),
        "rewrap" | "decrypt" => "decrypt".to_string(),
        other => {
            if let Some(grant) = other.strip_prefix("issue:cwt:") {
                format!("issue_cwt_{}", grant.replace(['/', ':'], "_"))
            } else {
                other.replace(['/', ':'], "_")
            }
        }
    };
    if !opentdf_identifier_ok(&mapped) {
        return Err(TranslateError::IllegalAction);
    }
    Ok(mapped)
}

fn pep_fqns_present(resource: &Value) -> bool {
    resource
        .get("properties")
        .and_then(|p| p.as_object())
        .is_some_and(|o| o.contains_key("attribute_value_fqns"))
}

fn pep_fqns(resource: &Value) -> Vec<String> {
    resource
        .get("properties")
        .and_then(|p| p.get("attribute_value_fqns"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn tool_attr_value(id: &str) -> Result<String, TranslateError> {
    let slug = tool_value_slug(id);
    let value = match slug.as_str() {
        "device_tap" => "device_management_tap",
        "device_swipe" => "device_management_swipe",
        other => other,
    };
    if !opentdf_identifier_ok(value) {
        return Err(TranslateError::IllegalResourceId);
    }
    Ok(value.to_string())
}

pub fn map_resource(resource: &Value) -> Result<ResourceMap, TranslateError> {
    let rtype = resource
        .get("type")
        .and_then(Value::as_str)
        .ok_or(TranslateError::Malformed("resource.type"))?;
    let id = resource
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TranslateError::Malformed("resource.id"))?;
    match rtype {
        "tool" => {
            if pep_fqns_present(resource) {
                return Err(TranslateError::PepFqns);
            }
            let value = tool_attr_value(id)?;
            Ok(ResourceMap::Fqns {
                ephemeral_id: id.to_string(),
                fqns: vec![format!("{MCP_TOOL_FQN_PREFIX}{value}")],
            })
        }
        "mcp_server" => {
            if pep_fqns_present(resource) {
                return Err(TranslateError::PepFqns);
            }
            if !opentdf_identifier_ok(id) {
                return Err(TranslateError::IllegalResourceId);
            }
            Ok(ResourceMap::Fqns {
                ephemeral_id: id.to_string(),
                fqns: vec![format!("{MCP_SERVER_FQN_PREFIX}{id}")],
            })
        }
        "catalog_item" => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "catalog_item missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
        "tdf" | "kas" => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "resource missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
        _ => {
            let fqns = pep_fqns(resource);
            if fqns.is_empty() {
                Ok(ResourceMap::DenyClosed {
                    ephemeral_id: id.to_string(),
                    message: "resource missing attribute_value_fqns",
                })
            } else {
                Ok(ResourceMap::Fqns {
                    ephemeral_id: id.to_string(),
                    fqns,
                })
            }
        }
    }
}

fn claims_entity(ephemeral_id: &str, subject: bool, claims: Value) -> Value {
    json!({
        "ephemeralId": ephemeral_id,
        "category": if subject { "CATEGORY_SUBJECT" } else { "CATEGORY_ENVIRONMENT" },
        "claims": {
            "@type": "type.googleapis.com/google.protobuf.Struct",
            "value": claims,
        },
    })
}

fn pe_claims(subject: &Value) -> Result<Value, TranslateError> {
    let id = subject
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TranslateError::Malformed("subject.id"))?;
    let mut m = Map::new();
    m.insert("sub".into(), json!(id));
    if let Some(props) = subject.get("properties").and_then(Value::as_object) {
        if let Some(iss) = props.get("iss") {
            m.insert("iss".into(), iss.clone());
        }
        if let Some(email) = props.get("email") {
            m.insert("email".into(), email.clone());
        }
        if let Some(patreon) = props.get("arkavo_patreon") {
            m.insert("arkavo_patreon".into(), patreon.clone());
            if let Some(uid) = patreon.get("patreon_user_id") {
                m.insert("patreon_user_id".into(), uid.clone());
            }
        }
    }
    Ok(Value::Object(m))
}

pub fn reconstruct_chain(
    subject: &Value,
    context: Option<&Value>,
) -> Result<ChainMap, TranslateError> {
    let pe = pe_claims(subject)?;
    let pe_sub = pe["sub"].as_str().unwrap_or_default().to_string();
    let devices = match context {
        Some(ctx) => match devices_from_context(ctx) {
            Ok(d) => d,
            Err(DeviceError::MissingField(_)) => {
                return Err(TranslateError::Malformed("device missing required field"));
            }
            Err(DeviceError::BothDeviceAndDevices) => {
                return Err(TranslateError::Malformed(
                    "context.device and context.devices both present",
                ));
            }
            Err(DeviceError::EmptyDevices) => {
                return Err(TranslateError::Malformed("context.devices is empty"));
            }
        },
        None => vec![],
    };
    let env_present = context
        .and_then(|c| c.get("environment"))
        .is_some_and(|v| !v.is_null());
    let e_count = if env_present { 1 } else { 0 };
    if 1 + devices.len() + e_count > MAX_CHAIN {
        return Err(TranslateError::ChainCap);
    }
    for d in &devices {
        if d.aud != DEVICECHECK_AUD {
            return Ok(ChainMap::DenyClosed(
                "device aud must be arkavo:devicecheck",
            ));
        }
        if !devices_bind(&pe_sub, &d.sub) {
            return Ok(ChainMap::DenyClosed(
                "device sub does not bind to subject.id",
            ));
        }
    }

    let mut entities = Vec::with_capacity(1 + devices.len() + e_count);
    entities.push(claims_entity("e0", true, pe));
    for (i, d) in devices.iter().enumerate() {
        entities.push(claims_entity(
            &format!("e{}", i + 1),
            false,
            device_to_value(d),
        ));
    }
    if env_present {
        let env = allowlist_environment(&context.unwrap()["environment"]);
        entities.push(claims_entity(&format!("e{}", entities.len()), false, env));
    }
    Ok(ChainMap::Ok(json!({
        "ephemeralId": "chain",
        "entities": entities,
    })))
}

pub fn fulfillable_from_context(context: Option<&Value>) -> Vec<String> {
    context
        .and_then(|c| c.get("pep"))
        .and_then(|p| p.get("fulfillable_obligation_fqns"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn entity_identifier(chain: &Value) -> Value {
    json!({ "entityChain": chain })
}

pub fn resource_body(ephemeral_id: &str, fqns: &[String]) -> Value {
    json!({
        "ephemeralId": ephemeral_id,
        "attributeValues": { "fqns": fqns },
    })
}

pub fn get_decision_request(
    chain: &Value,
    action: &str,
    ephemeral_id: &str,
    fqns: &[String],
    fulfillable: &[String],
) -> Value {
    json!({
        "entityIdentifier": entity_identifier(chain),
        "action": { "name": action },
        "resource": resource_body(ephemeral_id, fqns),
        "fulfillableObligationFqns": fulfillable,
    })
}

pub fn multi_resource_request(
    chain: &Value,
    action: &str,
    resources: &[(String, Vec<String>)],
    fulfillable: &[String],
) -> Value {
    json!({
        "entityIdentifier": entity_identifier(chain),
        "action": { "name": action },
        "resources": resources.iter().map(|(id, fqns)| resource_body(id, fqns)).collect::<Vec<_>>(),
        "fulfillableObligationFqns": fulfillable,
    })
}

pub fn bulk_request(groups: &[Value]) -> Value {
    json!({ "decisionRequests": groups })
}

pub fn is_permit(decision: &str) -> bool {
    decision == "DECISION_PERMIT"
}

fn obligations_from(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Nested `GetDecisionResponse.decision.decision` (not a top-level enum string).
pub fn parse_get_decision_response(resp: &Value) -> DecisionOut {
    let nested = resp.get("decision");
    let decision = nested
        .and_then(|d| d.get("decision"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let ephemeral_id = nested
        .and_then(|d| d.get("ephemeralResourceId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    DecisionOut {
        ephemeral_id,
        permit: is_permit(decision),
        required_obligations: obligations_from(nested.and_then(|d| d.get("requiredObligations"))),
    }
}

pub fn parse_resource_decisions(resp: &Value) -> Vec<DecisionOut> {
    resp.get("resourceDecisions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|d| DecisionOut {
                    ephemeral_id: d
                        .get("ephemeralResourceId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    permit: is_permit(d.get("decision").and_then(Value::as_str).unwrap_or("")),
                    required_obligations: obligations_from(d.get("requiredObligations")),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_bulk_responses(resp: &Value) -> Vec<Vec<DecisionOut>> {
    resp.get("decisionResponses")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(parse_resource_decisions).collect())
        .unwrap_or_default()
}

pub fn evaluation_id(rid: &str, index: Option<usize>) -> String {
    match index {
        Some(i) => format!("{rid}:{i}"),
        None => rid.to_string(),
    }
}

pub fn decision_context(
    rid: &str,
    index: Option<usize>,
    obligations: &[String],
    error: Option<Value>,
) -> Value {
    let mut ctx = Map::new();
    ctx.insert("evaluation_id".into(), json!(evaluation_id(rid, index)));
    ctx.insert("obligations".into(), json!({ "required": obligations }));
    if let Some(err) = error {
        ctx.insert("error".into(), err);
    }
    Value::Object(ctx)
}

pub fn authzen_decision(
    permit: bool,
    rid: &str,
    index: Option<usize>,
    obligations: &[String],
    error: Option<Value>,
) -> Value {
    json!({
        "decision": permit,
        "context": decision_context(rid, index, obligations, error),
    })
}

pub fn deny_closed(rid: &str, index: Option<usize>, message: &str) -> Value {
    authzen_decision(false, rid, index, &[], Some(json!({ "message": message })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_subject() -> Value {
        json!({
            "type": "identity",
            "id": "arkavo:550e8400-e29b-41d4-a716-446655440000",
            "properties": {
                "iss": "https://identity.arkavo.net",
                "idp": "arkavo",
                "email": "alice@example.com",
                "email_verified": true,
                "arkavo_account_id": "arkavo:550e8400-e29b-41d4-a716-446655440000",
                "arkavo_roles": ["user"],
                "arkavo_entitlements": ["tdf:decrypt"],
                "arkavo_patreon": {
                    "role": "consumer",
                    "patreon_user_id": "12345678",
                    "memberships": [{
                        "campaign_id": "87654321",
                        "patron_status": "active_patron",
                        "tier_ids": ["111"],
                        "tier_slugs": ["supporter"]
                    }],
                    "verified_at": 1779996400,
                    "cache_expires_at": 1780000000
                }
            }
        })
    }

    fn phone() -> Value {
        json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "cGhvbmUta2lk"
        })
    }

    fn watch() -> Value {
        json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "d2F0Y2gta2lk"
        })
    }

    #[test]
    fn action_registry() {
        assert_eq!(map_action("read").unwrap(), "read");
        assert_eq!(map_action("tools/call").unwrap(), "execute_tool");
        assert_eq!(map_action("execute_tool").unwrap(), "execute_tool");
        assert_eq!(map_action("tools/list").unwrap(), "tools_list");
        assert_eq!(map_action("rewrap").unwrap(), "decrypt");
        assert_eq!(map_action("decrypt").unwrap(), "decrypt");
        assert_eq!(
            map_action("issue:cwt:authorization_code").unwrap(),
            "issue_cwt_authorization_code"
        );
        assert_eq!(map_action("READ").unwrap(), "read");
        assert_eq!(map_action("custom_ok").unwrap(), "custom_ok");
        assert_eq!(
            map_action("foo.bar").unwrap_err(),
            TranslateError::IllegalAction
        );
        assert_eq!(
            map_action("foo/bar.baz").unwrap_err(),
            TranslateError::IllegalAction
        );
        assert_eq!(
            map_action("").unwrap_err(),
            TranslateError::Malformed("action.name")
        );
    }

    #[test]
    fn tool_fqns_derived_not_pep() {
        let r = map_resource(&json!({"type":"tool","id":"git_commit"})).unwrap();
        assert_eq!(
            r,
            ResourceMap::Fqns {
                ephemeral_id: "git_commit".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-tool/value/git_commit".into()],
            }
        );
        let dotted = map_resource(&json!({"type":"tool","id":"git.commit"})).unwrap();
        match dotted {
            ResourceMap::Fqns { fqns, .. } => {
                assert_eq!(fqns[0], "https://arkavo.net/attr/mcp-tool/value/git_commit");
            }
            _ => panic!("expected fqns"),
        }
        assert_eq!(
            map_resource(&json!({"type":"tool","id":"device_tap"})).unwrap(),
            ResourceMap::Fqns {
                ephemeral_id: "device_tap".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-tool/value/device_management_tap".into()],
            }
        );
        assert_eq!(
            map_resource(&json!({
                "type":"tool","id":"git_commit",
                "properties":{"attribute_value_fqns":["https://evil/attr/x/value/y"]}
            }))
            .unwrap_err(),
            TranslateError::PepFqns
        );
    }

    #[test]
    fn mcp_server_derives_and_rejects_pep_fqns() {
        let r = map_resource(&json!({"type":"mcp_server","id":"mcp_arkavo_net"})).unwrap();
        assert_eq!(
            r,
            ResourceMap::Fqns {
                ephemeral_id: "mcp_arkavo_net".into(),
                fqns: vec!["https://arkavo.net/attr/mcp-server/value/mcp_arkavo_net".into()],
            }
        );
        assert_eq!(
            map_resource(&json!({"type":"mcp_server","id":"https://mcp.arkavo.net"})).unwrap_err(),
            TranslateError::IllegalResourceId
        );
        assert_eq!(
            map_resource(&json!({
                "type":"mcp_server","id":"mcp_arkavo_net",
                "properties":{"attribute_value_fqns":[]}
            }))
            .unwrap_err(),
            TranslateError::PepFqns
        );
    }

    #[test]
    fn catalog_item_empty_fqns_deny_closed() {
        let r = map_resource(&json!({"type":"catalog_item","id":"aa"})).unwrap();
        match r {
            ResourceMap::DenyClosed { ephemeral_id, .. } => assert_eq!(ephemeral_id, "aa"),
            _ => panic!("expected deny-closed"),
        }
        let ok = map_resource(&json!({
            "type":"catalog_item",
            "id":"aa",
            "properties":{"attribute_value_fqns":["https://patreon.arkavo.com/attr/tier/value/supporter"]}
        }))
        .unwrap();
        match ok {
            ResourceMap::Fqns { fqns, .. } => assert_eq!(fqns.len(), 1),
            _ => panic!("expected fqns"),
        }
    }

    #[test]
    fn chain_pe_then_devices_then_env_mismatched_prefix_bind() {
        let ctx = json!({
            "devices": [phone(), watch()],
            "environment": {
                "region": "us-east-1",
                "kind": "environment",
                "email": "injected@example.com",
                "patreon_access_token": "nope"
            }
        });
        let ChainMap::Ok(chain) = reconstruct_chain(&pe_subject(), Some(&ctx)).unwrap() else {
            panic!("expected chain");
        };
        let ents = chain["entities"].as_array().unwrap();
        assert_eq!(ents.len(), 4);
        assert_eq!(ents[0]["ephemeralId"], json!("e0"));
        assert_eq!(ents[0]["category"], json!("CATEGORY_SUBJECT"));
        assert_eq!(
            ents[0]["claims"]["value"]["sub"],
            json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(
            ents[0]["claims"]["value"]["email"],
            json!("alice@example.com")
        );
        assert_eq!(
            ents[0]["claims"]["value"]["patreon_user_id"],
            json!("12345678")
        );
        assert!(ents[0]["claims"]["value"].get("arkavo_roles").is_none());
        assert_eq!(ents[1]["category"], json!("CATEGORY_ENVIRONMENT"));
        assert_eq!(ents[1]["claims"]["value"]["kid"], json!("cGhvbmUta2lk"));
        assert_eq!(
            ents[1]["claims"]["value"]["sub"],
            json!("550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(ents[1]["claims"]["value"].get("email").is_none());
        assert_eq!(ents[2]["claims"]["value"]["kid"], json!("d2F0Y2gta2lk"));
        assert_eq!(ents[3]["claims"]["value"]["region"], json!("us-east-1"));
        assert_eq!(ents[3]["claims"]["value"]["kind"], json!("environment"));
        assert!(ents[3]["claims"]["value"].get("email").is_none());
        assert!(ents[3]["claims"]["value"]
            .get("patreon_access_token")
            .is_none());
        assert!(chain.get("token").is_none());
    }

    #[test]
    fn chain_wrong_aud_and_unbound_are_deny_closed() {
        let bad_aud = json!({"device": {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA"
        }});
        assert!(matches!(
            reconstruct_chain(&pe_subject(), Some(&bad_aud)).unwrap(),
            ChainMap::DenyClosed(_)
        ));
        let unbound = json!({"device": {
            "sub": "00000000-0000-0000-0000-000000000000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck",
            "kid": "YWxwaGEtZGV2aWNlLWtpZA"
        }});
        assert!(matches!(
            reconstruct_chain(&pe_subject(), Some(&unbound)).unwrap(),
            ChainMap::DenyClosed(_)
        ));
    }

    #[test]
    fn chain_missing_device_field_is_malformed() {
        let missing = json!({"device": {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "https://identity.arkavo.net",
            "aud": "arkavo:devicecheck"
        }});
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&missing)).unwrap_err(),
            TranslateError::Malformed("device missing required field")
        );
    }

    #[test]
    fn chain_cap_and_both_device_fields() {
        let mut devices = Vec::new();
        for i in 0..7 {
            devices.push(json!({
                "sub": "550e8400-e29b-41d4-a716-446655440000",
                "iss": "https://identity.arkavo.net",
                "aud": "arkavo:devicecheck",
                "kid": format!("kid{i}")
            }));
        }
        let over = json!({
            "devices": devices,
            "environment": { "region": "us-east-1" }
        });
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&over)).unwrap_err(),
            TranslateError::ChainCap
        );
        let both = json!({"device": phone(), "devices": [phone()]});
        assert_eq!(
            reconstruct_chain(&pe_subject(), Some(&both)).unwrap_err(),
            TranslateError::Malformed("context.device and context.devices both present")
        );
    }

    #[test]
    fn nested_get_decision_not_top_level_string() {
        let nested = json!({
            "decision": {
                "ephemeralResourceId": "git_commit",
                "decision": "DECISION_PERMIT",
                "requiredObligations": ["https://example/obl/x"]
            }
        });
        let out = parse_get_decision_response(&nested);
        assert!(out.permit);
        assert_eq!(out.required_obligations, vec!["https://example/obl/x"]);
        let footgun = json!({ "decision": "DECISION_PERMIT" });
        assert!(!parse_get_decision_response(&footgun).permit);
        let deny = json!({
            "decision": { "decision": "DECISION_DENY", "requiredObligations": [] }
        });
        assert!(!parse_get_decision_response(&deny).permit);
        let missing = json!({});
        assert!(!parse_get_decision_response(&missing).permit);
    }

    #[test]
    fn evaluation_id_and_obligations_shape() {
        assert_eq!(evaluation_id("rid", None), "rid");
        assert_eq!(evaluation_id("rid", Some(1)), "rid:1");
        let ctx = decision_context("rid", Some(0), &["https://o".into()], None);
        assert_eq!(ctx["evaluation_id"], json!("rid:0"));
        assert_eq!(ctx["obligations"]["required"], json!(["https://o"]));
    }

    #[test]
    fn catalog_fixture_multiresource_shape() {
        let req: Value =
            serde_json::from_str(include_str!("fixtures/catalog_evaluations_request.json"))
                .unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("fixtures/catalog_multiresource_request.json"))
                .unwrap();
        let ChainMap::Ok(chain) = reconstruct_chain(&req["subject"], req.get("context")).unwrap()
        else {
            panic!("chain");
        };
        let action = map_action(req["action"]["name"].as_str().unwrap()).unwrap();
        let mut resources = Vec::new();
        for ev in req["evaluations"].as_array().unwrap() {
            match map_resource(&ev["resource"]).unwrap() {
                ResourceMap::Fqns { ephemeral_id, fqns } => resources.push((ephemeral_id, fqns)),
                ResourceMap::DenyClosed { .. } => panic!("unexpected deny"),
            }
        }
        let fulfillable = fulfillable_from_context(req.get("context"));
        let body = multi_resource_request(&chain, &action, &resources, &fulfillable);
        assert_eq!(body, expected);
        assert!(body["entityIdentifier"].get("token").is_none());
    }

    #[test]
    fn mcp_fixture_getdecision_shape() {
        let req: Value =
            serde_json::from_str(include_str!("fixtures/mcp_evaluation_request.json")).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("fixtures/mcp_getdecision_request.json")).unwrap();
        let ChainMap::Ok(chain) = reconstruct_chain(&req["subject"], req.get("context")).unwrap()
        else {
            panic!("chain");
        };
        let action = map_action(req["action"]["name"].as_str().unwrap()).unwrap();
        let ResourceMap::Fqns { ephemeral_id, fqns } = map_resource(&req["resource"]).unwrap()
        else {
            panic!("resource");
        };
        let body = get_decision_request(
            &chain,
            &action,
            &ephemeral_id,
            &fqns,
            &fulfillable_from_context(req.get("context")),
        );
        assert_eq!(body, expected);
    }
}
