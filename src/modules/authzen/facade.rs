//! AuthZEN HTTPS JSON facade: PEP service-CWT authn + OpenTDF v2 client.

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_subject::{Aud, DecodedClaims};
use crate::modules::authzen::cwt_verify::{header_kid, verify_header_token, VerifyOpts};
use crate::modules::authzen::discovery;
use crate::modules::authzen::translate::{
    authzen_decision, bulk_request, deny_closed, fulfillable_from_context, get_decision_request,
    map_action, map_resource, multi_resource_request, parse_bulk_responses,
    parse_get_decision_response, parse_resource_decisions, reconstruct_chain, ChainMap,
    ResourceMap, TranslateError, MAX_EVALUATIONS,
};
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

const UPSTREAM_TIMEOUT_SECS: u64 = 10;

pub struct FacadeState {
    pub platform_url: String,
    pub issuer: String,
    pub pep_client_ids: Option<HashSet<String>>,
    pub public_url: Option<String>,
    pub keys: CoseKeyCache,
    pub http: reqwest::Client,
    /// When set, sent as OpenTDF `Authorization` instead of the PEP service CWT.
    pub upstream_bearer: Option<String>,
}

pub fn enabled_from_env() -> Result<bool, String> {
    match std::env::var("AUTHZEN_FACADE") {
        Err(_) => Ok(false),
        Ok(s) => match s.to_ascii_lowercase().as_str() {
            "off" | "" => Ok(false),
            "on" => Ok(true),
            other => Err(format!("AUTHZEN_FACADE must be off or on, got {other}")),
        },
    }
}

impl FacadeState {
    pub fn from_env(platform_url: &str) -> Result<Arc<Self>, String> {
        let issuer = std::env::var("OIDC_ISSUER")
            .unwrap_or_else(|_| "https://identity.arkavo.net".to_string());
        let keys_url = std::env::var("AUTHZEN_COSE_KEYS_URL")
            .unwrap_or_else(|_| format!("{}/.well-known/cose-keys", issuer.trim_end_matches('/')));
        let pep_client_ids = std::env::var("AUTHZEN_PEP_CLIENT_IDS").ok().and_then(|s| {
            let set: HashSet<String> = s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        });
        let public_url = std::env::var("AUTHZEN_PUBLIC_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let upstream_bearer = std::env::var("AUTHZEN_UPSTREAM_BEARER")
            .ok()
            .filter(|s| !s.is_empty());
        Self::new(
            platform_url,
            issuer,
            CoseKeyCache::new(keys_url),
            pep_client_ids,
            public_url,
            upstream_bearer,
        )
    }

    pub fn new(
        platform_url: &str,
        issuer: String,
        keys: CoseKeyCache,
        pep_client_ids: Option<HashSet<String>>,
        public_url: Option<String>,
        upstream_bearer: Option<String>,
    ) -> Result<Arc<Self>, String> {
        let parsed =
            Url::parse(platform_url).map_err(|e| format!("invalid OPENTDF_PLATFORM_URL: {e}"))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(format!(
                "invalid OPENTDF_PLATFORM_URL scheme: {}",
                parsed.scheme()
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(UPSTREAM_TIMEOUT_SECS))
            .redirect(Policy::none())
            .build()
            .map_err(|e| format!("authzen http client: {e}"))?;
        Ok(Arc::new(Self {
            platform_url: platform_url.trim_end_matches('/').to_string(),
            issuer,
            pep_client_ids,
            public_url,
            keys,
            http,
            upstream_bearer,
        }))
    }
}

pub fn router(state: Arc<FacadeState>) -> Router {
    Router::new()
        .route("/access/v1/evaluation", post(evaluation))
        .route("/access/v1/evaluations", post(evaluations))
        .route("/.well-known/authzen-configuration", get(well_known))
        .with_state(state)
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && HeaderValue::from_str(s).is_ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn public_base(state: &FacadeState, headers: &HeaderMap) -> String {
    if let Some(u) = &state.public_url {
        return u.trim_end_matches('/').to_string();
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    format!("{proto}://{host}")
}

fn with_rid(mut res: Response, rid: &str) -> Response {
    if let Ok(v) = HeaderValue::from_str(rid) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}

fn err_json(status: StatusCode, message: &str, rid: &str) -> Response {
    with_rid(
        (status, Json(json!({ "error": message }))).into_response(),
        rid,
    )
}

enum PepAuth {
    Unauthorized,
    Forbidden,
}

async fn authenticate_pep(
    state: &FacadeState,
    headers: &HeaderMap,
) -> Result<(DecodedClaims, String), PepAuth> {
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(PepAuth::Unauthorized)?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(PepAuth::Unauthorized)?;
    let kid = header_kid(token).map_err(|_| PepAuth::Unauthorized)?;
    let key = state
        .keys
        .resolve(&kid)
        .await
        .map_err(|_| PepAuth::Unauthorized)?;
    let now = chrono::Utc::now().timestamp();
    let claims = verify_header_token(
        token,
        &key,
        VerifyOpts {
            expected_iss: Some(&state.issuer),
            expected_aud: None,
            expected_kid: Some(kid.as_slice()),
            now,
        },
    )
    .map_err(|_| PepAuth::Unauthorized)?;
    let Some(client_id) = claims.sub.strip_prefix("client:").filter(|s| !s.is_empty()) else {
        return Err(PepAuth::Unauthorized);
    };
    let has_role = claims
        .arkavo_roles
        .as_ref()
        .is_some_and(|r| r.iter().any(|x| x == "service-account"));
    if !has_role {
        return Err(PepAuth::Unauthorized);
    }
    let aud_ok = match &claims.aud {
        Aud::One(s) => s == client_id,
        Aud::Many(v) => v.iter().any(|s| s == client_id),
    };
    if !aud_ok {
        return Err(PepAuth::Unauthorized);
    }
    if let Some(allow) = &state.pep_client_ids {
        if !allow.contains(client_id) {
            return Err(PepAuth::Forbidden);
        }
    }
    Ok((claims, token.to_string()))
}

fn pep_fail(e: PepAuth, rid: &str) -> Response {
    match e {
        PepAuth::Unauthorized => err_json(StatusCode::UNAUTHORIZED, "invalid pep credential", rid),
        PepAuth::Forbidden => err_json(StatusCode::FORBIDDEN, "pep client not allowlisted", rid),
    }
}

fn translate_err(e: TranslateError, rid: &str) -> Response {
    err_json(StatusCode::BAD_REQUEST, e.message(), rid)
}

fn field<'a>(entry: &'a Value, top: &'a Value, key: &str) -> Option<&'a Value> {
    entry
        .get(key)
        .filter(|v| !v.is_null())
        .or_else(|| top.get(key).filter(|v| !v.is_null()))
}

fn check_tools_list(action_name: &str, resource: &Value) -> Result<(), TranslateError> {
    if action_name.eq_ignore_ascii_case("tools/list")
        && resource.get("type").and_then(Value::as_str) != Some("mcp_server")
    {
        return Err(TranslateError::Malformed(
            "tools/list requires resource.type mcp_server",
        ));
    }
    Ok(())
}

struct Prepared {
    index: usize,
    action: String,
    chain: Value,
    resource: ResourceMap,
    chain_deny: Option<&'static str>,
    fulfillable: Vec<String>,
    subject_id: String,
    resource_type: String,
}

fn prepare_one(
    index: usize,
    subject: &Value,
    action_obj: &Value,
    resource: &Value,
    context: Option<&Value>,
) -> Result<Prepared, TranslateError> {
    let action_name = action_obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or(TranslateError::Malformed("action.name"))?;
    check_tools_list(action_name, resource)?;
    let action = map_action(action_name)?;
    let resource_map = map_resource(resource)?;
    let (chain, chain_deny) = match reconstruct_chain(subject, context)? {
        ChainMap::Ok(c) => (c, None),
        ChainMap::DenyClosed(msg) => (json!({}), Some(msg)),
    };
    Ok(Prepared {
        index,
        action,
        chain,
        resource: resource_map,
        chain_deny,
        fulfillable: fulfillable_from_context(context),
        subject_id: subject
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        resource_type: resource
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

struct Group {
    chain: Value,
    action: String,
    fulfillable: Vec<String>,
    items: Vec<(usize, String, Vec<String>)>,
}

fn groups_of(prepared: &[Prepared]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for p in prepared {
        if p.chain_deny.is_some() {
            continue;
        }
        let ResourceMap::Fqns { ephemeral_id, fqns } = &p.resource else {
            continue;
        };
        if let Some(g) = groups
            .iter_mut()
            .find(|g| g.action == p.action && g.chain == p.chain && g.fulfillable == p.fulfillable)
        {
            g.items.push((p.index, ephemeral_id.clone(), fqns.clone()));
        } else {
            groups.push(Group {
                chain: p.chain.clone(),
                action: p.action.clone(),
                fulfillable: p.fulfillable.clone(),
                items: vec![(p.index, ephemeral_id.clone(), fqns.clone())],
            });
        }
    }
    groups
}

fn apply_decisions(
    results: &mut [Option<Value>],
    items: &[(usize, String, Vec<String>)],
    parsed: &[crate::modules::authzen::translate::DecisionOut],
    rid: &str,
) {
    let mut by_id: HashMap<String, VecDeque<&crate::modules::authzen::translate::DecisionOut>> =
        HashMap::new();
    for d in parsed {
        by_id
            .entry(d.ephemeral_id.clone())
            .or_default()
            .push_back(d);
    }
    for (index, eid, _) in items {
        let d = by_id.get_mut(eid).and_then(|q| q.pop_front());
        let (permit, obls) = match d {
            Some(d) => (d.permit, d.required_obligations.clone()),
            None => (false, Vec::new()),
        };
        results[*index] = Some(authzen_decision(permit, rid, Some(*index), &obls, None));
    }
}

async fn post_connect(
    state: &FacadeState,
    method: &str,
    body: &Value,
    bearer: &str,
    rid: &str,
) -> Result<Value, StatusCode> {
    let url = format!(
        "{}/authorization.v2.AuthorizationService/{method}",
        state.platform_url
    );
    let mut req = state
        .http
        .post(&url)
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .header("x-request-id", rid)
        .json(body);
    if !bearer.is_empty() {
        req = req.bearer_auth(bearer);
    }
    let resp = req.send().await.map_err(|e| {
        log::warn!("authzen upstream {method}: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if !resp.status().is_success() {
        log::warn!("authzen upstream {method}: HTTP {}", resp.status());
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    resp.json().await.map_err(|e| {
        log::warn!("authzen upstream {method} json: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

fn semantic_of(body: &Value) -> &str {
    body.get("options")
        .and_then(|o| o.get("evaluations_semantic"))
        .and_then(Value::as_str)
        .unwrap_or("execute_all")
}

fn fill_remaining_deny(results: &mut [Option<Value>], rid: &str, message: &str) {
    for (i, slot) in results.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(deny_closed(rid, Some(i), message));
        }
    }
}

async fn well_known(State(state): State<Arc<FacadeState>>, headers: HeaderMap) -> Json<Value> {
    Json(discovery::document(&public_base(&state, &headers)))
}

async fn evaluation(
    State(state): State<Arc<FacadeState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let rid = request_id(&headers);
    let (pep, pep_token) = match authenticate_pep(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return pep_fail(e, &rid),
    };
    let subject = match body.get("subject") {
        Some(s) => s,
        None => return translate_err(TranslateError::Malformed("subject"), &rid),
    };
    let action = match body.get("action") {
        Some(s) => s,
        None => return translate_err(TranslateError::Malformed("action"), &rid),
    };
    let resource = match body.get("resource") {
        Some(s) => s,
        None => return translate_err(TranslateError::Malformed("resource"), &rid),
    };
    let prepared = match prepare_one(0, subject, action, resource, body.get("context")) {
        Ok(p) => p,
        Err(e) => return translate_err(e, &rid),
    };
    if let Some(msg) = prepared.chain_deny {
        log_eval(&pep.sub, &prepared, false, &rid);
        return with_rid(
            (StatusCode::OK, Json(deny_closed(&rid, None, msg))).into_response(),
            &rid,
        );
    }
    if let ResourceMap::DenyClosed { message, .. } = &prepared.resource {
        log_eval(&pep.sub, &prepared, false, &rid);
        return with_rid(
            (StatusCode::OK, Json(deny_closed(&rid, None, message))).into_response(),
            &rid,
        );
    }
    let ResourceMap::Fqns { ephemeral_id, fqns } = &prepared.resource else {
        unreachable!();
    };
    let req_body = get_decision_request(
        &prepared.chain,
        &prepared.action,
        ephemeral_id,
        fqns,
        &prepared.fulfillable,
    );
    let bearer = state
        .upstream_bearer
        .as_deref()
        .unwrap_or(pep_token.as_str());
    let upstream = match post_connect(&state, "GetDecision", &req_body, bearer, &rid).await {
        Ok(v) => v,
        Err(s) => return err_json(s, "upstream", &rid),
    };
    let out = parse_get_decision_response(&upstream);
    log_eval(&pep.sub, &prepared, out.permit, &rid);
    with_rid(
        (
            StatusCode::OK,
            Json(authzen_decision(
                out.permit,
                &rid,
                None,
                &out.required_obligations,
                None,
            )),
        )
            .into_response(),
        &rid,
    )
}

async fn evaluations(
    State(state): State<Arc<FacadeState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let rid = request_id(&headers);
    let (pep, pep_token) = match authenticate_pep(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return pep_fail(e, &rid),
    };
    let entries = match body.get("evaluations").and_then(Value::as_array) {
        Some(arr) if !arr.is_empty() => arr.clone(),
        _ => {
            if body.get("resource").is_some() {
                vec![json!({})]
            } else {
                return translate_err(
                    TranslateError::Malformed("empty evaluations without resource"),
                    &rid,
                );
            }
        }
    };
    if entries.len() > MAX_EVALUATIONS {
        return err_json(
            StatusCode::BAD_REQUEST,
            "evaluations.length exceeds 500",
            &rid,
        );
    }
    let mut prepared = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let subject = match field(entry, &body, "subject") {
            Some(s) => s,
            None => return translate_err(TranslateError::Malformed("subject"), &rid),
        };
        let action = match field(entry, &body, "action") {
            Some(s) => s,
            None => return translate_err(TranslateError::Malformed("action"), &rid),
        };
        let resource = match field(entry, &body, "resource") {
            Some(s) => s,
            None => return translate_err(TranslateError::Malformed("resource"), &rid),
        };
        let context = field(entry, &body, "context");
        match prepare_one(i, subject, action, resource, context) {
            Ok(p) => prepared.push(p),
            Err(e) => return translate_err(e, &rid),
        }
    }

    let mut results: Vec<Option<Value>> = vec![None; prepared.len()];
    for p in &prepared {
        if let Some(msg) = p.chain_deny {
            results[p.index] = Some(deny_closed(&rid, Some(p.index), msg));
        } else if let ResourceMap::DenyClosed { message, .. } = &p.resource {
            results[p.index] = Some(deny_closed(&rid, Some(p.index), message));
        }
    }

    let groups = groups_of(&prepared);
    let semantic = semantic_of(&body);
    let bearer = state
        .upstream_bearer
        .as_deref()
        .unwrap_or(pep_token.as_str());

    if !groups.is_empty() {
        let run = async {
            if groups.len() == 1 {
                let g = &groups[0];
                let resources: Vec<(String, Vec<String>)> = g
                    .items
                    .iter()
                    .map(|(_, id, fqns)| (id.clone(), fqns.clone()))
                    .collect();
                let req_body =
                    multi_resource_request(&g.chain, &g.action, &resources, &g.fulfillable);
                let upstream =
                    post_connect(&state, "GetDecisionMultiResource", &req_body, bearer, &rid)
                        .await?;
                apply_decisions(
                    &mut results,
                    &g.items,
                    &parse_resource_decisions(&upstream),
                    &rid,
                );
            } else {
                let reqs: Vec<Value> = groups
                    .iter()
                    .map(|g| {
                        let resources: Vec<(String, Vec<String>)> = g
                            .items
                            .iter()
                            .map(|(_, id, fqns)| (id.clone(), fqns.clone()))
                            .collect();
                        multi_resource_request(&g.chain, &g.action, &resources, &g.fulfillable)
                    })
                    .collect();
                let upstream = post_connect(
                    &state,
                    "GetDecisionBulk",
                    &bulk_request(&reqs),
                    bearer,
                    &rid,
                )
                .await?;
                let parsed_groups = parse_bulk_responses(&upstream);
                for (g, parsed) in groups.iter().zip(parsed_groups.iter()) {
                    apply_decisions(&mut results, &g.items, parsed, &rid);
                    if semantic == "deny_on_first_deny"
                        && results.iter().flatten().any(|v| v["decision"] == false)
                    {
                        fill_remaining_deny(&mut results, &rid, "deny_on_first_deny");
                        break;
                    }
                    if semantic == "permit_on_first_permit"
                        && results.iter().flatten().any(|v| v["decision"] == true)
                    {
                        fill_remaining_deny(&mut results, &rid, "permit_on_first_permit");
                        break;
                    }
                }
            }
            Ok::<(), StatusCode>(())
        };
        if let Err(s) = run.await {
            return err_json(s, "upstream", &rid);
        }
    }

    fill_remaining_deny(&mut results, &rid, "unspecified");
    let evaluations: Vec<Value> = results.into_iter().map(|v| v.unwrap()).collect();
    if let Some(first) = prepared.first() {
        log::info!(
            "authzen evaluations evaluation_id={} pep_sub={} subject_id={} batch={}",
            rid,
            pep.sub,
            first.subject_id,
            evaluations.len()
        );
    }
    with_rid(
        (StatusCode::OK, Json(json!({ "evaluations": evaluations }))).into_response(),
        &rid,
    )
}

fn log_eval(pep_sub: &str, p: &Prepared, permit: bool, rid: &str) {
    log::info!(
        "authzen evaluation evaluation_id={} pep_sub={} subject_id={} action={} resource_type={} decision={}",
        rid,
        pep_sub,
        p.subject_id,
        p.action,
        p.resource_type,
        permit
    );
}
