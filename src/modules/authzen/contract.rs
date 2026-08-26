//! HTTP contract tests (PR 3b) against a mock OpenTDF Authorization v2.

use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_verify::test_support::{keypair, mint, mint_map};
use crate::modules::authzen::facade::{self, FacadeState};
use crate::modules::platform_proxy::{self, PlatformProxyState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use ciborium::value::Value as Cbor;
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KID: &[u8] = b"kid-1";
const ISS: &str = "https://identity.arkavo.net";
const RID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

fn mint_service(sk: &SigningKey, client_id: &str, multi_aud: bool) -> String {
    let now = chrono::Utc::now().timestamp();
    let aud = if multi_aud {
        Cbor::Array(vec![
            Cbor::Text(client_id.into()),
            Cbor::Text("https://platform.arkavo.net".into()),
        ])
    } else {
        Cbor::Text(client_id.into())
    };
    mint_map(
        sk,
        KID,
        vec![
            (Cbor::Integer(1.into()), Cbor::Text(ISS.into())),
            (
                Cbor::Integer(2.into()),
                Cbor::Text(format!("client:{client_id}")),
            ),
            (Cbor::Integer(3.into()), aud),
            (Cbor::Integer(4.into()), Cbor::Integer((now + 3600).into())),
            (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
            (Cbor::Integer(7.into()), Cbor::Bytes(vec![9u8; 16])),
            (
                Cbor::Text("arkavo_roles".into()),
                Cbor::Array(vec![Cbor::Text("service-account".into())]),
            ),
        ],
    )
}

fn mint_user(sk: &SigningKey) -> String {
    let now = chrono::Utc::now().timestamp();
    mint(
        sk,
        KID,
        ISS,
        "arkavo:550e8400-e29b-41d4-a716-446655440000",
        "arkavo",
        now,
        now + 3600,
        &[1u8; 16],
    )
}

fn state(upstream: &str, allowlist: Option<HashSet<String>>) -> (Arc<FacadeState>, SigningKey) {
    state_with_upstream(upstream, allowlist, None)
}

fn state_with_upstream(
    upstream: &str,
    allowlist: Option<HashSet<String>>,
    upstream_bearer: Option<String>,
) -> (Arc<FacadeState>, SigningKey) {
    let (sk, vk) = keypair();
    let keys = CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]);
    let state = FacadeState::new(
        upstream,
        ISS.to_string(),
        keys,
        allowlist,
        Some("https://kas.arkavo.net".into()),
        upstream_bearer,
    )
    .unwrap();
    (state, sk)
}

fn assert_bearer(req: &wiremock::Request, token: &str) {
    assert_eq!(
        req.headers.get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {token}")
    );
}

async fn call(
    app: Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
    rid: Option<&str>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(r) = rid {
        b = b.header("x-request-id", r);
    }
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    let bytes = body.map(|v| v.to_string()).unwrap_or_default();
    let req = b.body(Body::from(bytes)).unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let raw = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    (status, json, headers)
}

fn catalog_req() -> Value {
    serde_json::from_str(include_str!("fixtures/catalog_evaluations_request.json")).unwrap()
}

fn mcp_req() -> Value {
    serde_json::from_str(include_str!("fixtures/mcp_evaluation_request.json")).unwrap()
}

#[tokio::test]
async fn catalog_evaluations_roundtrip_multiresource() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/catalog_multiresource_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "catalog-node", true);
    let app = facade::router(st);
    let (status, body, headers) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&catalog_req()),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-request-id").unwrap(), RID);
    assert_eq!(body["evaluations"][0]["decision"], json!(true));
    assert_eq!(body["evaluations"][1]["decision"], json!(false));
    assert_eq!(
        body["evaluations"][0]["context"]["evaluation_id"],
        json!(format!("{RID}:0"))
    );
    assert_eq!(
        body["evaluations"][1]["context"]["evaluation_id"],
        json!(format!("{RID}:1"))
    );
    assert_eq!(
        body["evaluations"][0]["context"]["obligations"]["required"],
        json!([])
    );

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers.get("connect-protocol-version").unwrap(),
        "1"
    );
    assert_bearer(&received[0], &token);
    let got: Value = serde_json::from_slice(&received[0].body).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/catalog_multiresource_request.json")).unwrap();
    assert_eq!(got, expected);
    assert!(got["entityIdentifier"].get("token").is_none());
}

#[tokio::test]
async fn two_device_chain_pe_then_npes_then_env() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/catalog_multiresource_response.json"),
            "application/json",
        ))
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "catalog-node", false);
    let mut req = catalog_req();
    req["context"] =
        serde_json::from_str(include_str!("fixtures/two_devices_context.json")).unwrap();
    req["context"]["pep"] = json!({ "fulfillable_obligation_fqns": [] });
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&req),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let got: Value =
        serde_json::from_slice(&upstream.received_requests().await.unwrap()[0].body).unwrap();
    let ents = got["entityIdentifier"]["entityChain"]["entities"]
        .as_array()
        .unwrap();
    assert_eq!(ents.len(), 4);
    assert_eq!(ents[0]["category"], json!("CATEGORY_SUBJECT"));
    assert_eq!(
        ents[0]["claims"]["value"]["sub"],
        json!("arkavo:550e8400-e29b-41d4-a716-446655440000")
    );
    assert_eq!(ents[1]["claims"]["value"]["kid"], json!("cGhvbmUta2lk"));
    assert_eq!(ents[2]["claims"]["value"]["kid"], json!("d2F0Y2gta2lk"));
    assert_eq!(ents[3]["claims"]["value"]["region"], json!("us-east-1"));
}

#[tokio::test]
async fn mismatched_prefix_bind_is_permit_path() {
    // catalog fixture already uses PE arkavo:{uuid} + device bare UUID.
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/catalog_multiresource_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "catalog-node", true);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&catalog_req()),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["evaluations"][0]["decision"], json!(true));
}

#[tokio::test]
async fn mcp_evaluation_nested_get_decision() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/mcp_getdecision_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "mcp-edge", true);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], json!(true));
    assert_eq!(body["context"]["evaluation_id"], json!(RID));
    assert_eq!(body["context"]["obligations"]["required"], json!([]));
    let received = upstream.received_requests().await.unwrap();
    assert_bearer(&received[0], &token);
    let got: Value = serde_json::from_slice(&received[0].body).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/mcp_getdecision_request.json")).unwrap();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn nested_footgun_top_level_string_is_deny() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"decision":"DECISION_PERMIT"}"#, "application/json"),
        )
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], json!(false));
}

#[tokio::test]
async fn authn_401_vs_200_deny() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"decision":{"ephemeralResourceId":"git_commit","decision":"DECISION_DENY","requiredObligations":[]}}"#,
            "application/json",
        ))
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let app = facade::router(st.clone());
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        None,
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let user = mint_user(&sk);
    let app = facade::router(st.clone());
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&user),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], json!(false));
}

#[tokio::test]
async fn empty_evaluations_without_resource_is_400() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "catalog-node", false);
    let app = facade::router(st);
    let body = json!({
        "subject": { "type": "identity", "id": "arkavo:u1" },
        "action": { "name": "read" },
        "evaluations": []
    });
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&body),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn chain_over_cap_is_400() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "catalog-node", false);
    let mut devices = Vec::new();
    for i in 0..7 {
        devices.push(json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "iss": ISS,
            "aud": "arkavo:devicecheck",
            "kid": format!("k{i}")
        }));
    }
    let mut req = catalog_req();
    req["context"]["devices"] = json!(devices);
    req["context"].as_object_mut().unwrap().remove("device");
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&req),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_device_field_is_400() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "catalog-node", false);
    let mut req = catalog_req();
    req["context"]["device"]
        .as_object_mut()
        .unwrap()
        .remove("kid");
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&req),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_aud_and_unbound_sub_are_deny_closed() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "catalog-node", false);

    let mut bad_aud = catalog_req();
    bad_aud["context"]["device"]["aud"] = json!("arkavo");
    let app = facade::router(st.clone());
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&bad_aud),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["evaluations"][0]["decision"], json!(false));
    assert!(body["evaluations"][0]["context"].get("error").is_some());

    let mut unbound = catalog_req();
    unbound["context"]["device"]["sub"] = json!("00000000-0000-0000-0000-000000000000");
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&unbound),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["evaluations"][0]["decision"], json!(false));
    assert!(body["evaluations"][1]["context"].get("error").is_some());
}

#[tokio::test]
async fn pep_fqns_on_tool_and_mcp_server_are_400() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "mcp-edge", false);
    let mut tool = mcp_req();
    tool["resource"]["properties"] = json!({"attribute_value_fqns": ["https://x/attr/a/value/b"]});
    let app = facade::router(st.clone());
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&tool),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mcp = json!({
        "subject": mcp_req()["subject"],
        "action": { "name": "tools/list" },
        "resource": {
            "type": "mcp_server",
            "id": "mcp_arkavo_net",
            "properties": { "attribute_value_fqns": ["https://x/attr/a/value/b"] }
        }
    });
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn charset_illegal_action_is_400() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "mcp-edge", false);
    let mut req = mcp_req();
    req["action"]["name"] = json!("foo.bar");
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&req),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn obligations_mapped_on_evaluation_and_evaluations() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/obligations_getdecision_response.json"),
            "application/json",
        ))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"resourceDecisions":[
                {"ephemeralResourceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","decision":"DECISION_PERMIT","requiredObligations":["https://arkavo.net/obl/watermark"]},
                {"ephemeralResourceId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decision":"DECISION_DENY","requiredObligations":[]}
            ]}"#,
            "application/json",
        ))
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st.clone());
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["context"]["obligations"]["required"],
        json!(["https://arkavo.net/obl/watermark"])
    );
    assert_eq!(body["context"]["evaluation_id"], json!(RID));

    let token = mint_service(&sk, "catalog-node", false);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&catalog_req()),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["evaluations"][0]["context"]["obligations"]["required"],
        json!(["https://arkavo.net/obl/watermark"])
    );
    assert_eq!(
        body["evaluations"][1]["context"]["obligations"]["required"],
        json!([])
    );
    assert!(body.get("context").is_none() || body["context"].get("obligations").is_none());
}

#[tokio::test]
async fn allowlist_403_when_client_not_listed() {
    let (st, sk) = state(
        "http://127.0.0.1:1",
        Some(HashSet::from(["catalog-node".to_string()])),
    );
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn facade_off_routes_are_404() {
    let app = Router::new();
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        None,
        Some(&json!({})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let app = Router::new();
    let (status, _, _) = call(
        app,
        "GET",
        "/.well-known/authzen-configuration",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn discovery_omits_search() {
    let (st, _) = state("http://127.0.0.1:1", None);
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "GET",
        "/.well-known/authzen-configuration",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["policy_decision_point"],
        json!("https://kas.arkavo.net")
    );
    assert!(body.get("search_resource_endpoint").is_none());
    assert!(body.get("signed_metadata").is_none());
}

#[tokio::test]
async fn authz_proxy_still_independently_mountable() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"resourceDecisions":[]}"#, "application/json"),
        )
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/mcp_getdecision_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;

    let proxy_state = PlatformProxyState::new(&upstream.uri()).unwrap();
    let authz_router = Router::new()
        .route(
            "/authorization.v2.AuthorizationService/*method",
            post(platform_proxy::proxy),
        )
        .with_state(proxy_state);
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "mcp-edge", false);
    let app = Router::new().merge(authz_router).merge(facade::router(st));

    let (status, _, _) = call(
        app.clone(),
        "POST",
        "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        None,
        Some(&json!({"entityIdentifier":{}})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], json!(true));
}

#[tokio::test]
async fn upstream_failure_is_500_not_502() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn mixed_actions_use_get_decision_bulk() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionBulk",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/bulk_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&upstream)
        .await;
    let (st, sk) = state(&upstream.uri(), None);
    let token = mint_service(&sk, "catalog-node", false);
    let req: Value =
        serde_json::from_str(include_str!("fixtures/bulk_evaluations_request.json")).unwrap();
    let app = facade::router(st);
    let (status, body, _) = call(
        app,
        "POST",
        "/access/v1/evaluations",
        Some(&token),
        Some(&req),
        Some(RID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["evaluations"][0]["decision"], json!(true));
    assert_eq!(body["evaluations"][1]["decision"], json!(false));
    assert_eq!(
        body["evaluations"][0]["context"]["evaluation_id"],
        json!(format!("{RID}:0"))
    );
    assert_eq!(
        body["evaluations"][1]["context"]["evaluation_id"],
        json!(format!("{RID}:1"))
    );

    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert!(received[0]
        .url
        .path()
        .ends_with("/authorization.v2.AuthorizationService/GetDecisionBulk"));
    assert_bearer(&received[0], &token);
    let got: Value = serde_json::from_slice(&received[0].body).unwrap();
    let expected: Value = serde_json::from_str(include_str!("fixtures/bulk_request.json")).unwrap();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn static_upstream_bearer_replaces_service_cwt() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorization.v2.AuthorizationService/GetDecision"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            include_str!("fixtures/mcp_getdecision_response.json"),
            "application/json",
        ))
        .expect(1)
        .mount(&upstream)
        .await;
    let (st, sk) = state_with_upstream(&upstream.uri(), None, Some("static-lab-token".into()));
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let received = upstream.received_requests().await.unwrap();
    assert_bearer(&received[0], "static-lab-token");
    assert_ne!(
        received[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {token}")
    );
}

#[tokio::test]
async fn invalid_json_is_400_not_422() {
    let (st, sk) = state("http://127.0.0.1:1", None);
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let req = Request::builder()
        .method("POST")
        .uri("/access/v1/evaluation")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from("not-json"))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_set_fetch_failure_is_500() {
    let (sk, _) = keypair();
    let keys = CoseKeyCache::new("http://127.0.0.1:1/.well-known/cose-keys".into());
    let st = FacadeState::new(
        "http://127.0.0.1:1",
        ISS.to_string(),
        keys,
        None,
        Some("https://kas.arkavo.net".into()),
        None,
    )
    .unwrap();
    let token = mint_service(&sk, "mcp-edge", false);
    let app = facade::router(st);
    let (status, _, _) = call(
        app,
        "POST",
        "/access/v1/evaluation",
        Some(&token),
        Some(&mcp_req()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
