//! CWT bearer authentication middleware (spec §1 `act` rule).
//!
//! Every non-public route runs `require_cwt`. The bearer must be a CWT from
//! the trusted issuer with `aud` ∋ this service. If the caller also sends
//! `X-Actor-Token`, that token's `sub` must be listed in the bearer's `act`
//! — the forwarder authenticating itself — otherwise 401.
//!
//! Mounted by `http_rewrap::local_router` and `media_api::router`; the public
//! routes (`/.well-known/apple-app-site-association`,
//! `/kas/v2/kas_public_key`, `/media/v1/certificate`) sit on unlayered
//! routers that are merged in alongside.

use crate::modules::cwt_token::{CwtClaims, CwtValidator};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::warn;
use std::sync::Arc;

pub const ACTOR_TOKEN_HEADER: &str = "x-actor-token";

pub struct CwtAuthState {
    pub validator: Arc<CwtValidator>,
}

/// Verified identity attached to the request as an axum `Extension`.
#[derive(Clone, Debug)]
pub struct AuthenticatedSubject {
    pub sub: String,
    // Carried from the CWT for handlers that will need them (entitlement
    // checks land in a later change); no route reads them yet.
    #[allow(dead_code)]
    pub account_id: Option<String>,
    #[allow(dead_code)]
    pub roles: Vec<String>,
    /// `sub` of the authenticated forwarder, when the token was forwarded.
    pub actor: Option<String>,
}

fn unauthorized(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}

pub async fn require_cwt(
    State(state): State<Arc<CwtAuthState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let Some(auth) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return unauthorized("Missing Bearer CWT");
    };
    let claims: CwtClaims = match state.validator.validate_authorization_header(auth).await {
        Ok(c) => c,
        Err(e) => {
            warn!("CWT validation failed: {e}");
            return unauthorized("Invalid CWT");
        }
    };

    let actor = match req.headers().get(ACTOR_TOKEN_HEADER) {
        None => None,
        Some(value) => {
            // A present-but-non-UTF-8 header must 401, not be silently
            // treated as absent — that would let a malformed forwarder
            // header fall through to a direct presentation.
            let Ok(raw) = value.to_str() else {
                warn!("actor token header is not valid UTF-8");
                return unauthorized("Invalid actor token");
            };
            match state.validator.validate_bearer(raw).await {
                Err(e) => {
                    warn!("actor token invalid: {e}");
                    return unauthorized("Invalid actor token");
                }
                Ok(actor_claims) => {
                    // Spec §1: the actor's `sub` MUST appear in the
                    // bearer's `act[].sub`. Membership in `claims.actors`
                    // is the only thing that authorizes an actor — there
                    // is no same-`sub` self-escape, even when `act[]` is
                    // empty.
                    if !claims.actors.iter().any(|a| a == &actor_claims.subject) {
                        warn!(
                            "actor {} not authorized in act for subject {}",
                            actor_claims.subject, claims.subject
                        );
                        return unauthorized("Actor not authorized for this token");
                    }
                    Some(actor_claims.subject)
                }
            }
        }
    };

    req.extensions_mut().insert(AuthenticatedSubject {
        sub: claims.subject,
        account_id: claims.account_id,
        roles: claims.roles,
        actor,
    });
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::cwt_token::CwtValidator;
    use axum::{extract::Extension, middleware::from_fn_with_state, routing::get, Router};
    use tokio::net::TcpListener;

    async fn spawn(state: Arc<CwtAuthState>) -> String {
        async fn whoami(Extension(s): Extension<AuthenticatedSubject>) -> String {
            format!("{}|{}", s.sub, s.actor.unwrap_or_default())
        }
        let app = Router::new()
            .route("/private", get(whoami))
            .layer(from_fn_with_state(state.clone(), require_cwt));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn state_with_keys() -> (
        Arc<CwtAuthState>,
        crate::modules::cwt_token::test_support::Signer,
        wiremock::MockServer,
    ) {
        let (signer, set) = crate::modules::cwt_token::test_support::keypair_and_set();
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/.well-known/cose-keys"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_raw(set, "application/cbor"),
            )
            .mount(&mock)
            .await;
        let validator = CwtValidator::new(
            format!("{}/.well-known/cose-keys", mock.uri()),
            "https://identity.test".into(),
            "https://arks.test".into(),
        );
        (
            Arc::new(CwtAuthState {
                validator: Arc::new(validator),
            }),
            signer,
            mock,
        )
    }

    #[tokio::test]
    async fn missing_bearer_is_401() {
        let (state, _, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let r = reqwest::get(format!("{base}/private")).await.unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn wrong_audience_is_401() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let tok = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://elsewhere.test"),
        ]);
        let r = reqwest::Client::new()
            .get(format!("{base}/private"))
            .bearer_auth(tok)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn direct_presentation_passes_and_sets_subject() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let tok = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let r = reqwest::Client::new()
            .get(format!("{base}/private"))
            .bearer_auth(tok)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.text().await.unwrap(), "did:key:z6Mka|");
    }

    #[tokio::test]
    async fn forwarded_token_requires_actor_in_act() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let bearer_ok = signer.mint_with_act(
            &[
                ("iss", "https://identity.test"),
                ("sub", "did:key:z6Mka"),
                ("aud", "https://arks.test"),
            ],
            &["https://kg.test"],
        );
        let bearer_no_act = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let actor = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "https://kg.test"),
            ("aud", "https://arks.test"),
        ]);
        let c = reqwest::Client::new();
        let ok = c
            .get(format!("{base}/private"))
            .bearer_auth(&bearer_ok)
            .header("X-Actor-Token", &actor)
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.text().await.unwrap(), "did:key:z6Mka|https://kg.test");
        let denied = c
            .get(format!("{base}/private"))
            .bearer_auth(&bearer_no_act)
            .header("X-Actor-Token", &actor)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 401);
    }

    // Finding #3a: the old guard let a same-`sub` actor through even when
    // the bearer's `act[]` was empty (a `!=` self-escape around the
    // membership check). Spec §1 says membership in `act[]` is the only
    // thing that authorizes an actor.
    #[tokio::test]
    async fn same_sub_actor_without_act_membership_is_401() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let bearer_no_act = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let actor_same_sub = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let r = reqwest::Client::new()
            .get(format!("{base}/private"))
            .bearer_auth(&bearer_no_act)
            .header("X-Actor-Token", &actor_same_sub)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    // Finding #3b: a present-but-non-UTF-8 `X-Actor-Token` must 401, not be
    // treated as an absent header (which would silently fall through to a
    // direct presentation).
    #[tokio::test]
    async fn non_utf8_actor_header_is_401() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let bearer = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let r = reqwest::Client::new()
            .get(format!("{base}/private"))
            .bearer_auth(&bearer)
            .header("X-Actor-Token", vec![0xFF, 0xFE, 0xFD])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    // Finding #5: the `Err(e)` arm of actor-token validation — a header
    // that is present, valid UTF-8, but not a valid CWT itself (here: wrong
    // audience) — was untested. `act`-membership denial is covered by
    // `forwarded_token_requires_actor_in_act` above; this is the *invalid
    // token* arm.
    #[tokio::test]
    async fn invalid_actor_token_is_401() {
        let (state, signer, _mock) = state_with_keys().await;
        let base = spawn(state).await;
        let bearer = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "did:key:z6Mka"),
            ("aud", "https://arks.test"),
        ]);
        let bad_actor = signer.mint(&[
            ("iss", "https://identity.test"),
            ("sub", "https://kg.test"),
            ("aud", "https://wrong.test"),
        ]);
        let r = reqwest::Client::new()
            .get(format!("{base}/private"))
            .bearer_auth(&bearer)
            .header("X-Actor-Token", &bad_actor)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
}
