//! CWT bearer authentication middleware (spec §1 `act` rule).
//!
//! Every non-public route runs `require_cwt`. The bearer must be a CWT from
//! the trusted issuer with `aud` ∋ this service. If the caller also sends
//! `X-Actor-Token`, that token's `sub` must be listed in the bearer's `act`
//! — the forwarder authenticating itself — otherwise 401.
//!
//! Not yet mounted on any route in this change; a later change hangs this
//! on the rewrap and media routers. Until then clippy `--bin arks` without
//! `--tests` would treat everything here as dead.

#![allow(dead_code)]

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
    /// This service's own identity (matches the `aud` it accepts).
    pub self_id: String,
}

/// Verified identity attached to the request as an axum `Extension`.
#[derive(Clone, Debug)]
pub struct AuthenticatedSubject {
    pub sub: String,
    pub account_id: Option<String>,
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

    let actor = match req
        .headers()
        .get(ACTOR_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        None => None,
        Some(raw) => match state.validator.validate_bearer(raw).await {
            Err(e) => {
                warn!("actor token invalid: {e}");
                return unauthorized("Invalid actor token");
            }
            Ok(actor_claims) => {
                if actor_claims.subject != claims.subject
                    && !claims.actors.iter().any(|a| a == &actor_claims.subject)
                {
                    warn!(
                        "actor {} not authorized in act for subject {}",
                        actor_claims.subject, claims.subject
                    );
                    return unauthorized("Actor not authorized for this token");
                }
                Some(actor_claims.subject)
            }
        },
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
                self_id: "https://arks.test".into(),
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
}
