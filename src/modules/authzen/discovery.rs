//! AuthZEN well-known discovery document (profile MUST; no search in v1).

use serde_json::{json, Value};

pub fn document(policy_decision_point: &str) -> Value {
    let base = policy_decision_point.trim_end_matches('/');
    json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
        "access_evaluations_endpoint": format!("{base}/access/v1/evaluations"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_omits_search_and_signed_metadata() {
        let d = document("https://platform.arkavo.net/");
        assert_eq!(
            d["policy_decision_point"],
            json!("https://platform.arkavo.net")
        );
        assert_eq!(
            d["access_evaluation_endpoint"],
            json!("https://platform.arkavo.net/access/v1/evaluation")
        );
        assert_eq!(
            d["access_evaluations_endpoint"],
            json!("https://platform.arkavo.net/access/v1/evaluations")
        );
        assert!(d.get("search_resource_endpoint").is_none());
        assert!(d.get("search_subject_endpoint").is_none());
        assert!(d.get("search_action_endpoint").is_none());
        assert!(d.get("signed_metadata").is_none());
        assert_eq!(d.as_object().unwrap().len(), 3);
    }
}
