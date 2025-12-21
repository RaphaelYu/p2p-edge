use edge_bootstrap::auth::{OperatorTokens, parse_bearer};

#[test]
fn bearer_parsing() {
    assert_eq!(parse_bearer("Bearer abc123"), Some("abc123"));
    assert_eq!(parse_bearer("Bearer   token"), Some("token"));
    assert!(parse_bearer("bearer abc").is_none());
    assert!(parse_bearer("Bearer").is_none());
}

#[test]
fn auth_tokens_plain() {
    let tokens = OperatorTokens::from_plain(vec![
        ("ops-1".to_string(), "secret1".to_string()),
        ("ops-2".to_string(), "secret2".to_string()),
    ]);
    assert_eq!(tokens.authenticate("secret1"), Some("ops-1".to_string()));
    assert_eq!(tokens.authenticate("secret2"), Some("ops-2".to_string()));
    assert!(tokens.authenticate("wrong").is_none());
}

#[test]
fn auth_tokens_hashed() {
    // sha256("secret3") = e0d9ac7d3719d04d3d68bc463498b0889723c4e70c3549d43681dd8996b7177f
    let tokens = OperatorTokens::from_hashed(vec![(
        "ops-3".to_string(),
        "e0d9ac7d3719d04d3d68bc463498b0889723c4e70c3549d43681dd8996b7177f".to_string(),
    )])
    .expect("hash ok");
    assert_eq!(tokens.authenticate("secret3"), Some("ops-3".to_string()));
    assert!(tokens.authenticate("secret4").is_none());
}
