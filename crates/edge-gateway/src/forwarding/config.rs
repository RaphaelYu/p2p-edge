use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ForwardRule {
    pub protocol: String,
    pub backend: String,
    #[serde(default)]
    pub max_conns: Option<u32>,
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
}

pub fn load_forward_rules(base: Option<Vec<ForwardRule>>) -> Result<Vec<ForwardRule>> {
    if let Ok(env_rules) = std::env::var("EDGE_FORWARD_RULES_JSON") {
        let rules: Vec<ForwardRule> =
            serde_json::from_str(&env_rules).context("parse EDGE_FORWARD_RULES_JSON")?;
        validate_rules(&rules)?;
        return Ok(rules);
    }
    let rules = base.unwrap_or_default();
    validate_rules(&rules)?;
    Ok(rules)
}

fn validate_rules(rules: &[ForwardRule]) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if rule.protocol.trim().is_empty() {
            anyhow::bail!("forward rule #{i} protocol is empty");
        }
        if !rule.backend.starts_with("unix:") {
            anyhow::bail!("forward rule #{i} backend must start with unix:");
        }
        let path = &rule.backend["unix:".len()..];
        if path.is_empty() {
            anyhow::bail!("forward rule #{i} backend path is empty");
        }
    }
    Ok(())
}
