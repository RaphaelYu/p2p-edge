use std::collections::HashMap;

use super::config::ForwardRule;
use super::types::{ErrorCode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendSpec {
    Unix { path: String },
}

#[derive(Clone, Debug)]
pub struct Router {
    table: HashMap<String, BackendSpec>,
}

impl Router {
    pub fn new(rules: &[ForwardRule]) -> Self {
        let mut table = HashMap::new();
        for rule in rules {
            // Backend validation was done at config load; keep minimal parsing here.
            if let Some(path) = rule.backend.strip_prefix("unix:") {
                table.insert(
                    rule.protocol.clone(),
                    BackendSpec::Unix {
                        path: path.to_string(),
                    },
                );
            }
        }
        Self { table }
    }

    pub fn route(&self, protocol: &str) -> Result<&BackendSpec, ErrorCode> {
        self.table.get(protocol).ok_or(ErrorCode::NoRoute)
    }
}
