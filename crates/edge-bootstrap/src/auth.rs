use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug)]
pub struct TokenEntry {
    pub operator_id: String,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct OperatorTokens {
    entries: Vec<TokenEntry>,
}

impl OperatorTokens {
    pub fn from_plain(tokens: Vec<(String, String)>) -> Self {
        let entries = tokens
            .into_iter()
            .map(|(operator_id, token)| TokenEntry {
                operator_id,
                hash: hash_token(&token),
            })
            .collect();
        Self { entries }
    }

    pub fn from_hashed(hashes: Vec<(String, String)>) -> Option<Self> {
        let mut entries = Vec::new();
        for (operator_id, hash_hex) in hashes {
            if let Some(hash) = decode_hash_hex(&hash_hex) {
                entries.push(TokenEntry { operator_id, hash });
            } else {
                return None;
            }
        }
        Some(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn authenticate(&self, bearer_token: &str) -> Option<String> {
        let presented = hash_token(bearer_token);
        for entry in &self.entries {
            if entry.hash.ct_eq(&presented).into() {
                return Some(entry.operator_id.clone());
            }
        }
        None
    }
}

pub fn parse_bearer(header: &str) -> Option<&str> {
    let prefix = "Bearer ";
    if header.len() <= prefix.len() || !header.starts_with(prefix) {
        return None;
    }
    Some(header[prefix.len()..].trim())
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn decode_hash_hex(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}
