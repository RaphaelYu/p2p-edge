use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::{Duration as TimeDuration, OffsetDateTime};

#[derive(Clone)]
pub struct ChallengeManager {
    ttl: Duration,
    inner: Arc<Mutex<HashMap<String, ChallengeEntry>>>,
}

#[derive(Clone)]
struct ChallengeEntry {
    challenge: Vec<u8>,
    expires_at: Instant,
}

impl ChallengeManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn issue(&self, peer_id: &str) -> Result<(String, OffsetDateTime), ChallengeError> {
        let mut buf = vec![0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let expires_at = Instant::now() + self.ttl;
        let expires_wall =
            OffsetDateTime::now_utc() + TimeDuration::seconds(self.ttl.as_secs() as i64);
        let entry = ChallengeEntry {
            challenge: buf.clone(),
            expires_at,
        };
        let mut guard = self.inner.lock().map_err(|_| ChallengeError::Poisoned)?;
        guard.insert(peer_id.to_string(), entry);
        Ok((STANDARD_NO_PAD.encode(buf), expires_wall))
    }

    pub fn take(&self, peer_id: &str) -> Result<Vec<u8>, ChallengeError> {
        let mut guard = self.inner.lock().map_err(|_| ChallengeError::Poisoned)?;
        if let Some(entry) = guard.remove(peer_id) {
            if Instant::now() > entry.expires_at {
                return Err(ChallengeError::Expired);
            }
            return Ok(entry.challenge);
        }
        Err(ChallengeError::NotFound)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChallengeError {
    NotFound,
    Expired,
    Poisoned,
}
