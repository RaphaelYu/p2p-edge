use crate::error::{BootstrapError, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Clone)]
pub struct ManifestSigner {
    signing_key: SigningKey,
}

impl ManifestSigner {
    pub fn from_base64(key_b64: &str) -> Result<Self> {
        let bytes = STANDARD_NO_PAD
            .decode(key_b64)
            .or_else(|_| STANDARD.decode(key_b64))
            .map_err(|e| BootstrapError::InvalidKey(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(BootstrapError::InvalidKey(
                "expected 32-byte Ed25519 private key".to_string(),
            ));
        }
        let signing_key = SigningKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| BootstrapError::InvalidKey("invalid key length".into()))?,
        );
        Ok(Self { signing_key })
    }

    pub fn sign(&self, message: &[u8]) -> Result<String> {
        let signature: Signature = self.signing_key.sign(message);
        Ok(STANDARD_NO_PAD.encode(signature.to_bytes()))
    }

    pub fn verify(&self, message: &[u8], signature_b64: &str) -> Result<()> {
        let sig_bytes = STANDARD_NO_PAD
            .decode(signature_b64)
            .or_else(|_| STANDARD.decode(signature_b64))
            .map_err(|e| BootstrapError::InvalidKey(e.to_string()))?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| BootstrapError::InvalidKey("invalid signature length".into()))?,
        );
        self.verifying_key()
            .verify(message, &signature)
            .map_err(|e| BootstrapError::InvalidKey(e.to_string()))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
