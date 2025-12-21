use thiserror::Error;

pub type Result<T> = std::result::Result<T, BootstrapError>;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<time::error::Format> for BootstrapError {
    fn from(err: time::error::Format) -> Self {
        BootstrapError::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for BootstrapError {
    fn from(err: serde_json::Error) -> Self {
        BootstrapError::Serialization(err.to_string())
    }
}
