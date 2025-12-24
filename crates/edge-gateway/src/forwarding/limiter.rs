use std::time::Duration;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

#[derive(Clone)]
pub struct ForwardLimiter {
    sem: std::sync::Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ForwardLimitError {
    #[error("too_many_streams")]
    TooManyStreams,
}

impl ForwardLimiter {
    pub fn new(max_streams: usize, wait_timeout: Duration) -> Self {
        let capacity = if max_streams == 0 { 1 } else { max_streams };
        Self {
            sem: std::sync::Arc::new(Semaphore::new(capacity)),
            timeout: wait_timeout,
        }
    }

    pub fn try_acquire_now(&self) -> Result<OwnedSemaphorePermit, ForwardLimitError> {
        self.sem
            .clone()
            .try_acquire_owned()
            .map_err(|_| ForwardLimitError::TooManyStreams)
    }

    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, ForwardLimitError> {
        match timeout(self.timeout, self.sem.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(ForwardLimitError::TooManyStreams),
        }
    }
}
