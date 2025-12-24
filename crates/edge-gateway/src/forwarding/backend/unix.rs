use std::path::Path;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::time::timeout;

#[derive(Debug)]
pub enum BackendConnectError {
    BackendConnectTimeout,
    BackendConnectFailed,
}

pub async fn connect_unix(
    path: impl AsRef<Path>,
    wait: Duration,
) -> Result<UnixStream, BackendConnectError> {
    let path = path.as_ref().to_path_buf();
    match timeout(wait, UnixStream::connect(path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(BackendConnectError::BackendConnectFailed),
        Err(_) => Err(BackendConnectError::BackendConnectTimeout),
    }
}
