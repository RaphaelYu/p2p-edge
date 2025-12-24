use crate::forwarding::types::CloseReason;
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeStats {
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub close_reason: CloseReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeStage {
    StreamRead,
    StreamWrite,
    BackendRead,
    BackendWrite,
    Unknown,
}

#[derive(Debug)]
pub struct BridgeError {
    pub stage: BridgeStage,
    pub io: std::io::Error,
}

/// Bidirectional copy between two streams, returning byte counts and close reason.
pub async fn bridge<A, B>(mut a: A, mut b: B) -> Result<BridgeStats, BridgeError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match io::copy_bidirectional(&mut a, &mut b).await {
        Ok((a_to_b, b_to_a)) => Ok(BridgeStats {
            bytes_a_to_b: a_to_b,
            bytes_b_to_a: b_to_a,
            close_reason: CloseReason::Normal,
        }),
        Err(e) => Err(BridgeError {
            stage: BridgeStage::Unknown,
            io: e,
        }),
    }
}

/// Bidirectional copy with an overall idle timeout.
pub async fn bridge_with_idle<A, B>(
    mut a: A,
    mut b: B,
    idle_timeout: Duration,
) -> Result<BridgeStats, BridgeError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match timeout(idle_timeout, io::copy_bidirectional(&mut a, &mut b)).await {
        Ok(Ok((a_to_b, b_to_a))) => Ok(BridgeStats {
            bytes_a_to_b: a_to_b,
            bytes_b_to_a: b_to_a,
            close_reason: CloseReason::Normal,
        }),
        Ok(Err(e)) => Err(BridgeError {
            stage: BridgeStage::Unknown,
            io: e,
        }),
        Err(_) => Ok(BridgeStats {
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            close_reason: CloseReason::IdleTimeout,
        }),
    }
}
