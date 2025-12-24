use edge_gateway::forwarding::bridge::{bridge, bridge_with_idle, BridgeStage, BridgeStats};
use edge_gateway::forwarding::types::CloseReason;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

#[tokio::test]
async fn bridge_copies_bytes() {
    let (mut a_peer, a_side) = duplex(64);
    let (mut b_peer, b_side) = duplex(64);

    a_peer.write_all(b"hello").await.unwrap();
    b_peer.write_all(b"world").await.unwrap();
    // Close writer halves so copy can finish.
    drop(a_peer);
    drop(b_peer);

    let stats = bridge(a_side, b_side).await.expect("bridge ok");
    assert_eq!(
        stats,
        BridgeStats {
            bytes_a_to_b: 5,
            bytes_b_to_a: 5,
            close_reason: CloseReason::Normal
        }
    );
}

#[tokio::test]
async fn bridge_times_out_when_idle() {
    let (_a_peer, a_side) = duplex(64);
    let (_b_peer, b_side) = duplex(64);

    let stats = bridge_with_idle(
        a_side,
        b_side,
        Duration::from_millis(50),
    )
    .await
    .expect("timeout returns stats");

    assert_eq!(stats.close_reason, CloseReason::IdleTimeout);
}

#[tokio::test]
async fn bridge_returns_error_on_peer_drop() {
    let (mut a_peer, a_side) = duplex(64);
    let (_b_peer, b_side) = duplex(64);

    a_peer.write_all(b"ping").await.unwrap();
    // Drop the other end early to cause error on copy
    drop(_b_peer);

    let err = bridge(a_side, b_side).await.expect_err("should error");
    assert_eq!(err.stage, BridgeStage::Unknown);
    assert_eq!(err.io.kind(), std::io::ErrorKind::BrokenPipe);
}
