use std::time::Duration;

use edge_gateway::forwarding::backend::unix::{BackendConnectError, connect_unix};
use tokio::net::UnixListener;

#[tokio::test]
async fn connect_fails_on_missing_socket() {
    let res = connect_unix("/tmp/nonexistent.sock", Duration::from_millis(50)).await;
    assert!(matches!(
        res,
        Err(BackendConnectError::BackendConnectFailed)
    ));
}

#[tokio::test]
async fn connect_times_out() {
    // Create a listener that never accepts to force client connect to hang; using an abstract path would fail fast.
    let path = "/tmp/edge-gateway-timeout.sock";
    let _listener = UnixListener::bind(path).expect("bind unix");
    // Drop accept loop; connect will hang until timeout.
    let res = connect_unix(path, Duration::from_millis(10)).await;
    assert!(matches!(
        res,
        Err(BackendConnectError::BackendConnectTimeout)
    ));
    // cleanup
    let _ = std::fs::remove_file(path);
}
