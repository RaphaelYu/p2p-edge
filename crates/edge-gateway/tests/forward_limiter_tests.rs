use std::time::Duration;

use edge_gateway::forwarding::limiter::{ForwardLimitError, ForwardLimiter};

#[tokio::test]
async fn limiter_rejects_when_over_capacity() {
    let limiter = ForwardLimiter::new(1, Duration::from_millis(50));
    let _p = limiter.acquire().await.expect("first acquire ok");
    let res = limiter.acquire().await;
    assert!(matches!(res, Err(ForwardLimitError::TooManyStreams)));
}
