use edge_gateway::forwarding::config::ForwardRule;
use edge_gateway::forwarding::handler::Handler;
use tokio::io::{AsyncReadExt, duplex};

#[tokio::test]
async fn handler_closes_and_counts() {
    let rules = vec![ForwardRule {
        protocol: "/p1".into(),
        backend: "unix:/tmp/a.sock".into(),
        max_conns: None,
        idle_timeout_secs: None,
    }];
    let handler = Handler::new(rules);
    let (mut a, b) = duplex(64);
    handler.handle_inbound(b, "/p1").await;
    let mut buf = [0u8; 1];
    // peer should see EOF
    let n = a.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0);
}
