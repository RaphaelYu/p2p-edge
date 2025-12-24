use edge_gateway::forwarding::config::ForwardRule;
use edge_gateway::forwarding::handler::Handler;

#[test]
fn stream_protocols_still_validate() {
    let rules = vec![ForwardRule {
        protocol: "/p1".into(),
        backend: "unix:/tmp/a.sock".into(),
        max_conns: None,
        idle_timeout_secs: None,
    }];
    let handler = Handler::new(rules);
    let protos = handler.stream_protocols().unwrap();
    assert_eq!(protos.len(), 1);
    assert_eq!(protos[0].to_string(), "/p1".to_string());
}
