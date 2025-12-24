use edge_gateway::forwarding::behaviour::forwarding_supported_protocols;
use edge_gateway::forwarding::config::ForwardRule;
use edge_gateway::forwarding::handler::Handler;

#[test]
fn forwarding_protocols_are_sorted_and_deduped() {
    let rules = vec![
        ForwardRule {
            protocol: "/z".into(),
            backend: "unix:/tmp/a.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
        ForwardRule {
            protocol: "/a".into(),
            backend: "unix:/tmp/b.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
        ForwardRule {
            protocol: "/a".into(),
            backend: "unix:/tmp/c.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
    ];
    let handler = Handler::new(rules);
    let protocols = forwarding_supported_protocols(&handler).expect("protocols");
    let names: Vec<String> = protocols.iter().map(|p| p.to_string()).collect();
    assert_eq!(names, vec!["/a".to_string(), "/z".to_string()]);
}
