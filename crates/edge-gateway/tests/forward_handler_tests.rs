use edge_gateway::forwarding::config::ForwardRule;
use edge_gateway::forwarding::handler::Handler;

#[test]
fn dedup_protocols() {
    let rules = vec![
        ForwardRule {
            protocol: "/p1".into(),
            backend: "unix:/tmp/a.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
        ForwardRule {
            protocol: "/p1".into(),
            backend: "unix:/tmp/b.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
        ForwardRule {
            protocol: "/p2".into(),
            backend: "unix:/tmp/c.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
    ];
    let handler = Handler::new(rules);
    let protos = handler.stream_protocols().unwrap();
    assert_eq!(protos.len(), 2);
    let names: Vec<String> = protos.into_iter().map(|p| p.to_string()).collect();
    assert_eq!(names, vec!["/p1".to_string(), "/p2".to_string()]);
}

#[test]
fn reject_empty_protocol() {
    let rules = vec![ForwardRule {
        protocol: "".into(),
        backend: "unix:/tmp/a.sock".into(),
        max_conns: None,
        idle_timeout_secs: None,
    }];
    let handler = Handler::new(rules);
    assert!(handler.stream_protocols().is_err());
}

#[test]
fn reject_too_long_protocol() {
    let rules = vec![ForwardRule {
        protocol: "x".repeat(300),
        backend: "unix:/tmp/a.sock".into(),
        max_conns: None,
        idle_timeout_secs: None,
    }];
    let handler = Handler::new(rules);
    assert!(handler.stream_protocols().is_err());
}

#[test]
fn reject_empty_rules() {
    let handler = Handler::new(vec![]);
    assert!(handler.stream_protocols().is_err());
}
