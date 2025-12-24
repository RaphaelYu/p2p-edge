use edge_gateway::forwarding::config::ForwardRule;
use edge_gateway::forwarding::router::{BackendSpec, Router};
use edge_gateway::forwarding::types::ErrorCode;

#[test]
fn route_returns_unix_backend() {
    let rules = vec![
        ForwardRule {
            protocol: "/p2".into(),
            backend: "unix:/tmp/p2.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
        ForwardRule {
            protocol: "/p1".into(),
            backend: "unix:/tmp/p1.sock".into(),
            max_conns: None,
            idle_timeout_secs: None,
        },
    ];
    let router = Router::new(&rules);
    let spec = router.route("/p1").expect("route exists");
    assert_eq!(
        spec,
        &BackendSpec::Unix {
            path: "/tmp/p1.sock".into()
        }
    );
}

#[test]
fn route_unknown_protocol_returns_error() {
    let rules = vec![ForwardRule {
        protocol: "/known".into(),
        backend: "unix:/tmp/known.sock".into(),
        max_conns: None,
        idle_timeout_secs: None,
    }];
    let router = Router::new(&rules);
    let err = router.route("/missing").err().expect("should error");
    assert_eq!(err, ErrorCode::NoRoute);
}
