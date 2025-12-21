use edge_bootstrap::registry::{NodeStatus, RegistryStore};
use tempfile::tempdir;

fn sample_addrs() -> Vec<String> {
    vec!["/ip4/127.0.0.1/tcp/4001".into()]
}

#[test]
fn pending_then_approve_and_list_active() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("registry.db");
    let store = RegistryStore::open(&db_path).unwrap();

    store
        .upsert_pending(
            "peer1",
            sample_addrs(),
            "operator1",
            vec!["bootstrap".into()],
            100,
            None,
        )
        .unwrap();
    store
        .set_status("peer1", NodeStatus::Active, "admin", None)
        .unwrap();

    let active = store.list_active().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].peer_id, "peer1");
    assert_eq!(active[0].status, NodeStatus::Active);
    assert!(active[0].last_approved_at.is_some());

    // Persist across reopen.
    drop(store);
    let store2 = RegistryStore::open(&db_path).unwrap();
    let active2 = store2.list_active().unwrap();
    assert_eq!(active2.len(), 1);
    assert_eq!(active2[0].peer_id, "peer1");
}

#[test]
fn revoke_moves_to_revoked_list() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("registry.db");
    let store = RegistryStore::open(&db_path).unwrap();

    store
        .upsert_pending("peer2", sample_addrs(), "operator2", vec![], 80, None)
        .unwrap();
    store
        .set_status("peer2", NodeStatus::Active, "admin", None)
        .unwrap();
    store
        .set_status(
            "peer2",
            NodeStatus::Revoked,
            "admin",
            Some("compromised".into()),
        )
        .unwrap();

    let active = store.list_active().unwrap();
    assert!(active.is_empty(), "revoked peer should not be active");
    let revoked = store.list_revoked_peer_ids().unwrap();
    assert_eq!(revoked, vec!["peer2".to_string()]);
}
