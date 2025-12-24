use edge_gateway::forwarding::types::{CloseReason, ErrorCode};

#[test]
fn close_reason_as_str_stable() {
    assert_eq!(CloseReason::NotImplemented.as_str(), "not_implemented");
    assert_eq!(CloseReason::Normal.as_str(), "normal");
    assert_eq!(CloseReason::IdleTimeout.as_str(), "idle_timeout");
    assert_eq!(CloseReason::BackendConnectFailed.as_str(), "backend_connect_failed");
    assert_eq!(CloseReason::NoRoute.as_str(), "no_route");
    assert_eq!(CloseReason::TooManyStreams.as_str(), "too_many_streams");
    assert_eq!(CloseReason::IoError.as_str(), "io_error");
    assert_eq!(CloseReason::IoErrorPeerReset.as_str(), "io_error_peer_reset");
    assert_eq!(CloseReason::Unknown.as_str(), "unknown");
}

#[test]
fn error_code_as_str_stable() {
    assert_eq!(ErrorCode::BackendConnectFailed.as_str(), "backend_connect_failed");
    assert_eq!(ErrorCode::BackendConnectTimeout.as_str(), "backend_connect_timeout");
    assert_eq!(ErrorCode::NoRoute.as_str(), "no_route");
    assert_eq!(ErrorCode::TooManyStreams.as_str(), "too_many_streams");
    assert_eq!(ErrorCode::IoError.as_str(), "io_error");
    assert_eq!(ErrorCode::IoErrorPeerReset.as_str(), "io_error_peer_reset");
    assert_eq!(ErrorCode::Unknown.as_str(), "unknown");
}

#[test]
fn map_io_error_kinds() {
    use std::io::{Error, ErrorKind};
    use edge_gateway::forwarding::types::{map_bridge_error_to_close_reason, map_io_error};

    assert_eq!(
        map_io_error(&Error::from(ErrorKind::NotFound)),
        ErrorCode::BackendConnectFailed
    );
    assert_eq!(
        map_io_error(&Error::from(ErrorKind::ConnectionReset)),
        ErrorCode::IoErrorPeerReset
    );
    assert_eq!(
        map_io_error(&Error::from(ErrorKind::BrokenPipe)),
        ErrorCode::IoErrorPeerReset
    );
    assert_eq!(
        map_io_error(&Error::from(ErrorKind::UnexpectedEof)),
        ErrorCode::IoErrorPeerReset
    );
    assert_eq!(
        map_io_error(&Error::from(ErrorKind::Other)),
        ErrorCode::IoError
    );

    assert_eq!(
        map_bridge_error_to_close_reason(Some(&Error::from(ErrorKind::ConnectionReset))),
        CloseReason::IoErrorPeerReset
    );
    assert_eq!(
        map_bridge_error_to_close_reason(Some(&Error::from(ErrorKind::TimedOut))),
        CloseReason::IdleTimeout
    );
    assert_eq!(
        map_bridge_error_to_close_reason(None),
        CloseReason::Normal
    );
}
