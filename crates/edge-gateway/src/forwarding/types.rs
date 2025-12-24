#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    NotImplemented,
    Normal,
    IdleTimeout,
    BackendConnectFailed,
    NoRoute,
    TooManyStreams,
    IoError,
    IoErrorPeerReset,
    Unknown,
}

impl CloseReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloseReason::NotImplemented => "not_implemented",
            CloseReason::Normal => "normal",
            CloseReason::IdleTimeout => "idle_timeout",
            CloseReason::BackendConnectFailed => "backend_connect_failed",
            CloseReason::NoRoute => "no_route",
            CloseReason::TooManyStreams => "too_many_streams",
            CloseReason::IoError => "io_error",
            CloseReason::IoErrorPeerReset => "io_error_peer_reset",
            CloseReason::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    BackendConnectFailed,
    BackendConnectTimeout,
    NoRoute,
    TooManyStreams,
    IoError,
    IoErrorPeerReset,
    Unknown,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::BackendConnectFailed => "backend_connect_failed",
            ErrorCode::BackendConnectTimeout => "backend_connect_timeout",
            ErrorCode::NoRoute => "no_route",
            ErrorCode::TooManyStreams => "too_many_streams",
            ErrorCode::IoError => "io_error",
            ErrorCode::IoErrorPeerReset => "io_error_peer_reset",
            ErrorCode::Unknown => "unknown",
        }
    }
}

/// Map a standard io::Error to a stable ErrorCode for metrics.
pub fn map_io_error(err: &std::io::Error) -> ErrorCode {
    use std::io::ErrorKind::*;
    match err.kind() {
        NotFound => ErrorCode::BackendConnectFailed,
        ConnectionReset | BrokenPipe | UnexpectedEof => ErrorCode::IoErrorPeerReset,
        TimedOut => ErrorCode::IoError,
        _ => ErrorCode::IoError,
    }
}

/// Map a bridge copy outcome to a CloseReason (best-effort).
pub fn map_bridge_error_to_close_reason(err: Option<&std::io::Error>) -> CloseReason {
    if let Some(e) = err {
        use std::io::ErrorKind::*;
        match e.kind() {
            TimedOut => CloseReason::IdleTimeout,
            ConnectionReset | BrokenPipe | UnexpectedEof => CloseReason::IoErrorPeerReset,
            _ => CloseReason::IoError,
        }
    } else {
        CloseReason::Normal
    }
}
