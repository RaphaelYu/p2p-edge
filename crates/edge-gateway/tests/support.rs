use std::{path::PathBuf, time::Duration};

use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    task::JoinHandle,
    time::sleep,
};

pub struct DropperServer {
    pub path: PathBuf,
    _tmpdir: TempDir,
    handle: JoinHandle<()>,
}

impl DropperServer {
    pub async fn wait(self) {
        let _ = self.handle.await;
    }
}

/// Start a unix socket server that drops the connection after reading `read_n` bytes (or immediately if 0).
pub async fn start_dropper(read_n: usize, drop_delay_ms: u64) -> DropperServer {
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let path = tmpdir.path().join("dropper.sock");
    // Ensure old socket is gone
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind dropper");
    let handle = tokio::spawn(async move {
        if let Ok((mut stream, _addr)) = listener.accept().await {
            if read_n > 0 {
                let mut buf = vec![0u8; read_n];
                let _ = stream.read_exact(&mut buf).await;
            }
            if drop_delay_ms > 0 {
                sleep(Duration::from_millis(drop_delay_ms)).await;
            }
            // drop stream to close
            let _ = stream.shutdown().await;
        }
    });

    DropperServer {
        path,
        _tmpdir: tmpdir,
        handle,
    }
}
