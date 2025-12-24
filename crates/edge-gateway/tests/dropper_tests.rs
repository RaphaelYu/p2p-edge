mod support;

use support::start_dropper;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{sleep, Duration},
};

#[tokio::test]
async fn dropper_accepts_and_closes() {
    let dropper = start_dropper(0, 0).await;
    let mut client = UnixStream::connect(&dropper.path).await.expect("connect dropper");
    client.write_all(b"ping").await.expect("write");
    // Give dropper a moment to close
    sleep(Duration::from_millis(50)).await;
    let mut buf = [0u8; 4];
    let n = client.read(&mut buf).await.expect("read");
    assert_eq!(n, 0, "connection should be closed");
    dropper.wait().await;
}
