use async_trait::async_trait;
use futures::{io as fio, prelude::*};
use libp2p::request_response::Codec;
use std::io;

#[derive(Debug, Clone)]
pub struct PingProtocol;

#[derive(Debug, Clone)]
pub struct PingRequest;

#[derive(Debug, Clone)]
pub struct PingResponse {
    pub message: String,
}

#[derive(Clone, Default)]
pub struct PingCodec;

impl AsRef<str> for PingProtocol {
    fn as_ref(&self) -> &str {
        "/p2p-edge/ping/1.0.0"
    }
}

#[async_trait]
impl Codec for PingCodec {
    type Protocol = PingProtocol;
    type Request = PingRequest;
    type Response = PingResponse;

    async fn read_request<T>(&mut self, _: &PingProtocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        fio::copy(io, &mut buf).await?;
        Ok(PingRequest)
    }

    async fn read_response<T>(&mut self, _: &PingProtocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        fio::copy(io, &mut buf).await?;
        let msg =
            String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(PingResponse { message: msg })
    }

    async fn write_request<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
        _req: PingRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
        resp: PingResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(resp.message.as_bytes()).await?;
        io.close().await
    }
}
