use bytes::Bytes;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use http_body_util::Empty;
use hyper::{
    body::{Body, Incoming},
    client, header, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::task::{Context, Poll};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} doesn't have an valid host")]
    InvalidHost(Uri),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    NativeTlsError(#[from] tokio_native_tls::native_tls::Error),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error("Failed to connect to {0}, {1}")]
    ConnectError(Uri, hyper::Error),
    #[error("Failed to connect with TLS to {0}, {1}")]
    TlsConnectError(Uri, native_tls::Error),
}

/// Upgraded connection
pub struct Upgrade {
    /// Client to server traffic
    pub client_to_server: UnboundedReceiver<Vec<u8>>,
    /// Server to client traffic
    pub server_to_client: UnboundedReceiver<Vec<u8>>,
}
#[derive(Clone)]
/// Default HTTP client for this crate
pub struct DefaultClient {
    tls_connector_no_alpn: tokio_native_tls::TlsConnector,
    tls_connector_alpn_h2: tokio_native_tls::TlsConnector,
}
impl DefaultClient {
    pub fn new() -> native_tls::Result<Self> {
        let tls_connector_no_alpn = native_tls::TlsConnector::builder().build()?;
        let tls_connector_alpn_h2 = native_tls::TlsConnector::builder()
            .request_alpns(&["h2", "http/1.1"])
            .build()?;

        Ok(Self {
            tls_connector_no_alpn: tokio_native_tls::TlsConnector::from(tls_connector_no_alpn),
            tls_connector_alpn_h2: tokio_native_tls::TlsConnector::from(tls_connector_alpn_h2),
        })
    }

    fn tls_connector(&self, http_version: Version) -> &tokio_native_tls::TlsConnector {
        match http_version {
            Version::HTTP_2 => &self.tls_connector_alpn_h2,
            _ => &self.tls_connector_no_alpn,
        }
    }

    /// Send a request and return a response.
    /// If the response is an upgrade (= if status code is 101 Switching Protocols), it will return a response and an Upgrade struct.
    /// Request should have a full URL including scheme.
    pub async fn send_request<B>(
        &self,
        req: Request<B>,
    ) -> Result<(Response<Incoming>, Option<Upgrade>), Error>
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut send_request = self.connect(req.uri(), req.version()).await?;

        let (req_parts, req_body) = req.into_parts();

        let res = send_request
            .send_request(Request::from_parts(req_parts.clone(), req_body))
            .await?;

        if res.status() == StatusCode::SWITCHING_PROTOCOLS {
            let (tx_client, rx_client) = futures::channel::mpsc::unbounded();
            let (tx_server, rx_server) = futures::channel::mpsc::unbounded();

            let (res_parts, res_body) = res.into_parts();

            let res0 = Response::from_parts(res_parts.clone(), Empty::<Bytes>::new());
            tokio::task::spawn(async move {
                if let (Ok(client), Ok(server)) = (
                    hyper::upgrade::on(Request::from_parts(req_parts, Empty::<Bytes>::new())).await,
                    hyper::upgrade::on(res0).await,
                ) {
                    upgrade(
                        TokioIo::new(client),
                        TokioIo::new(server),
                        tx_client,
                        tx_server,
                    )
                    .await;
                } else {
                    tracing::error!("Failed to upgrade connection (HTTP)");
                }
            });

            return Ok((
                Response::from_parts(res_parts, res_body),
                Some(Upgrade {
                    client_to_server: rx_client,
                    server_to_client: rx_server,
                }),
            ));
        }

        Ok((res, None))
    }

    async fn connect<B>(&self, uri: &Uri, http_version: Version) -> Result<SendRequest<B>, Error>
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let host = uri.host().ok_or_else(|| Error::InvalidHost(uri.clone()))?;
        let port =
            uri.port_u16()
                .unwrap_or(if uri.scheme() == Some(&hyper::http::uri::Scheme::HTTPS) {
                    443
                } else {
                    80
                });

        let tcp = TcpStream::connect((host, port)).await?;
        // This is actually needed to some servers
        let _ = tcp.set_nodelay(true);

        if uri.scheme() == Some(&hyper::http::uri::Scheme::HTTPS) {
            let tls = self
                .tls_connector(http_version)
                .connect(host, tcp)
                .await
                .map_err(|err| Error::TlsConnectError(uri.clone(), err))?;

            if let Ok(Some(true)) = tls
                .get_ref()
                .negotiated_alpn()
                .map(|a| a.map(|b| b == b"h2"))
            {
                let (sender, conn) = client::conn::http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(uri.clone(), err))?;

                tokio::spawn(conn);

                Ok(SendRequest::Http2(sender))
            } else {
                let (sender, conn) = client::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(uri.clone(), err))?;

                tokio::spawn(conn.with_upgrades());

                Ok(SendRequest::Http1(sender))
            }
        } else {
            let (sender, conn) = client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(tcp))
                .await
                .map_err(|err| Error::ConnectError(uri.clone(), err))?;
            tokio::spawn(conn.with_upgrades());
            Ok(SendRequest::Http1(sender))
        }
    }
}

enum SendRequest<B> {
    Http1(hyper::client::conn::http1::SendRequest<B>),
    Http2(hyper::client::conn::http2::SendRequest<B>),
}

impl<B> SendRequest<B>
where
    B: Body + 'static,
{
    async fn send_request(
        &mut self,
        mut req: Request<B>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            SendRequest::Http1(sender) => {
                if req.version() == hyper::Version::HTTP_2 {
                    if let Some(authority) = req.uri().authority().cloned() {
                        req.headers_mut().insert(
                            header::HOST,
                            authority.as_str().parse().expect("Invalid authority"),
                        );
                    }
                }
                remove_authority(&mut req);
                sender.send_request(req).await
            }
            SendRequest::Http2(sender) => {
                if req.version() != hyper::Version::HTTP_2 {
                    req.headers_mut().remove(header::HOST);
                }
                sender.send_request(req).await
            }
        }
    }
}

impl<B> SendRequest<B> {
    #[allow(dead_code)]
    // TODO: connection pooling
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        match self {
            SendRequest::Http1(sender) => sender.poll_ready(cx),
            SendRequest::Http2(sender) => sender.poll_ready(cx),
        }
    }
}

async fn upgrade<
    S1: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    S2: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
>(
    client: S1,
    server: S2,
    tx_client: UnboundedSender<Vec<u8>>,
    tx_server: UnboundedSender<Vec<u8>>,
) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    tokio::spawn(async move {
        loop {
            let mut buf = vec![];
            let n = client_read.read_buf(&mut buf).await?;
            if n == 0 {
                break;
            }
            server_write.write_all(&buf).await?;
            let _ = tx_client.unbounded_send(buf);
        }
        Ok::<(), std::io::Error>(())
    });
    tokio::spawn(async move {
        loop {
            let mut buf = vec![];
            let n = server_read.read_buf(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf).await?;
            let _ = tx_server.unbounded_send(buf);
        }
        Ok::<(), std::io::Error>(())
    });
}

fn remove_authority<B>(req: &mut Request<B>) {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts).unwrap();
}

pub mod websocket {
    /*
    https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    Frame format:

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-------+-+-------------+-------------------------------+
         |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
         |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
         |N|V|V|V|       |S|             |   (if payload len==126/127)   |
         | |1|2|3|       |K|             |                               |
         +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
         |     Extended payload length continued, if payload len == 127  |
         + - - - - - - - - - - - - - - - +-------------------------------+
         |                               |Masking-key, if MASK set to 1  |
         +-------------------------------+-------------------------------+
         | Masking-key (continued)       |          Payload Data         |
         +-------------------------------- - - - - - - - - - - - - - - - +
         :                     Payload Data continued ...                :
         + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
         |                     Payload Data continued ...                |
         +---------------------------------------------------------------+

    */

    use winnow::{
        binary::{be_u16, be_u64, u8},
        prelude::*,
        token::take,
    };

    pub struct Frame {
        pub b0: u8,
        pub b1: u8,
        pub payload_len: usize,
        pub masking_key: Option<[u8; 4]>,
        pub payload_data: Vec<u8>,
    }

    pub fn frame(input: &mut &[u8]) -> PResult<Frame> {
        let b0 = u8(input)?;
        let b1 = u8(input)?;

        let payload_len = match b1 & 0b0111_1111 {
            126 => {
                let len = be_u16(input)?;
                len as usize
            }
            127 => {
                let len = be_u64(input)?;
                len as usize
            }
            _ => (b1 & 0b0111_1111) as usize,
        };

        let mask = b1 & 0b1000_0000 != 0;
        let masking_key = if mask {
            Some([u8(input)?, u8(input)?, u8(input)?, u8(input)?])
        } else {
            None
        };

        dbg!(payload_len);
        let mut payload_data = take(payload_len).parse_next(input)?.to_vec();

        if let Some(mask) = masking_key {
            for (i, byte) in payload_data.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }

        Ok(Frame {
            b0,
            b1,
            payload_len,
            masking_key,
            payload_data,
        })
    }
}
