use bytes::Bytes;
use http_body_util::Empty;
use hyper::{
    body::{Body, Incoming},
    client, header, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::task::{Context, Poll};
use tokio::{net::TcpStream, task::JoinHandle};

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

/// Upgraded connections
pub struct Upgraded {
    /// A socket to Client
    pub client: TokioIo<hyper::upgrade::Upgraded>,
    /// A socket to Server
    pub server: TokioIo<hyper::upgrade::Upgraded>,
}
#[derive(Clone)]
/// Default HTTP client for this crate
pub struct DefaultClient {
    tls_connector_no_alpn: tokio_native_tls::TlsConnector,
    tls_connector_alpn_h2: tokio_native_tls::TlsConnector,
    /// If true, send_request will returns an Upgraded struct when the response is an upgrade
    /// If false, send_request never returns an Upgraded struct and just copy bidirectional when the response is an upgrade
    pub with_upgrades: bool,
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
            with_upgrades: false,
        })
    }

    /// Enable HTTP upgrades
    /// If you don't enable HTTP upgrades, send_request will just copy bidirectional when the response is an upgrade
    pub fn with_upgrades(mut self) -> Self {
        self.with_upgrades = true;
        self
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
    ) -> Result<
        (
            Response<Incoming>,
            Option<JoinHandle<Result<Upgraded, hyper::Error>>>,
        ),
        Error,
    >
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
            let (res_parts, res_body) = res.into_parts();

            let client_request = Request::from_parts(req_parts, Empty::<Bytes>::new());
            let server_response = Response::from_parts(res_parts.clone(), Empty::<Bytes>::new());

            let upgrade = if self.with_upgrades {
                Some(tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    Ok(Upgraded {
                        client: TokioIo::new(client),
                        server: TokioIo::new(server),
                    })
                }))
            } else {
                tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    let _ = tokio::io::copy_bidirectional(
                        &mut TokioIo::new(client),
                        &mut TokioIo::new(server),
                    )
                    .await;

                    Ok::<_, hyper::Error>(())
                });
                None
            };

            Ok((Response::from_parts(res_parts, res_body), upgrade))
        } else {
            Ok((res, None))
        }
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

fn remove_authority<B>(req: &mut Request<B>) {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts).unwrap();
}
