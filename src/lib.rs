#![doc = include_str!("../README.md")]

use bytes::Bytes;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{
    body::{Body, Incoming},
    client, header, server,
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    borrow::Borrow,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use tls::server_config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

pub use futures;
pub use hyper;
pub use tokio_native_tls;

mod tls;

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

#[derive(Clone)]
/// The main struct to run proxy server
pub struct MitmProxy<C> {
    /// Root certificate to sign fake certificates. You may need to trust this certificate on client application to use HTTPS.
    ///
    /// If None, proxy will just tunnel HTTPS traffic and will not observe HTTPS traffic.
    pub root_cert: Option<C>,
}

impl<C> MitmProxy<C> {
    pub fn new(root_cert: Option<C>) -> Self {
        Self { root_cert }
    }
}

/// Upgraded connection
pub struct Upgrade {
    /// Client to server traffic
    pub client_to_server: UnboundedReceiver<Vec<u8>>,
    /// Server to client traffic
    pub server_to_client: UnboundedReceiver<Vec<u8>>,
}

// pub type Handler<B, E> = Fn(Request<Incoming>) -> Result<Response<B>, E>;

impl<C: Borrow<rcgen::CertifiedKey> + Send + Sync + 'static> MitmProxy<C> {
    pub async fn bind<A: ToSocketAddrs, S, B, E, F>(
        self,
        addr: A,
        service: S,
    ) -> Result<impl Future<Output = ()>, std::io::Error>
    where
        B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
        S: Fn(SocketAddr, Request<Incoming>) -> F + Send + Sync + Clone + 'static,
        F: Future<Output = Result<Response<B>, E>> + Send,
    {
        let listener = TcpListener::bind(addr).await?;

        let proxy = Arc::new(self);

        Ok(async move {
            loop {
                let Ok((stream, client_addr)) = listener.accept().await else {
                    continue;
                };

                let service = service.clone();

                let proxy = proxy.clone();
                tokio::spawn(async move {
                    if let Err(err) = server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|req| {
                                Self::proxy(proxy.clone(), client_addr, req, service.clone())
                            }),
                        )
                        .with_upgrades()
                        .await
                    {
                        tracing::error!("Error in proxy: {}", err);
                    }
                });
            }
        })
    }

    async fn proxy<S, B, E, F>(
        proxy: Arc<MitmProxy<C>>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
        service: S,
    ) -> Result<Response<BoxBody<Bytes, E>>, E>
    where
        S: Fn(SocketAddr, Request<Incoming>) -> F + Send + Clone + 'static,
        F: Future<Output = Result<Response<B>, E>> + Send,
        B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        if req.method() == Method::CONNECT {
            // https
            let Some(connect_authority) = req.uri().authority().cloned() else {
                tracing::error!(
                    "Bad CONNECT request: {}, Reason: Invalid Authority",
                    req.uri()
                );
                return Ok(no_body(StatusCode::BAD_REQUEST));
            };

            tokio::spawn(async move {
                let Ok(client) = hyper::upgrade::on(req).await else {
                    tracing::error!(
                        "Bad CONNECT request: {}, Reason: Invalid Upgrade",
                        connect_authority
                    );
                    return;
                };
                if let Some(root_cert) = proxy.root_cert.as_ref() {
                    let Ok(server_config) =
                        // Even if URL is modified by middleman, we should sign with original host name to communicate client.
                        server_config(connect_authority.host().to_string(), root_cert.borrow(), true)
                    else {
                        tracing::error!("Failed to create server config for {}", connect_authority.host());
                        return;
                    };
                    // TODO: Cache server_config
                    let server_config = Arc::new(server_config);
                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                    let client = match tls_acceptor.accept(TokioIo::new(client)).await {
                        Ok(client) => client,
                        Err(err) => {
                            tracing::error!(
                                "Failed to accept TLS connection for {}, {}",
                                connect_authority.host(),
                                err
                            );
                            return;
                        }
                    };
                    let f = move |mut req: Request<_>| {
                        let connect_authority = connect_authority.clone();
                        let service = service.clone();

                        async move {
                            inject_authority(&mut req, connect_authority.clone());
                            service(client_addr, req).await
                        }
                    };
                    let res = if client.get_ref().1.alpn_protocol() == Some(b"h2") {
                        server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(client), service_fn(f))
                            .await
                    } else {
                        server::conn::http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(TokioIo::new(client), service_fn(f))
                            .with_upgrades()
                            .await
                    };

                    if let Err(err) = res {
                        tracing::error!("Error in proxy: {}", err);
                    }
                } else {
                    let Ok(mut server) = TcpStream::connect(connect_authority.as_str()).await
                    else {
                        tracing::error!("Failed to connect to {}", connect_authority);
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut server).await;
                }
            });

            Ok(Response::new(
                http_body_util::Empty::new()
                    .map_err(|never: std::convert::Infallible| match never {})
                    .boxed(),
            ))
        } else {
            // http
            service(client_addr, req)
                .await
                .map(|res| res.map(|b| b.boxed()))
        }
    }
}

pub struct DefaultClient(tokio_native_tls::TlsConnector);
impl DefaultClient {
    pub fn new(tls_connector: native_tls::TlsConnector) -> Self {
        Self(tls_connector.into())
    }

    pub async fn send_request<B>(
        &self,
        req: Request<B>,
    ) -> Result<(Response<Incoming>, Option<Upgrade>), hyper::Error>
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // TODO
        let mut send_request = self.connect(req.uri()).await.unwrap();

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

    async fn connect<B>(&self, uri: &Uri) -> Result<SendRequest<B>, Error>
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
                .0
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
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        match self {
            SendRequest::Http1(sender) => sender.poll_ready(cx),
            SendRequest::Http2(sender) => sender.poll_ready(cx),
        }
    }
}

fn no_body<E>(status: StatusCode) -> Response<BoxBody<Bytes, E>> {
    let mut res = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = status;
    res
}

fn inject_authority<B>(request_middleman: &mut Request<B>, authority: hyper::http::uri::Authority) {
    let mut parts = request_middleman.uri().clone().into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    if parts.authority.is_none() {
        parts.authority = Some(authority);
    }
    *request_middleman.uri_mut() = hyper::http::uri::Uri::from_parts(parts).unwrap();
}

fn remove_authority<B>(req: &mut Request<B>) {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts).unwrap();
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
