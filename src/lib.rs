#![doc = include_str!("../README.md")]

use bytes::{Buf, Bytes};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    lock::Mutex,
    Stream,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client, header, server,
    service::{service_fn, HttpService},
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use std::{
    borrow::Borrow,
    future::Future,
    sync::Arc,
    task::{Context, Poll},
};
use tls::server_config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};
use tower::{MakeService, Service};

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
    /// TLS connector to connect from proxy to server.
    pub tls_connector: tokio_native_tls::native_tls::TlsConnector,
}

struct MitmProxyImpl<C> {
    root_cert: Option<C>,
    tls_connector: tokio_native_tls::TlsConnector,
}

impl<C> MitmProxy<C> {
    pub fn new(
        root_cert: Option<C>,
        tls_connector: tokio_native_tls::native_tls::TlsConnector,
    ) -> Self {
        Self {
            root_cert,
            tls_connector,
        }
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
        S: Fn(Request<Incoming>) -> F + Send + Sync + Clone + 'static,
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
                            service_fn(|req| Self::proxy(proxy.clone(), req, service.clone())),
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
        req: Request<Incoming>,
        service: S,
    ) -> Result<Response<BoxBody<Bytes, E>>, E>
    where
        S: Fn(Request<Incoming>) -> F + Send + Clone + 'static,
        F: Future<Output = Result<Response<B>, E>> + Send,
        B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        if req.method() == Method::CONNECT {
            // https
            let connect_url = {
                let mut parts = req.uri().clone().into_parts();
                parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
                parts.path_and_query = Some(hyper::http::uri::PathAndQuery::from_static("/"));

                Uri::from_parts(parts).unwrap()
            };
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
                            service(req).await
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
            service(req).await.map(|res| res.map(|b| b.boxed()))
        }
    }
}

pub struct DefaultSendRequest(tokio_native_tls::TlsConnector);
impl DefaultSendRequest {
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

/*
/// Communication between client and server.
///
/// Note: http-mitm-proxy observe by Communication basis, not Connection basis. Some Communications may belong to the same connection using keep-alive.
#[allow(clippy::type_complexity)]
pub struct Communication<B> {
    /// Client address
    pub client_addr: std::net::SocketAddr,
    /// Request from client. request.uri() is an absolute URI except for `CONNECT` method.
    /// If you modify uri of `CONNECT` method, subsequent request will be sent to the modified uri (off course you can modify it). But `HOST` header remains the original value.
    pub request: Request<Incoming>,
    /// Send request back to server. You can modify request before sending it back.
    /// NOTE: If you drop this without send(), communication will be canceled and server will not receive request and client will get 500 Internal Server Error.
    pub request_back: futures::channel::oneshot::Sender<Request<B>>,
    /// Response from server. Be sent error if fails to get response from server.
    pub response: futures::channel::oneshot::Receiver<
        Result<Response<UnboundedReceiver<Result<Frame<Bytes>, Arc<hyper::Error>>>>, hyper::Error>,
    >,
    /// Upgraded connection. Proxy will upgrade connection if and only if response status is 101.
    pub upgrade: futures::channel::oneshot::Receiver<Upgrade>,
}

impl<C: Borrow<rcgen::CertifiedKey> + Send + Sync + 'static> MitmProxy<C> {
    /// Bind proxy server to address.
    /// You can observe communications between client and server by receiving stream.
    /// To run proxy server, you need to run returned future. This API design give you an ability to cancel proxy server when you want.
    pub async fn bind<A: ToSocketAddrs, B>(
        self,
        addr: A,
    ) -> Result<
        (
            impl Stream<Item = Communication<B>>,
            impl Future<Output = ()>,
        ),
        std::io::Error,
    >
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let listener = TcpListener::bind(addr).await?;
        let (tx, rx) = futures::channel::mpsc::unbounded();

        let serve = async move {
            let MitmProxy {
                root_cert,
                tls_connector,
            } = self;

            let proxy = Arc::new(MitmProxyImpl {
                root_cert,
                tls_connector: tokio_native_tls::TlsConnector::from(tls_connector),
            });

            loop {
                let Ok((stream, client_addr)) = listener.accept().await else {
                    continue;
                };
                let tx = tx.clone();

                let proxy = proxy.clone();
                tokio::spawn(
                    async move { MitmProxy::handle(proxy, stream, tx, client_addr).await },
                );
            }
        };

        Ok((rx, serve))
    }

    async fn handle<B>(
        proxy: Arc<MitmProxyImpl<C>>,
        stream: tokio::net::TcpStream,
        tx: UnboundedSender<Communication<B>>,
        client_addr: std::net::SocketAddr,
    ) where
        B: Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if let Err(err) = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req| Self::proxy(proxy.clone(), req, tx.clone(), client_addr)),
            )
            .with_upgrades()
            .await
        {
            tracing::error!("Error in proxy: {}", err);
        }
    }

    async fn proxy<B>(
        proxy: Arc<MitmProxyImpl<C>>,
        req: Request<hyper::body::Incoming>,
        tx: UnboundedSender<Communication<B>>,
        client_addr: std::net::SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, Arc<hyper::Error>>>, Error>
    where
        B: Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let original_uri = req.uri().clone();

        let (Some(req), res_tx, upgrade_tx) = send_and_receive_request(&tx, client_addr, req).await
        else {
            return Ok(no_body(StatusCode::INTERNAL_SERVER_ERROR));
        };

        if req.method() == Method::CONNECT {
            // HTTPS connection
            let connect_url = {
                let mut parts = req.uri().clone().into_parts();
                parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
                parts.path_and_query = Some(hyper::http::uri::PathAndQuery::from_static("/"));

                Uri::from_parts(parts).unwrap()
            };
            let Some(connect_authority) = req.uri().authority().cloned() else {
                tracing::error!(
                    "Bad CONNECT request: {}, Reason: Invalid Authority",
                    req.uri()
                );
                return Ok(no_body(StatusCode::BAD_REQUEST));
            };
            let Some(original_host) = original_uri.host().map(str::to_string) else {
                tracing::error!(
                    "Bad CONNECT request: {}, Reason: Invalid Host",
                    original_uri
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
                    let send_request_connect = proxy.connect(&connect_url).await;

                    let connect_server_h2 =
                        matches!(send_request_connect, Ok(SendRequest::Http2(_)));

                    let Ok(server_config) =
                        // Even if URL is modified by middleman, we should sign with original host name to communicate client.
                        server_config(original_host.to_string(), root_cert.borrow(), connect_server_h2)
                    else {
                        tracing::error!("Failed to create server config for {}", original_host);
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
                                original_host,
                                err
                            );
                            return;
                        }
                    };

                    let send_request_connect = Arc::new(Mutex::new(send_request_connect.ok()));

                    let f = move |mut req: Request<_>| {
                        let tx = tx.clone();
                        let connect_authority = connect_authority.clone();
                        let proxy = proxy.clone();
                        let send_request_connect = send_request_connect.clone();

                        async move {
                            inject_authority(&mut req, connect_authority.clone());

                            let (Some(req), res_tx, upgrade_tx) =
                                send_and_receive_request(&tx, client_addr, req).await
                            else {
                                return Ok::<_, Error>(no_body(StatusCode::INTERNAL_SERVER_ERROR));
                            };

                            let uri = req.uri().clone();

                            let (req, req_parts) = dup_request(req);

                            let response = if let Some(send_request_connect) =
                                send_request_connect.lock().await.as_mut()
                            {
                                if uri.authority() == Some(&connect_authority) {
                                    // Check if connection isn't closed by server yet.
                                    if futures::future::poll_fn(|ctx| {
                                        send_request_connect.poll_ready(ctx)
                                    })
                                    .await
                                    .is_err()
                                    {
                                        let sender = proxy.connect(req.uri()).await?;
                                        *send_request_connect = sender;
                                    }

                                    send_request_connect.send_request(req).await
                                } else {
                                    let mut sender = proxy.connect(req.uri()).await?;
                                    sender.send_request(req).await
                                }
                            } else {
                                let mut sender = proxy.connect(req.uri()).await?;
                                sender.send_request(req).await
                            };

                            let (res, res_upgrade) = match response {
                                Ok(res) => {
                                    tracing::info!("Response: {:?}", res.status());
                                    let (res, res_upgrade, res_middleman) = dup_response(res);
                                    let _ = res_tx.send(Ok(res_middleman));
                                    (res, res_upgrade)
                                }
                                Err(err) => {
                                    tracing::error!("Failed to send request to {} {}", uri, err);
                                    let _ = res_tx.send(Err(err));
                                    return Ok::<_, Error>(no_body(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                    ));
                                }
                            };

                            if res.status() == StatusCode::SWITCHING_PROTOCOLS {
                                tokio::task::spawn(async move {
                                    if let (Ok(client), Ok(server)) = (
                                        hyper::upgrade::on(Request::from_parts(
                                            req_parts,
                                            Empty::<Bytes>::new(),
                                        ))
                                        .await,
                                        hyper::upgrade::on(res_upgrade).await,
                                    ) {
                                        let (rx_client, rx_server) =
                                            upgrade(TokioIo::new(client), TokioIo::new(server))
                                                .await;

                                        let _ = upgrade_tx.send(Upgrade {
                                            client_to_server: rx_client,
                                            server_to_client: rx_server,
                                        });
                                    } else {
                                        tracing::error!("Failed to upgrade connection (HTTPS)");
                                    }
                                });
                            }

                            Ok(res)
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
                    .map_err(|never| match never {})
                    .boxed(),
            ))
        } else {
            let uri = req.uri().clone();
            let mut sender = proxy.connect(req.uri()).await?;

            let (req, req_parts) = dup_request(req);
            let (status, res, res_upgrade) = match sender.send_request(req).await {
                Ok(res) => {
                    tracing::info!("Response: {:?}", res.status());
                    let status = res.status();
                    let (res, res_upgrade, res_middleman) = dup_response(res);
                    let _ = res_tx.send(Ok(res_middleman));
                    (status, res, res_upgrade)
                }
                Err(err) => {
                    tracing::error!("Failed to send request to {}: {}", uri, err);
                    let _ = res_tx.send(Err(err));
                    return Ok(no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            // https://developer.mozilla.org/ja/docs/Web/HTTP/Status/101
            if status == StatusCode::SWITCHING_PROTOCOLS {
                tokio::task::spawn(async move {
                    if let (Ok(client), Ok(server)) = (
                        hyper::upgrade::on(Request::from_parts(req_parts, Empty::<Bytes>::new()))
                            .await,
                        hyper::upgrade::on(res_upgrade).await,
                    ) {
                        let (rx_client, rx_server) =
                            upgrade(TokioIo::new(client), TokioIo::new(server)).await;
                        let _ = upgrade_tx.send(Upgrade {
                            client_to_server: rx_client,
                            server_to_client: rx_server,
                        });
                    } else {
                        tracing::error!("Failed to upgrade connection (HTTP)");
                    }
                });
            }
            Ok(res)
        }
    }
}
    */

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

impl<C> MitmProxyImpl<C> {
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
                .tls_connector
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

/*
fn dup_request<B>(req: Request<B>) -> (Request<B>, hyper::http::request::Parts)
where
    B: Body<Data = Bytes> + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();

    (Request::from_parts(parts.clone(), body), parts)
}

#[allow(clippy::type_complexity)]
fn dup_response(
    res: Response<hyper::body::Incoming>,
) -> (
    Response<BoxBody<Bytes, Arc<hyper::Error>>>,
    Response<Empty<Bytes>>,
    Response<UnboundedReceiver<Result<Frame<Bytes>, Arc<hyper::Error>>>>,
) {
    let (parts, body) = res.into_parts();
    let (body, rx) = dup_body(body);

    (
        Response::from_parts(parts.clone(), StreamBody::new(body).boxed()),
        Response::from_parts(parts.clone(), Empty::new()),
        Response::from_parts(parts.clone(), rx),
    )
}

#[allow(clippy::type_complexity)]
fn dup_body<B>(
    body: B,
) -> (
    StreamBody<impl Stream<Item = Result<Frame<Bytes>, Arc<B::Error>>>>,
    UnboundedReceiver<Result<Frame<Bytes>, Arc<B::Error>>>,
)
where
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let body = futures::stream::unfold((body, tx), |(mut body, tx)| async move {
        if let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        let _ = tx.unbounded_send(Ok(Frame::data(data.clone())));
                    } else if let Some(trailers) = frame.trailers_ref() {
                        let _ = tx.unbounded_send(Ok(Frame::trailers(trailers.clone())));
                    }
                    Some((Ok(frame), (body, tx)))
                }
                Err(err) => {
                    let err = Arc::new(err);

                    let _ = tx.unbounded_send(Err(err.clone()));
                    Some((Err(err.clone()), (body, tx)))
                }
            }
        } else {
            None
        }
    });

    (StreamBody::new(body), rx)
}

async fn send_and_receive_request<B>(
    tx: &UnboundedSender<Communication<B>>,
    client_addr: std::net::SocketAddr,
    req: Request<Incoming>,
) -> (
    Option<Request<B>>,
    futures::channel::oneshot::Sender<
        Result<Response<UnboundedReceiver<Result<Frame<Bytes>, Arc<hyper::Error>>>>, hyper::Error>,
    >,
    futures::channel::oneshot::Sender<Upgrade>,
) {
    let (req_back_tx, req_back_rx) = futures::channel::oneshot::channel();
    let (res_tx, res_rx) = futures::channel::oneshot::channel();
    let (upgrade_tx, upgrade_rx) = futures::channel::oneshot::channel();
    // Used tokio::spawn above to middle_man can consume rx in request()
    let _ = tx.unbounded_send(Communication {
        client_addr,
        request: req,
        request_back: req_back_tx,
        response: res_rx,
        upgrade: upgrade_rx,
    });

    if let Ok(req) = req_back_rx.await {
        tracing::info!("Request canceled");
        (Some(req), res_tx, upgrade_tx)
    } else {
        (None, res_tx, upgrade_tx)
    }
}
*/
