#![doc = include_str!("../README.md")]

use bytes::Bytes;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    Stream,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client::{self},
    server::{self},
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use std::{future::Future, sync::Arc};
use tls::server_config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Mutex,
};
use tokiort::TokioIo;

pub use futures;
pub use hyper;
pub use tokio_native_tls;

mod tls;
mod tokiort;

#[derive(Clone)]
/// The main struct to run proxy server
pub struct MitmProxy {
    /// Root certificate to sign fake certificates. You may need to trust this certificate on client application to use HTTPS.
    ///
    /// If None, proxy will just tunnel HTTPS traffic and will not observe HTTPS traffic.
    pub root_cert: Option<Arc<rcgen::Certificate>>,
    /// TLS connector to connect from proxy to server.
    pub tls_connector: tokio_native_tls::native_tls::TlsConnector,
}

impl MitmProxy {
    pub fn new(
        root_cert: Option<Arc<rcgen::Certificate>>,
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

/// Communication between client and server.
///
/// Note: http-mitm-proxy observe by Communication basis, not Connection basis. Some Communications may belong to the same connection using keep-alive.
pub struct Communication<B> {
    /// Client address
    pub client_addr: std::net::SocketAddr,
    /// Request from client. request.uri() is an absolute URI.
    pub request: Request<Incoming>,
    /// Send request back to server. You can modify request before sending it back.
    /// NOTE: If you drop this without send(), communication will be canceled and server will not receive request and connection will be closed.
    pub request_back: futures::channel::oneshot::Sender<Request<B>>,
    /// Response from server. It may fail to receive response when some error occurs. Currently, not way to know the error.
    pub response: futures::channel::oneshot::Receiver<Response<UnboundedReceiver<Vec<u8>>>>,
    /// Upgraded connection. Proxy will upgrade connection if and only if response status is 101.
    pub upgrade: futures::channel::oneshot::Receiver<Upgrade>,
}

impl MitmProxy {
    /// Bind proxy server to address.
    /// You can observe communications between client and server by receiving stream.
    /// To run proxy server, you need to run returned future. This API design give you an ability to cancel proxy server when you want.
    pub async fn bind<A: ToSocketAddrs, B>(
        &self,
        addr: A,
    ) -> Result<
        (
            impl Stream<Item = Communication<B>>,
            impl Future<Output = ()>,
        ),
        std::io::Error,
    >
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let listener = TcpListener::bind(addr).await?;
        let (tx, rx) = futures::channel::mpsc::unbounded();

        let proxy = self.clone();

        let serve = async move {
            loop {
                let stream = listener.accept().await;
                let Ok((stream, client_addr)) = stream else {
                    continue;
                };
                let tx = tx.clone();

                let proxy = proxy.clone();
                tokio::spawn(async move { proxy.handle(stream, tx, client_addr).await });
            }
        };

        Ok((rx, serve))
    }

    async fn handle<B>(
        &self,
        stream: tokio::net::TcpStream,
        tx: UnboundedSender<Communication<B>>,
        client_addr: std::net::SocketAddr,
    ) where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let _ = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req| self.proxy(req, tx.clone(), client_addr)),
            )
            .with_upgrades()
            .await;
    }

    async fn proxy<B>(
        &self,
        req: Request<hyper::body::Incoming>,
        tx: UnboundedSender<Communication<B>>,
        client_addr: std::net::SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if req.method() == Method::CONNECT {
            // HTTPS connection
            // This request itself will not be reported as `Communication`
            let proxy = self.clone();
            tokio::spawn(async move {
                let uri = req.uri().clone();
                let Some(authority) = uri.authority() else {
                    return;
                };
                let Some(host) = uri.host() else {
                    return;
                };
                let Ok(client) = hyper::upgrade::on(req).await else {
                    return;
                };

                if let Some(root_cert) = proxy.root_cert.as_ref() {
                    let Ok(server_config) = server_config(host.to_string(), root_cert) else {
                        return;
                    };
                    // TODO: Cache server_config
                    let server_config = Arc::new(server_config);
                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                    let Ok(client) = tls_acceptor.accept(TokioIo::new(client)).await else {
                        return;
                    };

                    let Ok(server) = TcpStream::connect(authority.as_str()).await else {
                        return;
                    };
                    let native_tls_connector = proxy.tls_connector.clone();
                    let connector = tokio_native_tls::TlsConnector::from(native_tls_connector);
                    let Ok(server) = connector.connect(host, server).await else {
                        return;
                    };
                    let Ok((sender, conn)) = client::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .handshake(TokioIo::new(server))
                        .await
                    else {
                        return;
                    };

                    tokio::spawn(conn.with_upgrades());

                    let authority = authority.clone();
                    let sender = Arc::new(Mutex::new(sender));
                    let _ = server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(
                            TokioIo::new(client),
                            service_fn(move |mut req| {
                                let authority = authority.clone();
                                let sender = sender.clone();
                                let tx = tx.clone();

                                async move {
                                    let (req_back_tx, req_back_rx) =
                                        futures::channel::oneshot::channel();
                                    let (res_tx, res_rx) = futures::channel::oneshot::channel();
                                    let (upgrade_tx, upgrade_rx) =
                                        futures::channel::oneshot::channel();

                                    inject_authority(&mut req, authority);
                                    let _ = tx.unbounded_send(Communication {
                                        client_addr,
                                        request: req,
                                        request_back: req_back_tx,
                                        response: res_rx,
                                        upgrade: upgrade_rx,
                                    });
                                    let Ok(mut req) = req_back_rx.await else {
                                        return Ok::<_, hyper::Error>(no_body(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                        ));
                                    };
                                    remove_authority(&mut req);

                                    let (req, req_parts) = dup_request(req);
                                    let res = sender.lock().await.send_request(req).await?;
                                    let (res, res_upgrade, res_middleman) = dup_response(res);

                                    let _ = res_tx.send(res_middleman);

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
                                                let (rx_client, rx_server) = upgrade(
                                                    TokioIo::new(client),
                                                    TokioIo::new(server),
                                                )
                                                .await;

                                                let _ = upgrade_tx.send(Upgrade {
                                                    client_to_server: rx_client,
                                                    server_to_client: rx_server,
                                                });
                                            }
                                        });
                                        return Ok::<_, hyper::Error>(res);
                                    }

                                    Ok::<_, hyper::Error>(res)
                                }
                            }),
                        )
                        .with_upgrades()
                        .await;
                } else {
                    let Ok(mut server) =
                        TcpStream::connect(uri.authority().unwrap().as_str()).await
                    else {
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
            let Some(host) = req.uri().host() else {
                return Ok(no_body(StatusCode::BAD_REQUEST));
            };
            let port = req.uri().port_u16().unwrap_or(80);

            let Ok(stream) = TcpStream::connect((host, port)).await else {
                return Ok(no_body(StatusCode::BAD_GATEWAY));
            };

            let (mut sender, conn) = client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(stream))
                .await?;

            tokio::spawn(conn.with_upgrades());

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
            let Ok(mut req) = req_back_rx.await else {
                return Ok::<_, hyper::Error>(no_body(StatusCode::INTERNAL_SERVER_ERROR));
            };
            remove_authority(&mut req);

            let (req, req_parts) = dup_request(req);
            let res = sender.send_request(req).await?;
            let status = res.status();
            let (res, res_upgrade, res_middleman) = dup_response(res);

            let _ = res_tx.send(res_middleman);

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
                    }
                });
            }
            Ok(res)
        }
    }
}

fn no_body(status: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = status;
    res
}

fn inject_authority<B>(request_middleman: &mut Request<B>, authority: hyper::http::uri::Authority) {
    let mut parts = request_middleman.uri().clone().into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    parts.authority = Some(authority);
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
) -> (UnboundedReceiver<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    let (tx_client, rx_client) = futures::channel::mpsc::unbounded();
    let (tx_server, rx_server) = futures::channel::mpsc::unbounded();

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

    (rx_client, rx_server)
}

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
    Response<BoxBody<Bytes, hyper::Error>>,
    Response<Empty<Bytes>>,
    Response<UnboundedReceiver<Vec<u8>>>,
) {
    let (parts, body) = res.into_parts();
    let (body, rx) = dup_body(body);

    (
        Response::from_parts(parts.clone(), StreamBody::new(body).boxed()),
        Response::from_parts(parts.clone(), Empty::new()),
        Response::from_parts(parts.clone(), rx),
    )
}

fn dup_body<B>(
    body: B,
) -> (
    StreamBody<impl Stream<Item = Result<Frame<Bytes>, B::Error>>>,
    UnboundedReceiver<Vec<u8>>,
)
where
    B: Body<Data = Bytes> + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let body = futures::stream::unfold((body, tx), |(mut body, tx)| async move {
        if let Some(frame) = body.frame().await {
            if let Ok(frame) = frame.as_ref() {
                if let Some(data) = frame.data_ref() {
                    let _ = tx.unbounded_send(data.to_vec());
                }
            }
            Some((frame, (body, tx)))
        } else {
            None
        }
    });

    (StreamBody::new(body), rx)
}
