use async_trait::async_trait;
use bytes::Bytes;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    Stream,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    client::{self},
    server::{self},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use std::{future::Future, sync::Arc};
use tls::server_config;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokiort::TokioIo;

pub use futures;
pub use hyper;

mod tls;
pub mod tokiort;

#[async_trait]
pub trait MiddleMan<K> {
    // do not call hyper::upgrade::on() to req/res
    async fn request(&self, req: Request<UnboundedReceiver<Vec<u8>>>) -> K;
    async fn response(&self, key: K, res: Response<UnboundedReceiver<Vec<u8>>>) -> K;
    async fn upgrade(
        &self,
        key: K,
        client_to_server: UnboundedReceiver<Vec<u8>>,
        server_to_client: UnboundedReceiver<Vec<u8>>,
    );
}

struct Inner<T> {
    pub middle_man: T,
    pub root_cert: Option<rcgen::Certificate>,
}

#[derive(Clone)]
pub struct MitmProxy {
    pub root_cert: Option<Arc<rcgen::Certificate>>,
    pub tls_connector: Option<tokio_native_tls::native_tls::TlsConnector>,
}

impl MitmProxy {
    pub fn new(
        root_cert: Option<Arc<rcgen::Certificate>>,
        tls_connector: Option<tokio_native_tls::native_tls::TlsConnector>,
    ) -> Self {
        Self {
            root_cert,
            tls_connector,
        }
    }
}

pub struct Communication {
    pub request: Request<UnboundedReceiver<Vec<u8>>>,
}

impl MitmProxy {
    pub async fn bind<A: ToSocketAddrs>(
        &self,
        addr: A,
    ) -> Result<impl Stream<Item = Communication>, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let (tx, rx) = futures::channel::mpsc::unbounded();

        let proxy = self.clone();

        tokio::spawn(async move {
            loop {
                let stream = listener.accept().await;
                let Ok((stream, _)) = stream else {
                    continue;
                };
                let tx = tx.clone();

                let proxy = proxy.clone();
                tokio::spawn(async move { proxy.handle(stream, tx).await });
            }
        });

        Ok(rx)
    }

    async fn handle(&self, stream: tokio::net::TcpStream, tx: UnboundedSender<Communication>) {
        let _ = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|req| self.proxy(req, tx.clone())),
            )
            .with_upgrades()
            .await;
    }

    async fn proxy(
        &self,
        req: Request<hyper::body::Incoming>,
        tx: UnboundedSender<Communication>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if req.method() == Method::CONNECT {
            /*
            let uri = req.uri().clone();

            let proxy = self.clone();
            tokio::spawn(async move {
                let authority = uri.authority().unwrap().as_str();

                let client = hyper::upgrade::on(req).await.unwrap();

                if let Some(root_cert) = proxy.root_cert() {
                    let server_config = server_config(authority.to_string(), root_cert).unwrap();
                    // TODO: Cache server_config
                    let server_config = Arc::new(server_config);
                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                    let client = tls_acceptor.accept(TokioIo::new(client)).await.unwrap();

                    let server = TcpStream::connect(uri.authority().unwrap().as_str())
                        .await
                        .unwrap();
                    let native_tls_connector = proxy
                        .tls_connector
                        .as_ref()
                        .map(|c| c.clone())
                        .unwrap_or_else(|| {
                            tokio_native_tls::native_tls::TlsConnector::new().unwrap()
                        });
                    let connector = tokio_native_tls::TlsConnector::from(native_tls_connector);
                    let server = connector
                        .connect(uri.host().unwrap(), server)
                        .await
                        .unwrap();
                    let (sender, conn) = client::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .handshake(TokioIo::new(server))
                        .await
                        .unwrap();

                    tokio::spawn(conn.with_upgrades());

                    let authority = authority.to_string();
                    let sender = Arc::new(Mutex::new(sender));
                    let _ = server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(
                            TokioIo::new(client),
                            service_fn(|req| {
                                let proxy = proxy.clone();
                                let authority = authority.clone();
                                let sender = sender.clone();

                                async move {
                                    let mut lock = sender.lock().await;

                                    let (req, mut req_middleman, req_parts) = dup_request(req);
                                    inject_authority(
                                        &mut req_middleman,
                                        hyper::http::uri::Authority::try_from(authority).unwrap(),
                                    );
                                    let res = lock.send_request(req).await.unwrap();
                                    let (res, res_upgrade, res_middleman) = dup_response(res);
                                    let proxy2 = proxy.clone();
                                    let key = tokio::spawn(async move {
                                        proxy2.middle_man().request(req_middleman).await
                                    });
                                    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
                                        let proxy = proxy.clone();
                                        tokio::task::spawn(async move {
                                            match (
                                                hyper::upgrade::on(Request::from_parts(
                                                    req_parts,
                                                    Empty::<Bytes>::new(),
                                                ))
                                                .await,
                                                hyper::upgrade::on(res_upgrade).await,
                                            ) {
                                                (Ok(client), Ok(server)) => {
                                                    let (rx_client, rx_server) = upgrade(
                                                        TokioIo::new(client),
                                                        TokioIo::new(server),
                                                    )
                                                    .await;

                                                    let key = key.await.unwrap();
                                                    proxy
                                                        .middle_man()
                                                        .upgrade(key, rx_client, rx_server)
                                                        .await;
                                                }
                                                (Err(e), _) => eprintln!("upgrade error: {}", e),
                                                _ => todo!(),
                                            }
                                        });
                                        return Ok::<_, hyper::Error>(res);
                                    }
                                    drop(lock);
                                    proxy
                                        .middle_man()
                                        .response(key.await.unwrap(), res_middleman)
                                        .await;

                                    Ok::<_, hyper::Error>(res)
                                }
                            }),
                        )
                        .with_upgrades()
                        .await;
                } else {
                    let mut server = TcpStream::connect(uri.authority().unwrap().as_str())
                        .await
                        .unwrap();
                    tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut server)
                        .await
                        .unwrap();
                }
            });

            Ok(Response::new(
                http_body_util::Empty::new()
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            */
            todo!()
        } else {
            let host = req.uri().host().unwrap();
            let port = req.uri().port_u16().unwrap_or(80);

            let stream = TcpStream::connect((host, port)).await.unwrap();

            let (mut sender, conn) = client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(stream))
                .await?;

            tokio::spawn(conn.with_upgrades());

            let (req, req_middleman, req_parts) = dup_request(req);

            let res = tokio::spawn(sender.send_request(req));

            // Used tokio::spawn above to middle_man can consume rx in request()
            let _ = tx.unbounded_send(Communication {
                request: req_middleman,
            });
            // let key = self.middle_man().request(req_middleman).await;

            let res = res.await.unwrap()?;
            let status = res.status();
            let (res, res_upgrade, res_middleman) = dup_response(res);

            let proxy = self.clone();
            /*
            let key =
                tokio::spawn(async move { proxy.middle_man().response(key, res_middleman).await });
                */

            /*
            // https://developer.mozilla.org/ja/docs/Web/HTTP/Status/101
            if status == StatusCode::SWITCHING_PROTOCOLS {
                let proxy = self.clone();
                tokio::task::spawn(async move {
                    match (
                        hyper::upgrade::on(Request::from_parts(req_parts, Empty::<Bytes>::new()))
                            .await,
                        hyper::upgrade::on(res_upgrade).await,
                    ) {
                        (Ok(client), Ok(server)) => {
                            let (rx_client, rx_server) =
                                upgrade(TokioIo::new(client), TokioIo::new(server)).await;
                            let key = key.await.unwrap();
                            proxy.middle_man().upgrade(key, rx_client, rx_server).await;
                        }
                        (Err(e), _) => eprintln!("upgrade error: {}", e),
                        _ => todo!(),
                    }
                });
            }
            */
            Ok(res)
        }
    }
}

fn inject_authority(
    request_middleman: &mut Request<UnboundedReceiver<Vec<u8>>>,
    authority: hyper::http::uri::Authority,
) {
    let mut parts = request_middleman.uri().clone().into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    parts.authority = Some(authority);
    *request_middleman.uri_mut() = hyper::http::uri::Uri::from_parts(parts).unwrap();
}

async fn upgrade<
    S1: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
    S2: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
>(
    mut client: S1,
    mut server: S2,
) -> (UnboundedReceiver<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    let (tx_client, rx_client) = futures::channel::mpsc::unbounded();
    let (tx_server, rx_server) = futures::channel::mpsc::unbounded();

    tokio::spawn(async move {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        loop {
            buf1.clear();
            buf2.clear();
            tokio::select! {
                r = client.read_buf(&mut buf1) => {
                    if r.is_err() {
                        break;
                    }
                    if let Ok(0) = r {
                        break;
                    }
                    if server.write_all(&buf1).await.is_err() {
                        break;
                    }
                    let _ = tx_client.unbounded_send(buf1.clone());
                }

                r = server.read_buf(&mut buf2) => {
                    if r.is_err() {
                        break;
                    }
                    if let Ok(0) = r {
                        break;
                    }
                    if client.write_all(&buf2).await.is_err() {
                        break;
                    }
                    let _ = tx_server.unbounded_send(buf2.clone());
                }
            }
        }
    });
    (rx_client, rx_server)
}

fn dup_request(
    req: Request<hyper::body::Incoming>,
) -> (
    Request<StreamBody<impl Stream<Item = Result<Frame<Bytes>, hyper::Error>>>>,
    Request<UnboundedReceiver<Vec<u8>>>,
    hyper::http::request::Parts,
) {
    let (parts, body) = req.into_parts();
    let (body, rx) = dup_body(body);

    (
        Request::from_parts(parts.clone(), StreamBody::new(body)),
        Request::from_parts(parts.clone(), rx),
        parts,
    )
}

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

fn dup_body(
    body: Incoming,
) -> (
    StreamBody<impl Stream<Item = Result<Frame<Bytes>, hyper::Error>>>,
    UnboundedReceiver<Vec<u8>>,
) {
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
