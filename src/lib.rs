use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{channel::mpsc::UnboundedReceiver, Stream};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client,
    server::{self},
    service::service_fn,
    Request, Response, StatusCode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokiort::TokioIo;

mod tokiort;

#[async_trait]
pub trait MiddleMan<K> {
    async fn request(&self, req: Request<UnboundedReceiver<Vec<u8>>>) -> K;
    async fn response(&self, key: K, res: Response<UnboundedReceiver<Vec<u8>>>) -> K;
    async fn upgrade(
        &self,
        key: K,
        client_to_server: UnboundedReceiver<Vec<u8>>,
        server_to_client: UnboundedReceiver<Vec<u8>>,
    );
}

pub struct MitmProxy<T, K> {
    middle_man: Arc<T>,
    _phantom: std::marker::PhantomData<K>,
}

impl<T, K> MitmProxy<T, K> {
    pub fn new(middle_man: T) -> Self {
        Self {
            middle_man: Arc::new(middle_man),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Send + Sync + 'static, K: Sync> MitmProxy<T, K> {}

impl<T: MiddleMan<K> + Send + Sync + 'static, K: Sync + Send + 'static> MitmProxy<T, K> {
    pub async fn bind<A: ToSocketAddrs>(
        &self,
        addr: A,
    ) -> Result<impl Future<Output = ()>, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let middle_man = self.middle_man.clone();

        Ok(async move {
            loop {
                let stream = listener.accept().await;
                let Ok((stream, _)) = stream else {
                    continue;
                };

                let middle_man = middle_man.clone();
                tokio::spawn(async move { handle(middle_man, stream).await });
            }
        })
    }
}

async fn handle<M: MiddleMan<K> + Send + Sync + 'static, K: Send + 'static>(
    middle_man: Arc<M>,
    stream: tokio::net::TcpStream,
) {
    let _ = server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(|req| proxy(middle_man.clone(), req)),
        )
        .with_upgrades()
        .await;
}

async fn proxy<M: MiddleMan<K> + Send + Sync + 'static, K: Send + 'static>(
    middle_man: Arc<M>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<impl Body<Data = Bytes, Error = hyper::Error>>, hyper::Error> {
    let host = req.uri().host().unwrap();
    let port = req.uri().port_u16().unwrap_or(80);

    let stream = TcpStream::connect((host, port)).await.unwrap();

    let (mut sender, conn) = client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(TokioIo::new(stream))
        .await?;

    tokio::spawn(conn.with_upgrades());

    let (req_parts, body) = req.into_parts();
    let (body, rx) = dup_body(body);

    let res = tokio::spawn(sender.send_request(Request::from_parts(
        req_parts.clone(),
        StreamBody::new(body),
    )));

    // Used tokio::spawn above to middle_man can consume rx in request()
    let key = middle_man
        .request(Request::from_parts(req_parts.clone(), rx))
        .await;

    let res = res.await.unwrap()?;
    let status = res.status();
    let (parts, body) = res.into_parts();
    let (body, rx) = dup_body(body);

    let middle_man2 = middle_man.clone();
    let parts2 = parts.clone();
    let key = tokio::spawn(async move {
        middle_man2
            .response(key, Response::from_parts(parts2, rx))
            .await
    });

    if status == StatusCode::SWITCHING_PROTOCOLS {
        let res_parts = parts.clone();
        tokio::task::spawn(async move {
            match (
                hyper::upgrade::on(Request::from_parts(req_parts, Empty::<Bytes>::new())).await,
                hyper::upgrade::on(Response::from_parts(res_parts, Empty::<Bytes>::new())).await,
            ) {
                (Ok(client), Ok(server)) => {
                    let (tx_client, rx_client) = futures::channel::mpsc::unbounded();
                    let (tx_server, rx_server) = futures::channel::mpsc::unbounded();

                    let mut client = TokioIo::new(client);
                    let mut server = TokioIo::new(server);
                    let middle_man = middle_man.clone();
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

                    let key = key.await.unwrap();
                    middle_man.upgrade(key, rx_client, rx_server).await;
                }
                (Err(e), _) => eprintln!("upgrade error: {}", e),
                _ => todo!(),
            }
        });
        Ok(Response::from_parts(parts, StreamBody::new(body)))
    } else {
        Ok(Response::from_parts(parts, StreamBody::new(body)))
    }
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
