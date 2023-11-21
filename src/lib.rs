use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{channel::mpsc::UnboundedReceiver, Stream};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::{Body, Frame, Incoming},
    client,
    server::{self},
    service::service_fn,
    Request, Response,
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokiort::TokioIo;

mod tokiort;

#[async_trait]
pub trait MiddleMan<K> {
    async fn request(&self, req: Request<UnboundedReceiver<Vec<u8>>>) -> K;
    async fn response(&self, key: K, res: Response<UnboundedReceiver<Vec<u8>>>);
}

pub struct MitmProxy<T, K> {
    middle_man: T,
    _phantom: std::marker::PhantomData<K>,
}

impl<T, K> MitmProxy<T, K> {
    pub fn new(middle_man: T) -> Self {
        Self {
            middle_man,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Send + Sync + 'static, K: Sync> MitmProxy<T, K> {}

impl<T: MiddleMan<K> + Send + Sync + 'static, K: Sync + Send + 'static> MitmProxy<T, K> {
    pub async fn bind<A: ToSocketAddrs>(
        proxy: Arc<Self>,
        addr: A,
    ) -> Result<impl Future<Output = ()>, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;

        Ok(async move {
            loop {
                let stream = listener.accept().await;
                let Ok((stream, _)) = stream else {
                    continue;
                };

                let proxy = proxy.clone();
                tokio::spawn(async move { proxy.handle(stream).await });
            }
        })
    }

    async fn handle(&self, stream: tokio::net::TcpStream) {
        let _ = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(stream), service_fn(|req| self.proxy(req)))
            .with_upgrades()
            .await;
    }

    async fn proxy(
        &self,
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

        tokio::spawn(conn);

        let (parts, body) = req.into_parts();
        let (body, rx) = dup_body(body);

        let key = self
            .middle_man
            .request(Request::from_parts(parts.clone(), rx))
            .await;

        let res = sender
            .send_request(Request::from_parts(parts, StreamBody::new(body)))
            .await?;

        let (parts, body) = res.into_parts();
        let (body, rx) = dup_body(body);

        self.middle_man
            .response(key, Response::from_parts(parts.clone(), rx))
            .await;

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
