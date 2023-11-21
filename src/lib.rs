use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use http::Uri;
use parse::{
    request::{parse_path, read_req, replace_path},
    response::{read_resp, response_type, ResponseType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, ToSocketAddrs},
};

mod parse;

#[async_trait]
pub trait MiddleMan<K> {
    async fn request(&self, data: &[u8]) -> K;
    // For simple http response which isn't SSE or websocket.
    async fn response(&self, key: K, data: &[u8]);
    // For sse response
    // It doesn't guarantee that data is split by something meaningful.
    // response will be called when connection is closed (with 0 length data).
    async fn recv(&self, _key: &K, _data: &[u8]) {}
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

    async fn handle(&self, mut stream: tokio::net::TcpStream) {
        while let Ok(Some((buf, is_upgrade))) = read_req(&mut stream).await {
            let [_method, url, _version] = parse_path(&buf).unwrap();
            let url = Uri::try_from(url).unwrap();

            let req = replace_path(buf, !is_upgrade).unwrap();

            let key = self.middle_man.request(&req).await;

            let mut server =
                tokio::net::TcpStream::connect((url.host().unwrap(), url.port_u16().unwrap_or(80)))
                    .await
                    .unwrap();
            server.write_all(&req).await.unwrap();
            let mut resp = read_resp(&mut server).await.unwrap().unwrap();

            match response_type(&resp).unwrap() {
                ResponseType::Normal => {
                    let _ = server.read_to_end(&mut resp).await;
                    stream.write_all(&resp).await.unwrap();
                    self.middle_man.response(key, &resp).await;
                }
                ResponseType::Sse => {
                    stream.write_all(&resp).await.unwrap();
                    self.middle_man.recv(&key, &resp).await;

                    loop {
                        resp.clear();
                        let n = server.read_buf(&mut resp).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        stream.write_all(&resp).await.unwrap();
                        self.middle_man.recv(&key, &resp).await;
                    }
                    self.middle_man.response(key, &[]).await;

                    return;
                }
                ResponseType::Upgrade => {
                    // TODO: handle 101 with body. It should be rare.
                    stream.write_all(&resp).await.unwrap();

                    let mut resp = Vec::new();
                    let mut forward = [0u8; 4 * 1024];
                    loop {
                        tokio::select! {
                            res = server.read_buf(&mut resp) => {
                                if let Ok(n) = res {
                                    if n == 0 {
                                        break;
                                    }
                                    if stream.write_all(&resp[resp.len() - n..]).await.is_err() {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            res = stream.read(&mut forward) => {
                                if let Ok(n) = res {
                                    if n == 0 {
                                        break;
                                    }
                                    if server.write_all(&forward[..n]).await.is_err() {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }

                    return;
                }
            }
        }
    }
}
