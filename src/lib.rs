use std::sync::Arc;

use async_trait::async_trait;
use http::Uri;
use request::{parse_path, read_req, replace_path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, ToSocketAddrs},
};

mod request;

const MAX_HEADERS: usize = 100;
#[async_trait]
pub trait MiddleMan<K> {
    async fn request(&self, data: &[u8]) -> K;
    async fn response(&self, key: &K, data: &[u8], closed: bool);
}

pub struct MitmProxy<T> {
    middle_man: T,
}

impl<T> MitmProxy<T> {
    pub fn new(middle_man: T) -> Self {
        Self { middle_man }
    }

    async fn handle(&self, mut stream: tokio::net::TcpStream) {
        while let Ok(Some((buf, _is_upgrade))) = read_req(&mut stream).await {
            let [_method, url, _version] = parse_path(&buf).unwrap();
            let url = Uri::try_from(url).unwrap();

            let mut server = tokio::net::TcpStream::connect((
                url.authority().unwrap().as_str(),
                url.port_u16().unwrap_or(80),
            ))
            .await
            .unwrap();

            let req = replace_path(buf).unwrap();

            server.write_all(&req).await.unwrap();
            let mut res = Vec::new();
            server.read_to_end(&mut res).await.unwrap();
            stream.write_all(&res).await.unwrap();
        }
    }
}

impl<T: Send + Sync + 'static> MitmProxy<T> {
    pub async fn serve<A: ToSocketAddrs>(proxy: Arc<Self>, addr: A) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;

        loop {
            let stream = listener.accept().await;
            let Ok((stream, _)) = stream else {
                continue;
            };

            let proxy = proxy.clone();
            tokio::spawn(async move { proxy.handle(stream).await });
        }
    }
}
