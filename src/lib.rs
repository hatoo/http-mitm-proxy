use async_trait::async_trait;
use tokio::net::{TcpListener, ToSocketAddrs};

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

    pub async fn serve<A: ToSocketAddrs>(&self, addr: A) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(addr).await?;

        loop {
            let stream = listener.accept().await;
            let Ok((stream, _)) = stream else {
                continue;
            };

            todo!()
        }

        Ok(())
    }
}
