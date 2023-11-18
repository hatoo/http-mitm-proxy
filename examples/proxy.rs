use std::sync::Arc;

use http_mitm_proxy::{MiddleMan, MitmProxy};

struct SimpleMan;

#[async_trait::async_trait]
impl MiddleMan<()> for SimpleMan {
    async fn request(&self, data: &[u8]) -> () {
        dbg!(String::from_utf8_lossy(data));
    }

    async fn response(&self, _key: (), data: &[u8]) {
        dbg!(String::from_utf8_lossy(data));
    }
}

#[tokio::main]
async fn main() {
    let proxy = MitmProxy::new(SimpleMan);
    MitmProxy::serve(Arc::new(proxy), "127.0.0.1:3003")
        .await
        .unwrap();
}
