use std::{
    sync::{atomic::AtomicU16, Arc},
    time::Duration,
};

use axum::{routing::get, Router};
use http_mitm_proxy::{MiddleMan, MitmProxy};
use tokio::sync::mpsc::UnboundedSender;

static PORT: AtomicU16 = AtomicU16::new(3666);

fn get_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn hello_world_server() -> (
    u16,
    impl std::future::Future<Output = Result<(), std::io::Error>>,
) {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let port = get_port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    (port, axum::serve(listener, app))
}

struct ChannelMan {
    req_tx: UnboundedSender<Vec<u8>>,
    res_tx: UnboundedSender<Vec<u8>>,
}

impl ChannelMan {
    fn new(req_tx: UnboundedSender<Vec<u8>>, res_tx: UnboundedSender<Vec<u8>>) -> Self {
        Self { req_tx, res_tx }
    }
}

#[async_trait::async_trait]
impl MiddleMan<()> for ChannelMan {
    async fn request(&self, data: &[u8]) -> () {
        self.req_tx.send(data.to_vec()).unwrap();
    }

    async fn response(&self, _key: (), data: &[u8]) {
        self.res_tx.send(data.to_vec()).unwrap();
    }
}

#[tokio::test]
async fn test_hello_world() {
    let (server_port, server) = hello_world_server().await;

    tokio::spawn(server);

    let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
    let (res_tx, res_rx) = tokio::sync::mpsc::unbounded_channel();

    let proxy = http_mitm_proxy::MitmProxy::new(ChannelMan::new(req_tx, res_tx));

    let proxy_port = get_port();
    tokio::spawn(MitmProxy::serve(Arc::new(proxy), ("127.0.0.1", proxy_port)));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .build()
        .unwrap();

    client
        .get(format!("http://127.0.0.1:{}/", server_port))
        .send()
        .await
        .unwrap();
}
