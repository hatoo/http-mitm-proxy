use std::sync::{atomic::AtomicU16, Arc};

use axum::{routing::get, Router};
use http::{header, HeaderMap, HeaderName};
use http_mitm_proxy::{MiddleMan, MitmProxy};
use reqwest::Client;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

static PORT: AtomicU16 = AtomicU16::new(3666);

fn get_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn bind_app(
    app: Router,
) -> (
    u16,
    impl std::future::Future<Output = Result<(), std::io::Error>>,
) {
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

fn body_str(body: &[u8]) -> &str {
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut res = httparse::Response::new(&mut headers);
    let body_start = res.parse(&body).unwrap().unwrap();

    std::str::from_utf8(&body[body_start..]).unwrap()
}

fn client(proxy_port: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .build()
        .unwrap()
}

struct Setup {
    proxy_port: u16,
    server_port: u16,
    rx_req: UnboundedReceiver<Vec<u8>>,
    rx_res: UnboundedReceiver<Vec<u8>>,
    client: Client,
}

async fn setup(app: Router) -> Setup {
    let (server_port, server) = bind_app(app).await;

    tokio::spawn(server);

    let (req_tx, rx_req) = tokio::sync::mpsc::unbounded_channel();
    let (res_tx, rx_res) = tokio::sync::mpsc::unbounded_channel();

    let proxy = http_mitm_proxy::MitmProxy::new(ChannelMan::new(req_tx, res_tx));
    let proxy_port = get_port();

    tokio::spawn(
        MitmProxy::bind(Arc::new(proxy), ("127.0.0.1", proxy_port))
            .await
            .unwrap(),
    );

    let client = client(proxy_port);

    Setup {
        proxy_port,
        server_port,
        rx_req,
        rx_res,
        client,
    }
}

fn req_headers(buf: &[u8]) -> HeaderMap {
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(&buf).unwrap().unwrap();

    let mut map = HeaderMap::new();
    for header in req.headers.iter() {
        map.insert(
            HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
            std::str::from_utf8(header.value).unwrap().parse().unwrap(),
        );
    }

    map
}

fn res_headers(buf: &[u8]) -> HeaderMap {
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut res = httparse::Response::new(&mut headers);
    let _ = res.parse(&buf).unwrap().unwrap();

    let mut map = HeaderMap::new();
    for header in res.headers.iter() {
        map.insert(
            HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
            std::str::from_utf8(header.value).unwrap().parse().unwrap(),
        );
    }

    map
}

#[tokio::test]
async fn test_simple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app).await;

    setup
        .client
        .get(format!("http://127.0.0.1:{}/", setup.server_port))
        .send()
        .await
        .unwrap();

    let req = setup.rx_req.recv().await.unwrap();
    let req_headers = req_headers(&req);
    assert_eq!(
        req_headers.get(header::HOST).unwrap().as_bytes(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );
    let res = setup.rx_res.recv().await.unwrap();

    assert_eq!(body_str(&res), "Hello, World!");
}

#[tokio::test]
async fn test_multiple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app).await;

    // reqwest wii use single connection with keep-alive
    for _ in 0..16 {
        setup
            .client
            .get(format!("http://127.0.0.1:{}/", setup.server_port))
            .send()
            .await
            .unwrap();

        let req = setup.rx_req.recv().await.unwrap();
        let res = setup.rx_res.recv().await.unwrap();

        assert_eq!(body_str(&res), "Hello, World!");
    }
}
