use std::{convert::Infallible, sync::atomic::AtomicU16};

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{sse::Event, IntoResponse, Sse},
    routing::get,
    Router,
};
use bytes::Bytes;
use futures::{
    channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
    stream, StreamExt,
};
use http_body_util::{BodyExt, Empty};
use http_mitm_proxy::{tokiort::TokioIo, MiddleMan};
use hyper::{header, Request, Response, Uri};
use reqwest::Client;

static PORT: AtomicU16 = AtomicU16::new(3666);

fn get_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn bind_app(app: Router) -> (u16, impl std::future::Future<Output = ()>) {
    let port = get_port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    (port, async {
        axum::Server::from_tcp(listener.into_std().unwrap())
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap()
    })
}

struct ChannelMan {
    req_tx: UnboundedSender<Request<UnboundedReceiver<Vec<u8>>>>,
    res_tx: UnboundedSender<Response<UnboundedReceiver<Vec<u8>>>>,
}

impl ChannelMan {
    fn new(
        req_tx: UnboundedSender<Request<UnboundedReceiver<Vec<u8>>>>,
        res_tx: UnboundedSender<Response<UnboundedReceiver<Vec<u8>>>>,
    ) -> Self {
        Self { req_tx, res_tx }
    }
}

#[async_trait::async_trait]
impl MiddleMan<()> for ChannelMan {
    async fn request(&self, req: Request<UnboundedReceiver<Vec<u8>>>) {
        self.req_tx.unbounded_send(req).unwrap();
    }

    async fn response(&self, _: (), res: Response<UnboundedReceiver<Vec<u8>>>) {
        self.res_tx.unbounded_send(res).unwrap();
    }

    async fn upgrade(&self, _: (), _: UnboundedReceiver<Vec<u8>>, _: UnboundedReceiver<Vec<u8>>) {}
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
    rx_req: UnboundedReceiver<Request<UnboundedReceiver<Vec<u8>>>>,
    rx_res: UnboundedReceiver<Response<UnboundedReceiver<Vec<u8>>>>,
    client: Client,
}

async fn setup(app: Router) -> Setup {
    let (server_port, server) = bind_app(app).await;

    tokio::spawn(server);

    let (req_tx, rx_req) = unbounded();
    let (res_tx, rx_res) = unbounded();

    let proxy = http_mitm_proxy::MitmProxy::new(ChannelMan::new(req_tx, res_tx));
    let proxy_port = get_port();

    tokio::spawn(proxy.bind(("127.0.0.1", proxy_port)).await.unwrap());

    let client = client(proxy_port);

    Setup {
        proxy_port,
        server_port,
        rx_req,
        rx_res,
        client,
    }
}

#[tokio::test]
async fn test_simple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app).await;

    let response = setup
        .client
        .get(format!("http://127.0.0.1:{}/", setup.server_port))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let req = setup.rx_req.next().await.unwrap();
    assert_eq!(
        req.headers().get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );
    let res = setup.rx_res.next().await.unwrap();

    let body = res.into_body().concat().await;

    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_keep_alive() {
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

        let req = setup.rx_req.next().await.unwrap();
        assert_eq!(
            req.headers().get(header::HOST).unwrap(),
            format!("127.0.0.1:{}", setup.server_port).as_bytes()
        );
        let res = setup.rx_res.next().await.unwrap();

        let body = res.into_body().concat().await;

        assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
    }
}

#[tokio::test]
async fn test_sse() {
    let app = Router::new().route(
        "/sse",
        get(|| async {
            Sse::new(stream::iter(["1", "2", "3"].into_iter().map(|s| {
                Ok::<Event, Infallible>(Event::default().event("message").data(s))
            })))
        }),
    );

    let mut setup = setup(app).await;
    setup
        .client
        .get(format!("http://127.0.0.1:{}/sse", setup.server_port))
        .send()
        .await
        .unwrap();

    let res = setup.rx_res.next().await.unwrap();
    let body = res.into_body().concat().await;

    assert_eq!(
        body,
        b"event:message\ndata:1\n\nevent:message\ndata:2\n\nevent:message\ndata:3\n\n"
    );
}

#[tokio::test]
async fn test_upgrade() {
    let app = Router::new().route("/ws", get(ws_handler));
    let setup = setup(app).await;

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", setup.proxy_port))
        .await
        .unwrap();
    let io = TokioIo::new(stream);
    let (mut send_request, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn.with_upgrades());
    let mut res = send_request
        .send_request(
            Request::get(
                Uri::try_from(format!("http://127.0.0.1:{}/ws", setup.server_port)).unwrap(),
            )
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .body(Empty::<Bytes>::new())
            .unwrap(),
        )
        .await
        .unwrap();

    res.body_mut().collect().await.unwrap();
    let _stream = hyper::upgrade::on(res).await.unwrap();
    // FIXME: there are no websocket library supports proxy.
}

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket))
}

async fn handle_socket(mut socket: WebSocket) {
    // receive single message from a client (we can either receive or send with socket).
    // this will likely be the Pong for our Ping or a hello message from client.
    // waiting for message from a client will block this task, but will not block other client's
    // connections.
    if let Some(msg) = socket.recv().await {
        let _ = msg.unwrap();
    }

    socket
        .send(Message::Text("Hello, World!".to_string()))
        .await
        .unwrap();
}
