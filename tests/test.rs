use std::{
    convert::Infallible,
    sync::{atomic::AtomicU16, Arc},
};

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::{sse::Event, IntoResponse, Sse},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use bytes::Bytes;
use futures::{
    stream::{self, BoxStream},
    StreamExt,
};
use http_body_util::{BodyExt, Empty};
use http_mitm_proxy::Communication;
use hyper::{header, Request, Uri};
use rcgen::generate_simple_self_signed;
use reqwest::Client;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::tokiort::TokioIo;

#[path = "../src/tokiort.rs"]
mod tokiort;

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

async fn bind_app_tls(app: Router) -> (u16, impl std::future::Future<Output = ()>) {
    let port = get_port();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();

    (port, async move {
        axum_server::from_tcp_rustls(
            listener.into_std().unwrap(),
            RustlsConfig::from_config(tls_server_config(format!("127.0.0.1:{}", port))),
        )
        .serve(app.into_make_service())
        .await
        .unwrap()
    })
}

fn tls_server_config(host: String) -> Arc<ServerConfig> {
    let cert = generate_simple_self_signed(vec![host]).unwrap();
    let private_key = cert.get_key_pair().serialize_der();

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(cert.serialize_der().unwrap())],
            rustls::PrivateKey(private_key),
        )
        .unwrap();

    Arc::new(server_config)
}

fn client(proxy_port: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

struct Setup {
    proxy_port: u16,
    server_port: u16,
    proxy: BoxStream<'static, Communication>,
    client: Client,
}

async fn setup(app: Router) -> Setup {
    let (server_port, server) = bind_app(app).await;

    tokio::spawn(server);

    let proxy = http_mitm_proxy::MitmProxy::new(
        None,
        tokio_native_tls::native_tls::TlsConnector::new().unwrap(),
    );
    let proxy_port = get_port();

    let (branch, server) = proxy.bind(("127.0.0.1", proxy_port)).await.unwrap();

    tokio::spawn(server);

    let client = client(proxy_port);

    Setup {
        proxy_port,
        server_port,
        proxy: branch.boxed(),
        client,
    }
}

fn root_cert() -> rcgen::Certificate {
    let mut param = rcgen::CertificateParams::default();

    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<http-mitm-proxy TEST CA>".to_string()),
    );
    param.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    rcgen::Certificate::from_params(param).unwrap()
}

async fn setup_tls(app: Router, without_cert: bool) -> Setup {
    let (server_port, server) = bind_app_tls(app).await;

    tokio::spawn(server);

    let root_cert = Arc::new(root_cert());

    let proxy = http_mitm_proxy::MitmProxy::new(
        if without_cert {
            None
        } else {
            Some(root_cert.clone())
        },
        tokio_native_tls::native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap(),
    );
    let proxy_port = get_port();

    let (branch, server) = proxy.bind(("127.0.0.1", proxy_port)).await.unwrap();

    tokio::spawn(server);

    let client_builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).unwrap());

    let client = if !without_cert {
        client_builder
            .add_root_certificate(
                reqwest::Certificate::from_der(&root_cert.serialize_der().unwrap()).unwrap(),
            )
            .build()
            .unwrap()
    } else {
        client_builder
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    };

    Setup {
        proxy_port,
        server_port,
        proxy: branch.boxed(),
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

    let communication = setup.proxy.next().await.unwrap();

    assert_eq!(
        communication.request.uri().to_string(),
        format!("http://127.0.0.1:{}/", setup.server_port)
    );
    assert_eq!(
        communication.request.headers().get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );

    let body = communication
        .response
        .await
        .unwrap()
        .body_mut()
        .concat()
        .await;
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

        let communication = setup.proxy.next().await.unwrap();

        assert_eq!(
            communication.request.uri().to_string(),
            format!("http://127.0.0.1:{}/", setup.server_port)
        );
        assert_eq!(
            communication.request.headers().get(header::HOST).unwrap(),
            format!("127.0.0.1:{}", setup.server_port).as_bytes()
        );

        let body = communication
            .response
            .await
            .unwrap()
            .body_mut()
            .concat()
            .await;
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

    let communication = setup.proxy.next().await.unwrap();
    let body = communication
        .response
        .await
        .unwrap()
        .body_mut()
        .concat()
        .await;

    assert_eq!(
        body,
        b"event:message\ndata:1\n\nevent:message\ndata:2\n\nevent:message\ndata:3\n\n"
    );
}

#[tokio::test]
async fn test_upgrade() {
    let app = Router::new().route("/upgrade", get(upgrade_handler));
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
                Uri::try_from(format!("http://127.0.0.1:{}/upgrade", setup.server_port)).unwrap(),
            )
            .header(header::UPGRADE, "raw")
            .header(header::CONNECTION, "Upgrade")
            .body(Empty::<Bytes>::new())
            .unwrap(),
        )
        .await
        .unwrap();

    res.body_mut().collect().await.unwrap();
    let mut stream = TokioIo::new(hyper::upgrade::on(res).await.unwrap());
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    stream.write_all(b"pong").await.unwrap();
}

async fn upgrade_handler<B: Send + 'static>(req: axum::http::Request<B>) -> impl IntoResponse {
    tokio::spawn(async move {
        let mut socket = hyper14::upgrade::on(req).await.unwrap();

        socket.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    });

    axum::http::Response::builder()
        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
        .body(axum::body::Empty::new())
        .unwrap()
}

#[tokio::test]
async fn test_tls_simple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false).await;

    let response = setup
        .client
        .get(format!("https://127.0.0.1:{}/", setup.server_port))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let communication = setup.proxy.next().await.unwrap();

    assert_eq!(
        communication.request.uri().to_string(),
        format!("https://127.0.0.1:{}/", setup.server_port)
    );
    assert_eq!(
        communication.request.headers().get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );

    let body = communication
        .response
        .await
        .unwrap()
        .body_mut()
        .concat()
        .await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_tls_simple_tunnel() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let setup = setup_tls(app, true).await;

    let response = setup
        .client
        .get(format!("https://127.0.0.1:{}/", setup.server_port))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");
}

#[tokio::test]
async fn test_tls_keep_alive() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false).await;

    // reqwest wii use single connection with keep-alive
    for _ in 0..16 {
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send()
            .await
            .unwrap();

        let communication = setup.proxy.next().await.unwrap();

        assert_eq!(
            communication.request.uri().to_string(),
            format!("https://127.0.0.1:{}/", setup.server_port)
        );
        assert_eq!(
            communication.request.headers().get(header::HOST).unwrap(),
            format!("127.0.0.1:{}", setup.server_port).as_bytes()
        );

        let body = communication
            .response
            .await
            .unwrap()
            .body_mut()
            .concat()
            .await;
        assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
    }
}

#[tokio::test]
async fn test_tls_sse() {
    let app = Router::new().route(
        "/sse",
        get(|| async {
            Sse::new(stream::iter(["1", "2", "3"].into_iter().map(|s| {
                Ok::<Event, Infallible>(Event::default().event("message").data(s))
            })))
        }),
    );

    let mut setup = setup_tls(app, false).await;
    setup
        .client
        .get(format!("https://127.0.0.1:{}/sse", setup.server_port))
        .send()
        .await
        .unwrap();

    let communication = setup.proxy.next().await.unwrap();
    let body = communication
        .response
        .await
        .unwrap()
        .body_mut()
        .concat()
        .await;

    assert_eq!(
        body,
        b"event:message\ndata:1\n\nevent:message\ndata:2\n\nevent:message\ndata:3\n\n"
    );
}
