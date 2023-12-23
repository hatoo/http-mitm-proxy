use std::{
    convert::Infallible,
    sync::{atomic::AtomicU16, Arc},
};

use axum::{
    response::{sse::Event, IntoResponse, Sse},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use bytes::Bytes;
use futures::{
    channel::mpsc::UnboundedReceiver,
    stream::{self, BoxStream},
    StreamExt,
};
use http_mitm_proxy::Communication;
use hyper::{
    body::{Body, Frame, Incoming},
    header, HeaderMap,
};
use hyper_util::rt::TokioIo;
use rcgen::generate_simple_self_signed;
use reqwest::Client;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        axum::serve(listener, app).await.unwrap();
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

struct Setup<B> {
    _proxy_port: u16,
    server_port: u16,
    proxy: BoxStream<'static, Communication<B>>,
    client: Client,
}

async fn setup<B>(app: Router) -> Setup<B>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (server_port, server) = bind_app(app).await;

    tokio::spawn(server);

    let proxy = http_mitm_proxy::MitmProxy::<&'static rcgen::Certificate>::new(
        None,
        tokio_native_tls::native_tls::TlsConnector::new().unwrap(),
    );
    let proxy_port = get_port();

    let (twig, server) = proxy.bind(("127.0.0.1", proxy_port)).await.unwrap();

    tokio::spawn(server);

    let client = client(proxy_port);

    Setup {
        _proxy_port: proxy_port,
        server_port,
        proxy: twig.boxed(),
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

async fn setup_tls<B>(app: Router, without_cert: bool) -> Setup<B>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (server_port, server) = bind_app_tls(app).await;

    tokio::spawn(server);

    let root_cert = root_cert();
    let root_cert_der = root_cert.serialize_der().unwrap();

    let proxy = http_mitm_proxy::MitmProxy::new(
        if without_cert { None } else { Some(root_cert) },
        tokio_native_tls::native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap(),
    );
    let proxy_port = get_port();

    let (twig, server) = proxy.bind(("127.0.0.1", proxy_port)).await.unwrap();

    tokio::spawn(server);

    let client_builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).unwrap());

    let client = if !without_cert {
        client_builder
            .add_root_certificate(reqwest::Certificate::from_der(&root_cert_der).unwrap())
            .build()
            .unwrap()
    } else {
        client_builder
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    };

    Setup {
        _proxy_port: proxy_port,
        server_port,
        proxy: twig.boxed(),
        client,
    }
}

async fn read_body(
    body: &mut UnboundedReceiver<Result<Frame<Bytes>, Arc<hyper::Error>>>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    while let Some(frame) = body.next().await {
        if let Ok(frame) = frame {
            if let Some(data) = frame.data_ref() {
                buf.extend_from_slice(data);
            }
        }
    }
    buf
}

#[tokio::test]
async fn test_simple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("http://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    let uri = communication.request.uri().clone();
    let headers = communication.request.headers().clone();
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    assert_eq!(
        uri.to_string(),
        format!("http://127.0.0.1:{}/", setup.server_port)
    );
    assert_eq!(
        headers.get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );

    let body = read_body(communication.response.await.unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_modify_header() {
    let app = Router::new().route(
        "/",
        get(|header: HeaderMap| async move {
            header
                .get(header::USER_AGENT)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        }),
    );

    let mut setup = setup(app).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("http://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let mut communication = setup.proxy.next().await.unwrap();
    let uri = communication.request.uri().clone();
    let headers = communication.request.headers().clone();
    communication.request.headers_mut().insert(
        header::USER_AGENT,
        header::HeaderValue::from_static("MODIFIED"),
    );
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"MODIFIED");

    assert_eq!(
        uri.to_string(),
        format!("http://127.0.0.1:{}/", setup.server_port)
    );
    assert_eq!(
        headers.get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );

    let body = read_body(communication.response.await.unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "MODIFIED");
}

#[tokio::test]
async fn test_keep_alive() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app).await;

    // reqwest wii use single connection with keep-alive
    for _ in 0..16 {
        tokio::spawn(
            setup
                .client
                .get(format!("http://127.0.0.1:{}/", setup.server_port))
                .send(),
        );

        let communication = setup.proxy.next().await.unwrap();
        let uri = communication.request.uri().clone();
        let headers = communication.request.headers().clone();
        communication
            .request_back
            .send(communication.request)
            .unwrap();

        assert_eq!(
            uri.to_string(),
            format!("http://127.0.0.1:{}/", setup.server_port)
        );
        assert_eq!(
            headers.get(header::HOST).unwrap(),
            format!("127.0.0.1:{}", setup.server_port).as_bytes()
        );

        let body = read_body(communication.response.await.unwrap().body_mut()).await;
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
    tokio::spawn(
        setup
            .client
            .get(format!("http://127.0.0.1:{}/sse", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    communication
        .request_back
        .send(communication.request)
        .unwrap();
    let body = read_body(communication.response.await.unwrap().body_mut()).await;

    assert_eq!(
        body,
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"
    );
}

#[tokio::test]
async fn test_upgrade() {
    let app = Router::new().route("/upgrade", get(upgrade_handler));
    let mut setup = setup(app).await;

    let res = tokio::spawn(
        setup
            .client
            .get(format!("http://127.0.0.1:{}/upgrade", setup.server_port))
            .header(reqwest::header::UPGRADE, "raw")
            .header(reqwest::header::CONNECTION, "Upgrade")
            .send(),
    );

    let comm = setup.proxy.next().await.unwrap();
    comm.request_back.send(comm.request).unwrap();

    let mut stream = res.await.unwrap().unwrap().upgrade().await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);

    let upgrade = comm.upgrade.await.unwrap();

    assert_eq!(upgrade.server_to_client.concat().await, b"ping");
    assert_eq!(upgrade.client_to_server.concat().await, b"pong");
}

async fn upgrade_handler<B: Send + 'static>(req: axum::http::Request<B>) -> impl IntoResponse {
    tokio::spawn(async move {
        let socket = hyper::upgrade::on(req).await.unwrap();
        let mut socket = TokioIo::new(socket);

        socket.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    });

    axum::http::Response::builder()
        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
        .body(http_body_util::Empty::new())
        .unwrap()
}

#[tokio::test]
async fn test_tls_simple() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send(),
    );
    let communication = setup.proxy.next().await.unwrap();
    let uri = communication.request.uri().clone();
    let headers = communication.request.headers().clone();
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    assert_eq!(
        uri.to_string(),
        format!("https://127.0.0.1:{}/", setup.server_port)
    );
    assert_eq!(
        headers.get(header::HOST).unwrap(),
        format!("127.0.0.1:{}", setup.server_port).as_bytes()
    );

    let body = read_body(communication.response.await.unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_tls_simple_tunnel() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let setup: Setup<Incoming> = setup_tls(app, true).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let response = response.await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");
}

#[tokio::test]
async fn test_tls_keep_alive() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false).await;

    // reqwest wii use single connection with keep-alive
    for _ in 0..16 {
        tokio::spawn(
            setup
                .client
                .get(format!("https://127.0.0.1:{}/", setup.server_port))
                .send(),
        );

        let communication = setup.proxy.next().await.unwrap();
        let uri = communication.request.uri().clone();
        let headers = communication.request.headers().clone();
        communication
            .request_back
            .send(communication.request)
            .unwrap();

        assert_eq!(
            uri.to_string(),
            format!("https://127.0.0.1:{}/", setup.server_port)
        );
        assert_eq!(
            headers.get(header::HOST).unwrap(),
            format!("127.0.0.1:{}", setup.server_port).as_bytes()
        );

        let body = read_body(communication.response.await.unwrap().body_mut()).await;
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
    tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/sse", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    communication
        .request_back
        .send(communication.request)
        .unwrap();
    let body = read_body(communication.response.await.unwrap().body_mut()).await;

    assert_eq!(
        body,
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"
    );
}

#[tokio::test]
async fn test_tls_upgrade() {
    let app = Router::new().route("/upgrade", get(upgrade_handler));
    let mut setup = setup_tls(app, false).await;

    let res = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/upgrade", setup.server_port))
            .header(reqwest::header::UPGRADE, "raw")
            .header(reqwest::header::CONNECTION, "Upgrade")
            .send(),
    );

    let comm = setup.proxy.next().await.unwrap();
    comm.request_back.send(comm.request).unwrap();

    let res = res.await.unwrap().unwrap();
    let mut stream = res.upgrade().await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    stream.write_all(b"pong").await.unwrap();
    drop(stream);

    let upgrade = comm.upgrade.await.unwrap();

    assert_eq!(upgrade.server_to_client.concat().await, b"ping");
    assert_eq!(upgrade.client_to_server.concat().await, b"pong");
}
