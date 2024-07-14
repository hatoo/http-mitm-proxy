use std::{
    convert::Infallible,
    sync::{atomic::AtomicU16, Arc},
};

use axum::{
    extract::Request,
    response::{sse::Event, Sse},
    routing::get,
    Router,
};
use futures::stream;
use http_mitm_proxy::{DefaultClient, MitmProxy};

static PORT: AtomicU16 = AtomicU16::new(3666);

fn get_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn root_cert() -> rcgen::CertifiedKey {
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

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = param.self_signed(&key_pair).unwrap();

    rcgen::CertifiedKey { cert, key_pair }
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

fn client(proxy_port: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn proxy_client() -> Arc<DefaultClient> {
    Arc::new(DefaultClient::new(
        tokio_native_tls::native_tls::TlsConnector::builder()
            .request_alpns(&["h2", "http/1.1"])
            .build()
            .unwrap(),
    ))
}

#[tokio::test]
async fn test_simple_http() {
    let proxy = MitmProxy::new(Some(root_cert()));
    let proxy_port = get_port();

    const BODY: &str = "Hello, World!";
    let app = Router::new().route("/", get(|| async move { BODY }));

    let (port, server) = bind_app(app).await;
    tokio::spawn(server);

    let proxy_client = proxy_client();
    let proxy = proxy
        .bind(("127.0.0.1", proxy_port), move |req| {
            let proxy_client = proxy_client.clone();
            async move { proxy_client.send_request(req).await.map(|t| t.0) }
        })
        .await
        .unwrap();

    tokio::spawn(proxy);

    let client = client(proxy_port);

    let res = client
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), BODY);
}

#[tokio::test]
async fn test_modify_http() {
    let proxy = MitmProxy::new(Some(root_cert()));
    let proxy_port = get_port();

    let app = Router::new().route(
        "/",
        get(|req: Request| async move {
            req.headers()
                .get("X-test")
                .map(|v| v.to_str().unwrap())
                .unwrap_or("none")
                .to_string()
        }),
    );

    let (port, server) = bind_app(app).await;
    tokio::spawn(server);

    let proxy_client = proxy_client();
    let proxy = proxy
        .bind(("127.0.0.1", proxy_port), move |mut req| {
            let proxy_client = proxy_client.clone();
            async move {
                req.headers_mut()
                    .insert("X-test", "modified".parse().unwrap());
                proxy_client.send_request(req).await.map(|t| t.0)
            }
        })
        .await
        .unwrap();

    tokio::spawn(proxy);

    let client = client(proxy_port);

    let res = client
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "modified");
}

#[tokio::test]
async fn test_sse_http() {
    let app = Router::new().route(
        "/sse",
        get(|| async {
            Sse::new(stream::iter(["1", "2", "3"].into_iter().map(|s| {
                Ok::<Event, Infallible>(Event::default().event("message").data(s))
            })))
        }),
    );

    let (port, server) = bind_app(app).await;
    tokio::spawn(server);

    let proxy = MitmProxy::new(Some(root_cert()));
    let proxy_port = get_port();
    let proxy_client = proxy_client();
    let proxy = proxy
        .bind(("127.0.0.1", proxy_port), move |req| {
            let proxy_client = proxy_client.clone();
            async move { proxy_client.send_request(req).await.map(|t| t.0) }
        })
        .await
        .unwrap();
    tokio::spawn(proxy);

    let client = client(proxy_port);
    let res = client
        .get(format!("http://127.0.0.1:{}/sse", port))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.bytes().await.unwrap(),
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"[..]
    );
}

/*
use std::{
    convert::Infallible,
    sync::{atomic::AtomicU16, Arc},
};

use axum::{
    extract::Request,
    http::HeaderValue,
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
use rustls21::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_test::traced_test;

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

async fn bind_app_tls(app: Router, h2: bool) -> (u16, impl std::future::Future<Output = ()>) {
    let port = get_port();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();

    (port, async move {
        axum_server::from_tcp_rustls(
            listener.into_std().unwrap(),
            RustlsConfig::from_config(tls_server_config(format!("127.0.0.1:{}", port), h2)),
        )
        .serve(app.into_make_service())
        .await
        .unwrap()
    })
}

fn tls_server_config(host: String, h2: bool) -> Arc<ServerConfig> {
    let cert = generate_simple_self_signed(vec![host]).unwrap();

    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls21::Certificate(cert.cert.der().to_vec())],
            rustls21::PrivateKey(cert.key_pair.serialize_der()),
        )
        .unwrap();

    if h2 {
        server_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
    }

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

async fn setup<B>(app: Router, https_server: bool) -> Setup<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let server_port = if https_server {
        let (p, s) = bind_app_tls(app, true).await;
        tokio::spawn(s);
        p
    } else {
        let (p, s) = bind_app(app).await;
        tokio::spawn(s);
        p
    };

    let proxy = http_mitm_proxy::MitmProxy::<&'static rcgen::CertifiedKey>::new(
        None,
        tokio_native_tls::native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap(),
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

fn root_cert() -> rcgen::CertifiedKey {
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

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = param.self_signed(&key_pair).unwrap();

    rcgen::CertifiedKey { cert, key_pair }
}

async fn setup_tls<B>(app: Router, without_cert: bool, http_server: bool, h2: bool) -> Setup<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let server_port = if http_server {
        let (p, s) = bind_app(app).await;
        tokio::spawn(s);
        p
    } else {
        let (p, s) = bind_app_tls(app, h2).await;
        tokio::spawn(s);
        p
    };

    let root_cert = root_cert();
    let root_cert_der = root_cert.cert.der().to_vec();

    let proxy = http_mitm_proxy::MitmProxy::new(
        if without_cert { None } else { Some(root_cert) },
        tokio_native_tls::native_tls::TlsConnector::builder()
            .request_alpns(&["h2", "http/1.1"])
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
#[traced_test]
async fn test_simple() {
    let app = Router::new().route(
        "/",
        get(|req: Request| async move {
            assert_eq!(req.version(), hyper::http::Version::HTTP_11);
            "Hello, World!"
        }),
    );

    let mut setup = setup(app, false).await;

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

    assert_eq!(response.version(), hyper::http::Version::HTTP_11);
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

    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
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

    let mut setup = setup(app, false).await;

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

    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "MODIFIED");
}
#[tokio::test]
async fn test_modify_url_http_to_http() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app, false).await;

    let response = tokio::spawn(setup.client.get("http://example.com/").send());

    let mut comm = setup.proxy.next().await.unwrap();

    assert_eq!(comm.request.uri().to_string(), "http://example.com/");

    *comm.request.uri_mut() = format!("http://127.0.0.1:{}/", setup.server_port)
        .parse()
        .unwrap();

    comm.request_back.send(comm.request).unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let body = read_body(comm.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_modify_url_http_to_https() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app, true).await;

    let response = tokio::spawn(setup.client.get("http://example.com/").send());

    let mut comm = setup.proxy.next().await.unwrap();

    assert_eq!(comm.request.uri().to_string(), "http://example.com/");

    *comm.request.uri_mut() = format!("https://127.0.0.1:{}/", setup.server_port)
        .parse()
        .unwrap();

    comm.request_back.send(comm.request).unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let body = read_body(comm.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_keep_alive() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup(app, false).await;

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

        let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
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

    let mut setup = setup(app, false).await;
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
    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;

    assert_eq!(
        body,
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"
    );
}

#[tokio::test]
async fn test_upgrade() {
    let app = Router::new().route("/upgrade", get(upgrade_handler));
    let mut setup = setup(app, false).await;

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
#[traced_test]
async fn test_tls_simple() {
    let app = Router::new().route(
        "/",
        get(|req: Request| async move {
            assert_eq!(req.version(), hyper::http::Version::HTTP_2);
            "Hello, World!"
        }),
    );

    let mut setup = setup_tls(app, false, false, true).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    assert_eq!(communication.request.method(), hyper::Method::CONNECT);
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let communication = setup.proxy.next().await.unwrap();
    let uri = communication.request.uri().clone();
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.version(), hyper::http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    assert_eq!(
        uri.to_string(),
        format!("https://127.0.0.1:{}/", setup.server_port)
    );

    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
#[traced_test]
async fn test_tls_match_http_version() {
    let app = Router::new().route(
        "/",
        get(|req: Request| async move {
            assert_eq!(req.version(), hyper::http::Version::HTTP_11);
            "Hello, World!"
        }),
    );

    let mut setup = setup_tls(app, false, false, false).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    assert_eq!(communication.request.method(), hyper::Method::CONNECT);
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let communication = setup.proxy.next().await.unwrap();
    let uri = communication.request.uri().clone();
    let headers = communication.request.headers().clone();
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.version(), hyper::http::Version::HTTP_11);
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

    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
#[traced_test]
async fn test_tls_modify_url_https_to_https() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false, false, true).await;

    let response = tokio::spawn(setup.client.get("https://example.com/").send());

    let comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.method(), hyper::Method::CONNECT);
    assert_eq!(comm.request.uri().to_string(), "example.com:443");
    comm.request_back.send(comm.request).unwrap();

    let mut comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.uri().to_string(), "https://example.com/");
    *comm.request.uri_mut() = format!("https://127.0.0.1:{}/", setup.server_port)
        .parse()
        .unwrap();
    // But the HOST header will still be the original one because a client doesn't know the modified URL.
    comm.request.headers_mut().insert(
        header::HOST,
        HeaderValue::from_bytes(format!("127.0.0.1:{}", setup.server_port).as_bytes()).unwrap(),
    );
    comm.request_back.send(comm.request).unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let body = read_body(comm.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_tls_modify_url_https_to_http() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false, true, true).await;

    let response = tokio::spawn(setup.client.get("https://example.com/").send());

    let comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.method(), hyper::Method::CONNECT);
    assert_eq!(comm.request.uri().to_string(), "example.com:443");
    comm.request_back.send(comm.request).unwrap();

    let mut comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.uri().to_string(), "https://example.com/");
    *comm.request.uri_mut() = format!("http://127.0.0.1:{}/", setup.server_port)
        .parse()
        .unwrap();
    // But the HOST header will still be the original one because a client doesn't know the modified URL.
    comm.request.headers_mut().insert(
        header::HOST,
        HeaderValue::from_bytes(format!("127.0.0.1:{}", setup.server_port).as_bytes()).unwrap(),
    );
    comm.request_back.send(comm.request).unwrap();

    let response = response.await.unwrap().unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");

    let body = read_body(comm.response.await.unwrap().unwrap().body_mut()).await;
    assert_eq!(String::from_utf8(body).unwrap(), "Hello, World!");
}

#[tokio::test]
async fn test_tls_simple_tunnel() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup: Setup<Incoming> = setup_tls(app, true, false, true).await;

    let response = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/", setup.server_port))
            .send(),
    );

    let comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.method(), hyper::Method::CONNECT);
    comm.request_back.send(comm.request).unwrap();

    let response = response.await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"Hello, World!");
}

#[tokio::test]
async fn test_tls_keep_alive() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let mut setup = setup_tls(app, false, false, false).await;

    let client = setup.client.clone();

    tokio::spawn(async move {
        for _ in 0..16 {
            let res = client
                .get(format!("https://127.0.0.1:{}/", setup.server_port))
                .send()
                .await
                .unwrap();

            assert_eq!(res.bytes().await.unwrap(), &b"Hello, World!"[..]);
        }
    });

    // reqwest wii use single connection with keep-alive
    for i in 0..16 {
        if i == 0 {
            let communication = setup.proxy.next().await.unwrap();
            assert_eq!(communication.request.method(), hyper::Method::CONNECT);
            communication
                .request_back
                .send(communication.request)
                .unwrap();
        }

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

        let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;
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

    let mut setup = setup_tls(app, false, false, true).await;
    tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/sse", setup.server_port))
            .send(),
    );

    let communication = setup.proxy.next().await.unwrap();
    assert_eq!(communication.request.method(), hyper::Method::CONNECT);
    communication
        .request_back
        .send(communication.request)
        .unwrap();

    let communication = setup.proxy.next().await.unwrap();
    communication
        .request_back
        .send(communication.request)
        .unwrap();
    let body = read_body(communication.response.await.unwrap().unwrap().body_mut()).await;

    assert_eq!(
        body,
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"
    );
}

#[tokio::test]
#[traced_test]
async fn test_tls_upgrade() {
    let app = Router::new().route("/upgrade", get(upgrade_handler));
    let mut setup = setup_tls(app, false, false, false).await;

    let res = tokio::spawn(
        setup
            .client
            .get(format!("https://127.0.0.1:{}/upgrade", setup.server_port))
            .header(reqwest::header::UPGRADE, "raw")
            .header(reqwest::header::CONNECTION, "Upgrade")
            .send(),
    );

    let comm = setup.proxy.next().await.unwrap();
    assert_eq!(comm.request.method(), hyper::Method::CONNECT);
    comm.request_back.send(comm.request).unwrap();

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

*/
