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
        .bind(("127.0.0.1", proxy_port), move |_, req| {
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
        .bind(("127.0.0.1", proxy_port), move |_, mut req| {
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
        .bind(("127.0.0.1", proxy_port), move |_, req| {
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
