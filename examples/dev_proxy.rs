use std::path::PathBuf;

use axum::{routing::get, Router};
use clap::{Args, Parser};
use futures::StreamExt;
use http_mitm_proxy::MitmProxy;

#[derive(Parser)]
struct Opt {
    #[clap(flatten)]
    external_cert: Option<ExternalCert>,
}

#[derive(Args, Debug)]
struct ExternalCert {
    #[arg(required = false)]
    cert: PathBuf,
    #[arg(required = false)]
    private_key: PathBuf,
}

fn make_root_cert() -> rcgen::CertifiedKey {
    let mut param = rcgen::CertificateParams::default();

    param.distinguished_name = rcgen::DistinguishedName::new();
    param.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
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

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    let port = 3333;

    let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async { axum::serve(listener, app).await });

    let root_cert = if let Some(external_cert) = opt.external_cert {
        // Use existing key
        let param = rcgen::CertificateParams::from_ca_cert_pem(
            &std::fs::read_to_string(&external_cert.cert).unwrap(),
        )
        .unwrap();
        let key_pair =
            rcgen::KeyPair::from_pem(&std::fs::read_to_string(&external_cert.private_key).unwrap())
                .unwrap();

        let cert = param.self_signed(&key_pair).unwrap();

        rcgen::CertifiedKey { cert, key_pair }
    } else {
        make_root_cert()
    };

    let root_cert_pem = root_cert.cert.pem();
    let root_cert_key = root_cert.key_pair.serialize_pem();

    let proxy = MitmProxy::new(
        // This is the root cert that will be used to sign the fake certificates
        Some(root_cert),
        // This is the connector that will be used to connect to the upstream server from proxy
        tokio_native_tls::native_tls::TlsConnector::builder()
            // You must set ALPN if you want to support HTTP/2
            .request_alpns(&["h2", "http/1.1"])
            .build()
            .unwrap(),
    );

    let (mut communications, server) = proxy.bind(("127.0.0.1", 3003)).await.unwrap();
    tokio::spawn(server);

    println!("HTTP Proxy is listening on http://127.0.0.1:3003");

    println!();
    println!("Trust this cert if you want to use HTTPS");
    println!();
    println!("{}", root_cert_pem);
    println!();

    /*
        Save this cert to ca.crt and use it with curl like this:
        curl https://www.google.com -x http://127.0.0.1:3003 --cacert ca.crt
    */

    println!("Private key");
    println!("{}", root_cert_key);

    while let Some(comm) = communications.next().await {
        let mut req = comm.request;

        let original_url = req.uri().clone();

        // Forward connection from http/https dev.example to http://127.0.0.1:3333
        if req.uri().host() == Some("dev.example") && req.method() != hyper::http::Method::CONNECT {
            req.headers_mut().insert(
                hyper::header::HOST,
                hyper::header::HeaderValue::from_maybe_shared(format!("127.0.0.1:{}", port))
                    .unwrap(),
            );

            let mut parts = req.uri().clone().into_parts();
            parts.scheme = Some(hyper::http::uri::Scheme::HTTP);
            parts.authority = Some(
                hyper::http::uri::Authority::from_maybe_shared(format!("127.0.0.1:{}", port))
                    .unwrap(),
            );
            *req.uri_mut() = hyper::Uri::from_parts(parts).unwrap();
        }

        let uri = req.uri().clone();

        let _ = comm.request_back.send(req);
        if let Ok(Ok(mut response)) = comm.response.await {
            tokio::spawn(async move {
                let mut len = 0;
                let body = response.body_mut();
                while let Some(frame) = body.next().await {
                    if let Ok(frame) = frame {
                        if let Some(data) = frame.data_ref() {
                            len += data.len();
                        }
                    }
                }
                println!(
                    "{}\t{} -> {}\t{}\t{}",
                    comm.client_addr,
                    original_url,
                    uri,
                    response.status(),
                    len
                );
            });
        }
    }
}
