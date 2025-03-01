use std::path::PathBuf;

use axum::{routing::get, Router};
use bytes::Bytes;
use clap::{Args, Parser};
use http_body_util::{BodyExt, Full};
use http_mitm_proxy::{
    hyper::{service::service_fn, Response},
    moka::sync::Cache,
    DefaultClient, MitmProxy,
};

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
        Some(Cache::new(128)),
    );

    let client = DefaultClient::new();
    let proxy = proxy
        .bind(
            ("127.0.0.1", 3003),
            service_fn(move |mut req| {
                let client = client.clone();
                async move {
                    // Forward connection from http/https dev.example to http://127.0.0.1:3333
                    if req.uri().host() == Some("dev.example") {
                        // Return a response created by the proxy
                        if req.uri().path() == "/test.json" {
                            let res = Response::builder()
                                .header(hyper::header::CONTENT_TYPE, "application/json")
                                .body(
                                    Full::new(Bytes::from("{data: 123}"))
                                        .map_err(|e| match e {})
                                        .boxed(),
                                )
                                .unwrap();
                            return Ok(res);
                        }

                        req.headers_mut().insert(
                            hyper::header::HOST,
                            hyper::header::HeaderValue::from_maybe_shared(format!(
                                "127.0.0.1:{}",
                                port
                            ))
                            .unwrap(),
                        );

                        let mut parts = req.uri().clone().into_parts();
                        parts.scheme = Some(hyper::http::uri::Scheme::HTTP);
                        parts.authority = Some(
                            hyper::http::uri::Authority::from_maybe_shared(format!(
                                "127.0.0.1:{}",
                                port
                            ))
                            .unwrap(),
                        );
                        *req.uri_mut() = hyper::Uri::from_parts(parts).unwrap();
                    }

                    let (res, _upgrade) = client.send_request(req).await?;

                    Ok::<_, http_mitm_proxy::default_client::Error>(res.map(|b| b.boxed()))
                }
            }),
        )
        .await
        .unwrap();

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

    proxy.await;
}
