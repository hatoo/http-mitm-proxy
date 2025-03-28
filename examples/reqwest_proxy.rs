/// This example demonstrates how to use `http-mitm-proxy` with `reqwest`.
use std::path::PathBuf;

use bytes::Bytes;
use clap::{Args, Parser};
use http_mitm_proxy::{
    MitmProxy,
    hyper::{body::Body, service::service_fn},
    moka::sync::Cache,
};
use tracing_subscriber::EnvFilter;

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

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

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

    let client = reqwest::Client::new();
    let server = proxy
        .bind(
            ("127.0.0.1", 3003),
            service_fn(move |req| {
                let client = client.clone();
                async move {
                    let uri = req.uri().clone();

                    // You can modify request here
                    // or You can just return response anywhere

                    let req = to_reqwest(req);
                    let res = client.execute(req).await?;

                    println!("{} -> {}", uri, res.status());

                    // You can modify response here

                    Ok::<_, reqwest::Error>(from_reqwest(res))
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

    server.await;
}

fn to_reqwest<T>(req: hyper::Request<T>) -> reqwest::Request
where
    T: Body + Send + Sync + 'static,
    T::Data: Into<Bytes>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();
    let url = reqwest::Url::parse(&parts.uri.to_string()).unwrap();
    let mut req = reqwest::Request::new(parts.method, url);
    *req.headers_mut() = parts.headers;
    req.body_mut().replace(reqwest::Body::wrap(body));
    *req.version_mut() = parts.version;

    req
}

fn from_reqwest(res: reqwest::Response) -> hyper::Response<reqwest::Body> {
    let mut hres = hyper::Response::builder()
        .status(res.status())
        .version(res.version());

    *hres.headers_mut().unwrap() = res.headers().clone();

    let body = reqwest::Body::from(res);

    hres.body(body).unwrap()
}
