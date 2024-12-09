use std::{path::PathBuf, sync::Arc};

use clap::{Args, Parser};
use http_mitm_proxy::{DefaultClient, MitmProxy};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use moka::sync::Cache;
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{self, pki_types::PrivatePkcs8KeyDer, ServerConfig},
    TlsAcceptor,
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
        .with_line_number(true)
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

    // Reusing the same root cert for proxy server
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![root_cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                root_cert.key_pair.serialize_der(),
            )),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    let proxy = MitmProxy::new(
        // This is the root cert that will be used to sign the fake certificates
        Some(root_cert),
        Some(Cache::new(128)),
    );
    let proxy = Arc::new(proxy);

    let client = DefaultClient::new().unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 3003)).await.unwrap();

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server = async move {
        loop {
            let (stream, _client_addr) = listener.accept().await.unwrap();
            let proxy = proxy.clone();
            let client = client.clone();
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                let client = client.clone();
                let service = MitmProxy::wrap_service(
                    proxy.clone(),
                    service_fn(move |req| {
                        let client = client.clone();
                        async move {
                            let uri = req.uri().clone();

                            // You can modify request here
                            // or You can just return response anywhere

                            let (res, _upgrade) = client.send_request(req).await?;

                            println!("{} -> {}", uri, res.status());

                            // You can modify response here

                            Ok::<_, http_mitm_proxy::default_client::Error>(res)
                        }
                    }),
                );

                let stream = tls_acceptor.accept(stream).await.unwrap();

                if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                    // HTTP/2
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .unwrap();
                } else {
                    // HTTP/1.1
                    hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades()
                        .await
                        .unwrap();
                }
            });
        }
    };

    println!("HTTPS Proxy is listening on https://127.0.0.1:3003");

    println!();
    println!("Trust this cert if you want to use HTTPS");
    println!();
    println!("{}", root_cert_pem);
    println!();

    /*
        You can test HTTPS proxy with curl like this:
        curl -x https://localhost:3003 https://example.com --insecure --proxy-insecure
    */

    println!("Private key");
    println!("{}", root_cert_key);

    server.await;
}
