# http-mitm-proxy

[![Crates.io](https://img.shields.io/crates/v/http-mitm-proxy.svg)](https://crates.io/crates/http-mitm-proxy)

A HTTP proxy server library intended to be a backend of application like Burp proxy.

- Sniff HTTP and HTTPS traffic by signing certificate on the fly.
- Server Sent Event
- WebSocket ("raw" traffic only. Parsers will not be implemented in this crate.)

## Usage

```rust, no_run
use std::path::PathBuf;

use clap::{Args, Parser};
use futures::StreamExt;
use http_mitm_proxy::{
    default_client::{websocket, Upgrade},
    DefaultClient, MitmProxy,
};
use moka::sync::Cache;
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

    let client = DefaultClient::new().unwrap();
    let server = proxy
        .bind(("127.0.0.1", 3003), move |_client_addr, req| {
            let client = client.clone();
            async move {
                let uri = req.uri().clone();

                // You can modify request here
                // or You can just return response anywhere

                let (res, upgrade) = client.send_request(req).await?;

                // println!("{} -> {}", uri, res.status());
                if let Some(upgrade) = upgrade {
                    // If the response is an upgrade, e.g. Websocket, you can see traffic.
                    // Modifying upgraded traffic is not supported yet.

                    // You can try https://echo.websocket.org/.ws to test websocket.
                    println!("Upgrade connection");
                    let Upgrade {
                        mut client_to_server,
                        mut server_to_client,
                    } = upgrade;
                    let url = uri.to_string();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        while let Some(data) = client_to_server.next().await {
                            buf.extend(data);
                            loop {
                                let input = &mut buf.as_slice();
                                if let Ok(frame) = websocket::frame(input) {
                                    println!(
                                        "Client -> Server: {} {:?}",
                                        url,
                                        String::from_utf8_lossy(&frame.payload_data)
                                    );
                                    buf = input.to_vec();
                                } else {
                                    break;
                                }
                            }
                        }
                    });
                    let url = uri.to_string();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        while let Some(data) = server_to_client.next().await {
                            buf.extend(data);
                            loop {
                                let input = &mut buf.as_slice();
                                if let Ok(frame) = websocket::frame(input) {
                                    println!(
                                        "Server -> Client: {} {:?}",
                                        url,
                                        String::from_utf8_lossy(&frame.payload_data)
                                    );
                                    buf = input.to_vec();
                                } else {
                                    break;
                                }
                            }
                        }
                    });
                }

                // You can modify response here

                Ok::<_, http_mitm_proxy::default_client::Error>(res)
            }
        })
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
```
