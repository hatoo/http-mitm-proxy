use std::{borrow::BorrowMut, sync::LazyLock};

use dashmap::{try_result::TryResult, DashMap};
use rustls::ServerConfig;

static SERVER_CONFIG_CACHE: LazyLock<DashMap<(String, Vec<u8>), rustls::ServerConfig>> = LazyLock::new(|| DashMap::new());

pub fn server_config(
    host: String,
    root_cert: &rcgen::CertifiedKey,
    h2: bool,
) -> Result<rustls::ServerConfig, rustls::Error> {

    if let TryResult::Present(config) = SERVER_CONFIG_CACHE.try_get(&(host.clone(), root_cert.key_pair.serialize_der())) {
        let mut config = config.clone();
        return Ok(maybe_h2_config(&mut config, h2).to_owned());
    }

    let mut cert_params = rcgen::CertificateParams::new(vec![host.clone()]).unwrap();
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

    let private_key = rcgen::KeyPair::generate().unwrap();

    let cert = cert_params
        .signed_by(&private_key, &root_cert.cert, &root_cert.key_pair)
        .unwrap();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                private_key.serialize_der(),
            )),
        );

    if let Ok(config) = &config {
        SERVER_CONFIG_CACHE.insert((host, root_cert.key_pair.serialize_der()), config.clone());
    }

    config.map(|mut config| maybe_h2_config(config.borrow_mut(), h2).to_owned())
}

fn maybe_h2_config(config: &mut ServerConfig, h2: bool) -> &ServerConfig {
    if h2 {
        config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
        config
    } else {
        config
    }
}
