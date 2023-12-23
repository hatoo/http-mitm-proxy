pub fn server_config(
    host: String,
    root_cert: &rcgen::Certificate,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut cert_params = rcgen::CertificateParams::new(vec![host]);
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

    let cert = rcgen::Certificate::from_params(cert_params).unwrap();
    let signed = cert.serialize_der_with_signer(root_cert).unwrap();
    let private_key = cert.get_key_pair().serialize_der();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(signed)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                private_key,
            )),
        )
}
