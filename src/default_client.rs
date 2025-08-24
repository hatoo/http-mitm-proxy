#![cfg(any(feature = "native-tls-client", feature = "rustls-client"))]

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{
    Request, Response, StatusCode, Uri, Version,
    body::{Body, Incoming},
    client, header,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::task::{Context, Poll};
use tokio::{net::TcpStream, task::JoinHandle};

#[cfg(all(feature = "native-tls-client", feature = "rustls-client"))]
compile_error!(
    "feature \"native-tls-client\" and feature \"rustls-client\" cannot be enabled at the same time"
);

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} doesn't have an valid host")]
    InvalidHost(Box<Uri>),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error("Failed to connect to {0}, {1}")]
    ConnectError(Box<Uri>, hyper::Error),

    #[cfg(feature = "native-tls-client")]
    #[error("Failed to connect with TLS to {0}, {1}")]
    TlsConnectError(Box<Uri>, native_tls::Error),
    #[cfg(feature = "native-tls-client")]
    #[error(transparent)]
    NativeTlsError(#[from] tokio_native_tls::native_tls::Error),

    #[cfg(feature = "rustls-client")]
    #[error("Failed to connect with TLS to {0}, {1}")]
    TlsConnectError(Box<Uri>, std::io::Error),

    #[error("Failed to parse URI: {0}")]
    UriParsingError(#[from] hyper::http::uri::InvalidUri),

    #[error("Failed to parse URI parts: {0}")]
    UriPartsError(#[from] hyper::http::uri::InvalidUriParts),

    #[error("TLS connector initialization failed: {0}")]
    TlsConnectorError(String),
}

/// Upgraded connections
pub struct Upgraded {
    /// A socket to Client
    pub client: TokioIo<hyper::upgrade::Upgraded>,
    /// A socket to Server
    pub server: TokioIo<hyper::upgrade::Upgraded>,
}
#[derive(Clone)]
/// Default HTTP client for this crate
pub struct DefaultClient {
    #[cfg(feature = "native-tls-client")]
    tls_connector_no_alpn: tokio_native_tls::TlsConnector,
    #[cfg(feature = "native-tls-client")]
    tls_connector_alpn_h2: tokio_native_tls::TlsConnector,

    #[cfg(feature = "rustls-client")]
    tls_connector_no_alpn: tokio_rustls::TlsConnector,
    #[cfg(feature = "rustls-client")]
    tls_connector_alpn_h2: tokio_rustls::TlsConnector,

    /// If true, send_request will returns an Upgraded struct when the response is an upgrade
    /// If false, send_request never returns an Upgraded struct and just copy bidirectional when the response is an upgrade
    pub with_upgrades: bool,
}
impl Default for DefaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultClient {
    #[cfg(feature = "native-tls-client")]
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|err| {
            panic!("Failed to create DefaultClient: {err}");
        })
    }

    #[cfg(feature = "native-tls-client")]
    pub fn try_new() -> Result<Self, Error> {
        let tls_connector_no_alpn = native_tls::TlsConnector::builder().build().map_err(|e| {
            Error::TlsConnectorError(format!("Failed to build no-ALPN connector: {e}"))
        })?;
        let tls_connector_alpn_h2 = native_tls::TlsConnector::builder()
            .request_alpns(&["h2", "http/1.1"])
            .build()
            .map_err(|e| {
                Error::TlsConnectorError(format!("Failed to build ALPN-H2 connector: {e}"))
            })?;

        Ok(Self {
            tls_connector_no_alpn: tokio_native_tls::TlsConnector::from(tls_connector_no_alpn),
            tls_connector_alpn_h2: tokio_native_tls::TlsConnector::from(tls_connector_alpn_h2),
            with_upgrades: false,
        })
    }

    #[cfg(feature = "rustls-client")]
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|err| {
            panic!("Failed to create DefaultClient: {}", err);
        })
    }

    #[cfg(feature = "rustls-client")]
    pub fn try_new() -> Result<Self, Error> {
        use std::sync::Arc;

        let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_connector_no_alpn = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store.clone())
            .with_no_client_auth();
        let mut tls_connector_alpn_h2 = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store.clone())
            .with_no_client_auth();
        tls_connector_alpn_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            tls_connector_no_alpn: tokio_rustls::TlsConnector::from(Arc::new(
                tls_connector_no_alpn,
            )),
            tls_connector_alpn_h2: tokio_rustls::TlsConnector::from(Arc::new(
                tls_connector_alpn_h2,
            )),
            with_upgrades: false,
        })
    }

    /// Enable HTTP upgrades
    /// If you don't enable HTTP upgrades, send_request will just copy bidirectional when the response is an upgrade
    pub fn with_upgrades(mut self) -> Self {
        self.with_upgrades = true;
        self
    }

    #[cfg(feature = "native-tls-client")]
    fn tls_connector(&self, http_version: Version) -> &tokio_native_tls::TlsConnector {
        match http_version {
            Version::HTTP_2 => &self.tls_connector_alpn_h2,
            _ => &self.tls_connector_no_alpn,
        }
    }

    #[cfg(feature = "rustls-client")]
    fn tls_connector(&self, http_version: Version) -> &tokio_rustls::TlsConnector {
        match http_version {
            Version::HTTP_2 => &self.tls_connector_alpn_h2,
            _ => &self.tls_connector_no_alpn,
        }
    }

    /// Send a request and return a response.
    /// If the response is an upgrade (= if status code is 101 Switching Protocols), it will return a response and an Upgrade struct.
    /// Request should have a full URL including scheme.
    pub async fn send_request<B>(
        &self,
        req: Request<B>,
    ) -> Result<
        (
            Response<Incoming>,
            Option<JoinHandle<Result<Upgraded, hyper::Error>>>,
        ),
        Error,
    >
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let mut send_request = self.connect(req.uri(), req.version()).await?;

        let (req_parts, req_body) = req.into_parts();

        let res = send_request
            .send_request(Request::from_parts(req_parts.clone(), req_body))
            .await?;

        if res.status() == StatusCode::SWITCHING_PROTOCOLS {
            let (res_parts, res_body) = res.into_parts();

            let client_request = Request::from_parts(req_parts, Empty::<Bytes>::new());
            let server_response = Response::from_parts(res_parts.clone(), Empty::<Bytes>::new());

            let upgrade = if self.with_upgrades {
                Some(tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    Ok(Upgraded {
                        client: TokioIo::new(client),
                        server: TokioIo::new(server),
                    })
                }))
            } else {
                tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    let _ = tokio::io::copy_bidirectional(
                        &mut TokioIo::new(client),
                        &mut TokioIo::new(server),
                    )
                    .await;

                    Ok::<_, hyper::Error>(())
                });
                None
            };

            Ok((Response::from_parts(res_parts, res_body), upgrade))
        } else {
            Ok((res, None))
        }
    }

    async fn connect<B>(&self, uri: &Uri, http_version: Version) -> Result<SendRequest<B>, Error>
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let host = uri
            .host()
            .ok_or_else(|| Error::InvalidHost(Box::new(uri.clone())))?;
        let port =
            uri.port_u16()
                .unwrap_or(if uri.scheme() == Some(&hyper::http::uri::Scheme::HTTPS) {
                    443
                } else {
                    80
                });

        let tcp = TcpStream::connect((host, port)).await?;
        // This is actually needed to some servers
        let _ = tcp.set_nodelay(true);

        if uri.scheme() == Some(&hyper::http::uri::Scheme::HTTPS) {
            #[cfg(feature = "native-tls-client")]
            let tls = self
                .tls_connector(http_version)
                .connect(host, tcp)
                .await
                .map_err(|err| Error::TlsConnectError(Box::new(uri.clone()), err))?;
            #[cfg(feature = "rustls-client")]
            let tls = self
                .tls_connector(http_version)
                .connect(
                    host.to_string()
                        .try_into()
                        .map_err(|_| Error::InvalidHost(Box::new(uri.clone())))?,
                    tcp,
                )
                .await
                .map_err(|err| Error::TlsConnectError(Box::new(uri.clone()), err))?;

            #[cfg(feature = "native-tls-client")]
            let is_h2 = matches!(
                tls.get_ref()
                    .negotiated_alpn()
                    .map(|a| a.map(|b| b == b"h2")),
                Ok(Some(true))
            );

            #[cfg(feature = "rustls-client")]
            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");

            if is_h2 {
                let (sender, conn) = client::conn::http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;

                tokio::spawn(conn);

                Ok(SendRequest::Http2(sender))
            } else {
                let (sender, conn) = client::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;

                tokio::spawn(conn.with_upgrades());

                Ok(SendRequest::Http1(sender))
            }
        } else {
            let (sender, conn) = client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(tcp))
                .await
                .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;
            tokio::spawn(conn.with_upgrades());
            Ok(SendRequest::Http1(sender))
        }
    }
}

enum SendRequest<B> {
    Http1(hyper::client::conn::http1::SendRequest<B>),
    Http2(hyper::client::conn::http2::SendRequest<B>),
}

impl<B> SendRequest<B>
where
    B: Body + 'static,
{
    async fn send_request(
        &mut self,
        mut req: Request<B>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            SendRequest::Http1(sender) => {
                if req.version() == hyper::Version::HTTP_2
                    && let Some(authority) = req.uri().authority().cloned()
                {
                    match authority.as_str().parse::<header::HeaderValue>() {
                        Ok(host_value) => {
                            req.headers_mut().insert(header::HOST, host_value);
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to parse authority '{}' as HOST header: {}",
                                authority,
                                err
                            );
                        }
                    }
                }
                if let Err(err) = remove_authority(&mut req) {
                    tracing::error!("Failed to remove authority from URI: {}", err);
                    // Continue with the original request if URI modification fails
                }
                sender.send_request(req).await
            }
            SendRequest::Http2(sender) => {
                if req.version() != hyper::Version::HTTP_2 {
                    req.headers_mut().remove(header::HOST);
                }
                sender.send_request(req).await
            }
        }
    }
}

impl<B> SendRequest<B> {
    #[allow(dead_code)]
    // TODO: connection pooling
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        match self {
            SendRequest::Http1(sender) => sender.poll_ready(cx),
            SendRequest::Http2(sender) => sender.poll_ready(cx),
        }
    }
}

fn remove_authority<B>(req: &mut Request<B>) -> Result<(), hyper::http::uri::InvalidUriParts> {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts)?;
    Ok(())
}
