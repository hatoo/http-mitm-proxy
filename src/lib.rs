#![doc = include_str!("../README.md")]

use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    server,
    service::{HttpService, service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use moka::sync::Cache;
use std::{borrow::Borrow, error::Error as StdError, future::Future, sync::Arc};
use tls::{CertifiedKeyDer, generate_cert};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls;

pub use futures;
pub use hyper;
pub use moka;

#[cfg(feature = "native-tls-client")]
pub use tokio_native_tls;

#[cfg(any(feature = "native-tls-client", feature = "rustls-client"))]
pub mod default_client;
mod tls;

#[cfg(any(feature = "native-tls-client", feature = "rustls-client"))]
pub use default_client::DefaultClient;

#[derive(Clone)]
/// The main struct to run proxy server
pub struct MitmProxy<I> {
    /// Root issuer to sign fake certificates. You may need to trust this issuer on client application to use HTTPS.
    ///
    /// If None, proxy will just tunnel HTTPS traffic and will not observe HTTPS traffic.
    pub root_issuer: Option<I>,
    /// Cache to store generated certificates. If None, cache will not be used.
    /// If root_issuer is None, cache will not be used.
    ///
    /// The key of cache is hostname.
    pub cert_cache: Option<Cache<String, CertifiedKeyDer>>,
}

impl<I> MitmProxy<I> {
    /// Create a new MitmProxy
    pub fn new(root_issuer: Option<I>, cache: Option<Cache<String, CertifiedKeyDer>>) -> Self {
        Self {
            root_issuer,
            cert_cache: cache,
        }
    }
}

impl<I> MitmProxy<I>
where
    I: Borrow<rcgen::Issuer<'static, rcgen::KeyPair>> + Send + Sync + 'static,
{
    /// Bind to a socket address and return a future that runs the proxy server.
    /// URL for requests that passed to service are full URL including scheme.
    pub async fn bind<A: ToSocketAddrs, S>(
        self,
        addr: A,
        service: S,
    ) -> Result<impl Future<Output = ()>, std::io::Error>
    where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        let listener = TcpListener::bind(addr).await?;

        let proxy = Arc::new(self);

        Ok(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!("Failed to accept connection: {}", err);
                        continue;
                    }
                };

                let service = service.clone();

                let proxy = proxy.clone();
                tokio::spawn(async move {
                    if let Err(err) = server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(
                            TokioIo::new(stream),
                            Self::wrap_service(proxy.clone(), service.clone()),
                        )
                        .with_upgrades()
                        .await
                    {
                        tracing::error!("Error in proxy: {}", err);
                    }
                });
            }
        })
    }

    /// Transform a service to a service that can be used in hyper server.
    /// URL for requests that passed to service are full URL including scheme.
    /// See `examples/https.rs` for usage.
    /// If you want to serve simple HTTP proxy server, you can use `bind` method instead.
    /// `bind` will call this method internally.
    pub fn wrap_service<S>(
        proxy: Arc<Self>,
        service: S,
    ) -> impl HttpService<
        Incoming,
        ResBody = BoxBody<<S::ResBody as Body>::Data, <S::ResBody as Body>::Error>,
        Future: Send,
    >
    where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        service_fn(move |req| {
            let proxy = proxy.clone();
            let mut service = service.clone();

            async move {
                if req.method() == Method::CONNECT {
                    // https
                    let Some(connect_authority) = req.uri().authority().cloned() else {
                        tracing::error!(
                            "Bad CONNECT request: {}, Reason: Invalid Authority",
                            req.uri()
                        );
                        return Ok(no_body(StatusCode::BAD_REQUEST)
                            .map(|b| b.boxed().map_err(|never| match never {}).boxed()));
                    };

                    tokio::spawn(async move {
                        let client = match hyper::upgrade::on(req).await {
                            Ok(client) => client,
                            Err(err) => {
                                tracing::error!(
                                    "Failed to upgrade CONNECT request for {}: {}",
                                    connect_authority,
                                    err
                                );
                                return;
                            }
                        };
                        if let Some(server_config) =
                            proxy.server_config(connect_authority.host().to_string(), true)
                        {
                            let server_config = match server_config {
                                Ok(server_config) => server_config,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to create server config for {}, {}",
                                        connect_authority.host(),
                                        err
                                    );
                                    return;
                                }
                            };
                            let server_config = Arc::new(server_config);
                            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                            let client = match tls_acceptor.accept(TokioIo::new(client)).await {
                                Ok(client) => client,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to accept TLS connection for {}, {}",
                                        connect_authority.host(),
                                        err
                                    );
                                    return;
                                }
                            };
                            let f = move |mut req: Request<_>| {
                                let connect_authority = connect_authority.clone();
                                let mut service = service.clone();

                                async move {
                                    inject_authority(&mut req, connect_authority.clone());
                                    service.call(req).await
                                }
                            };
                            let res = if client.get_ref().1.alpn_protocol() == Some(b"h2") {
                                server::conn::http2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(client), service_fn(f))
                                    .await
                            } else {
                                server::conn::http1::Builder::new()
                                    .preserve_header_case(true)
                                    .title_case_headers(true)
                                    .serve_connection(TokioIo::new(client), service_fn(f))
                                    .with_upgrades()
                                    .await
                            };

                            if let Err(err) = res {
                                tracing::debug!("Connection closed: {}", err);
                            }
                        } else {
                            let mut server =
                                match TcpStream::connect(connect_authority.as_str()).await {
                                    Ok(server) => server,
                                    Err(err) => {
                                        tracing::error!(
                                            "Failed to connect to {}: {}",
                                            connect_authority,
                                            err
                                        );
                                        return;
                                    }
                                };
                            let _ = tokio::io::copy_bidirectional(
                                &mut TokioIo::new(client),
                                &mut server,
                            )
                            .await;
                        }
                    });

                    Ok(Response::new(
                        http_body_util::Empty::new()
                            .map_err(|never: std::convert::Infallible| match never {})
                            .boxed(),
                    ))
                } else {
                    // http
                    service.call(req).await.map(|res| res.map(|b| b.boxed()))
                }
            }
        })
    }

    fn get_certified_key(&self, host: String) -> Option<CertifiedKeyDer> {
        self.root_issuer.as_ref().and_then(|root_issuer| {
            if let Some(cache) = self.cert_cache.as_ref() {
                // Try to get from cache, but handle generation errors gracefully
                cache
                    .try_get_with(host.clone(), move || {
                        generate_cert(host, root_issuer.borrow())
                    })
                    .map_err(|err| {
                        tracing::error!("Failed to generate certificate for host: {}", err);
                    })
                    .ok()
            } else {
                generate_cert(host, root_issuer.borrow())
                    .map_err(|err| {
                        tracing::error!("Failed to generate certificate for host: {}", err);
                    })
                    .ok()
            }
        })
    }

    fn server_config(
        &self,
        host: String,
        h2: bool,
    ) -> Option<Result<rustls::ServerConfig, rustls::Error>> {
        if let Some(cert) = self.get_certified_key(host) {
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(cert.cert_der)],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_der),
                    ),
                );

            Some(if h2 {
                config.map(|mut server_config| {
                    server_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
                    server_config
                })
            } else {
                config
            })
        } else {
            None
        }
    }
}

fn no_body<D>(status: StatusCode) -> Response<Empty<D>> {
    let mut res = Response::new(Empty::new());
    *res.status_mut() = status;
    res
}

fn inject_authority<B>(request_middleman: &mut Request<B>, authority: hyper::http::uri::Authority) {
    let mut parts = request_middleman.uri().clone().into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    if parts.authority.is_none() {
        parts.authority = Some(authority.clone());
    }

    match hyper::http::uri::Uri::from_parts(parts) {
        Ok(uri) => *request_middleman.uri_mut() = uri,
        Err(err) => {
            tracing::error!(
                "Failed to inject authority '{}' into URI: {}",
                authority,
                err
            );
            // Keep the original URI if injection fails
        }
    }
}
