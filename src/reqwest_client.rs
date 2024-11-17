use bytes::Bytes;
use hyper::{body::Body, Request};

pub fn to_reqwest<T>(req: Request<T>) -> reqwest::Request
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

pub fn from_reqwest(res: reqwest::Response) -> hyper::Response<reqwest::Body> {
    let mut hres = hyper::Response::builder()
        .status(res.status())
        .version(res.version());

    *hres.headers_mut().unwrap() = res.headers().clone();

    let body = reqwest::Body::from(res);

    hres.body(body).unwrap()
}
