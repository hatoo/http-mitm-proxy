use http::Uri;
use httparse::{Header, Request, Status};
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::MAX_HEADERS;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("httparse error")]
    Parse(#[from] httparse::Error),
    #[error("Bad Content-Length")]
    BadContentLength,
}

fn is_request_end<'a, 'b>(
    buf: &'a [u8],
    headers: &'b mut [Header<'a>],
) -> Result<Option<Request<'b, 'a>>, ParseError> {
    let mut req = httparse::Request::new(headers);
    match req.parse(buf) {
        Ok(Status::Complete(n)) => {
            let body = &buf[n..];

            for header in req
                .headers
                .into_iter()
                .take_while(|h| h != &&httparse::EMPTY_HEADER)
            {
                if header.name.to_lowercase().as_str() == "content-length" {
                    let len: usize = std::str::from_utf8(header.value)
                        .map_err(|_| ParseError::BadContentLength)?
                        .parse()
                        .map_err(|_| ParseError::BadContentLength)?;
                    if body.len() >= len {
                        return Ok(Some(req));
                    } else {
                        return Ok(None);
                    }
                }
            }

            Ok(Some(req))
        }
        Ok(Status::Partial) => Ok(None),
        Err(err) => Err(err.into()), // End communication
    }
}

pub async fn read_req<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Option<(Vec<u8>, bool)>, ParseError> {
    let mut buf = Vec::new();

    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        if let Some(req) = is_request_end(&buf, &mut headers)? {
            let has_upgrade = req
                .headers
                .into_iter()
                .take_while(|h| h != &&httparse::EMPTY_HEADER)
                .any(|h| {
                    h.name.to_lowercase().as_str() == "connection"
                        && std::str::from_utf8(h.value)
                            .map(|s| s.to_lowercase().contains("upgrade"))
                            == Ok(true)
                });
            return Ok(Some((buf, has_upgrade)));
        } else if stream.read_buf(&mut buf).await? == 0 {
            return Ok(None);
        }
    }
}

pub fn parse_path(buf: &[u8]) -> Option<[String; 3]> {
    let mut i = 0;

    while *buf.get(i)? != b'\r' {
        i += 1;
    }

    let first_line = std::str::from_utf8(&buf[..i]).ok()?;

    first_line
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
}

pub fn replace_path(buf: Vec<u8>) -> Option<Vec<u8>> {
    let mut lines = buf.split_inclusive(|&b| b == b'\n');

    let first_line = lines.next()?.strip_suffix(b"\r\n")?;
    let first_line = std::str::from_utf8(first_line).ok()?;

    let fst = first_line.split_whitespace().collect::<Vec<_>>();
    let uri = Uri::try_from(fst[1]).ok()?;

    let mut ret = Vec::new();

    ret.extend(fst[0].as_bytes());
    ret.push(b' ');
    ret.extend(uri.path_and_query().unwrap().as_str().as_bytes());
    ret.push(b' ');
    ret.extend(fst[2].as_bytes());
    ret.extend(b"\r\n");

    let mut in_header = true;

    ret.extend(b"Connection: close\r\n");
    for line in lines {
        if in_header {
            if line.starts_with(b"Connection") {
                continue;
            }
            if line == b"\r\n" {
                in_header = false;
            }
            ret.extend(line.strip_prefix(b"Proxy-").unwrap_or(line));
        } else {
            ret.extend(line);
        }
    }

    Some(ret)
}
