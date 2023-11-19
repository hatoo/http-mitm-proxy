use httparse::{Response, Status};
use tokio::io::AsyncReadExt;

use super::{ParseError, MAX_HEADERS};

fn is_response_end(buf: &[u8]) -> Result<bool, ParseError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(Status::Complete(n)) => {
            let body = &buf[n..];

            for header in headers
                .into_iter()
                .take_while(|h| h != &httparse::EMPTY_HEADER)
            {
                match header.name.to_lowercase().as_str() {
                    "content-length" => {
                        let len: usize = std::str::from_utf8(header.value)
                            .map_err(|_| ParseError::BadContentLength)?
                            .parse()
                            .map_err(|_| ParseError::BadContentLength)?;
                        return Ok(body.len() >= len);
                    }
                    "transfer-encoding" => {
                        if let Ok(enc) = std::str::from_utf8(header.value) {
                            if enc.to_lowercase().contains("chunked") {
                                let mut body = body;

                                loop {
                                    let httparse::Status::Complete((offset, len)) =
                                        httparse::parse_chunk_size(body)
                                            .map_err(|_| ParseError::BadChunkEncoding)?
                                    else {
                                        return Ok(false);
                                    };

                                    let next = offset + len as usize + 2;
                                    if body.len() < next {
                                        return Ok(false);
                                    }
                                    if len == 0 {
                                        return Ok(true);
                                    }
                                    body = &body[next..];
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(true)
        }
        Ok(Status::Partial) => Ok(false),
        Err(err) => Err(err.into()), // End communication
    }
}

pub async fn read_resp<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Option<Vec<u8>>, ParseError> {
    let mut buf = Vec::new();
    while {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut res = Response::new(&mut headers);
        res.parse(&buf)?.is_partial()
    } {
        if stream.read_buf(&mut buf).await? == 0 {
            return Ok(None);
        }
    }
    Ok(Some(buf))
}

pub enum ResponseType {
    Normal,
    Sse,
    Upgrade,
}

pub fn response_type(buf: &[u8]) -> Option<ResponseType> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(Status::Complete(_)) => {
            if resp.code == Some(101) {
                return Some(ResponseType::Upgrade);
            }

            for h in headers
                .into_iter()
                .take_while(|h| h != &httparse::EMPTY_HEADER)
            {
                if h.name.eq_ignore_ascii_case("content-type") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        if s.to_lowercase().contains("text/event-stream") {
                            return Some(ResponseType::Sse);
                        }
                    }
                }
            }

            Some(ResponseType::Normal)
        }
        _ => None,
    }
}
