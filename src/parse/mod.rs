use thiserror::Error;

pub mod request;
pub mod response;

const MAX_HEADERS: usize = 100;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("httparse error")]
    Parse(#[from] httparse::Error),
    #[error("Bad Content-Length")]
    BadContentLength,
    #[error("Bad Chunk encoding")]
    BadChunkEncoding,
}
