// every way this thing can blow up. one enum, everything funnels into it.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("frame of {0} bytes exceeds limit of {1}")]
    FrameTooLarge(u32, u32),

    #[error("malformed frame")]
    Malformed,

    #[error("unauthenticated")]
    Unauthenticated,

    #[error("table format error: {0}")]
    BadTable(&'static str),

    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
