// the wire format. this is the only file that parses bytes from strangers so it is the
// paranoid one. frames are a 4 byte big endian length then a 1 byte opcode then the body.
//
// the length gets checked against the cap before anything is allocated. reading a length
// and handing it straight to a Vec is how you turn a 5 byte packet into an out of memory
// kill, so that check is load bearing. everything below it is bounds checked slicing with
// no indexing that can panic, because a panic on a hostile frame is a free denial of service.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{MAX_FRAME_BYTES, MAX_KEY_BYTES, MAX_TOKEN_BYTES, MAX_VALUE_BYTES};
use crate::{Error, Result};

const OP_PING: u8 = 0x01;
const OP_AUTH: u8 = 0x02;
const OP_GET: u8 = 0x03;
const OP_SET: u8 = 0x04;
const OP_DEL: u8 = 0x05;

const ST_OK: u8 = 0x00;
const ST_VALUE: u8 = 0x01;
const ST_NOT_FOUND: u8 = 0x02;
const ST_DENIED: u8 = 0x03;
const ST_BAD_REQUEST: u8 = 0x04;
const ST_INTERNAL: u8 = 0x05;

#[derive(Debug)]
pub enum Request {
    Ping,
    Auth(Vec<u8>),
    Get(Vec<u8>),
    Set(Vec<u8>, Vec<u8>),
    Del(Vec<u8>),
}

#[derive(Debug)]
pub enum Response {
    Ok,
    Value(Vec<u8>),
    NotFound,
    Denied,
    BadRequest,
    Internal,
}

impl Request {
    pub fn needs_auth(&self) -> bool {
        !matches!(self, Request::Ping | Request::Auth(_))
    }

    pub fn decode(frame: &[u8]) -> Result<Request> {
        let (opcode, body) = frame.split_first().ok_or(Error::Malformed)?;

        let request = match *opcode {
            OP_PING => {
                expect_empty(body)?;
                Request::Ping
            }
            OP_AUTH => {
                let (token, rest) = take_len_prefixed(body, MAX_TOKEN_BYTES)?;
                expect_empty(rest)?;
                Request::Auth(token.to_vec())
            }
            OP_GET => {
                let (key, rest) = take_len_prefixed(body, MAX_KEY_BYTES)?;
                expect_empty(rest)?;
                reject_empty_key(key)?;
                Request::Get(key.to_vec())
            }
            OP_DEL => {
                let (key, rest) = take_len_prefixed(body, MAX_KEY_BYTES)?;
                expect_empty(rest)?;
                reject_empty_key(key)?;
                Request::Del(key.to_vec())
            }
            OP_SET => {
                let (key, rest) = take_len_prefixed(body, MAX_KEY_BYTES)?;
                let (value, rest) = take_len_prefixed(rest, MAX_VALUE_BYTES)?;
                expect_empty(rest)?;
                reject_empty_key(key)?;
                Request::Set(key.to_vec(), value.to_vec())
            }
            _ => return Err(Error::Malformed),
        };

        Ok(request)
    }
}

fn reject_empty_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(())
}

fn expect_empty(rest: &[u8]) -> Result<()> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

fn take_len_prefixed(buf: &[u8], limit: usize) -> Result<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return Err(Error::Malformed);
    }
    let (len_bytes, rest) = buf.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

    if len > limit || rest.len() < len {
        return Err(Error::Malformed);
    }
    Ok(rest.split_at(len))
}

pub async fn read_frame<R>(reader: &mut R, buf: &mut Vec<u8>) -> Result<Option<Request>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    }

    let len = u32::from_be_bytes(len_bytes);
    if len == 0 {
        return Err(Error::Malformed);
    }
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge(len, MAX_FRAME_BYTES));
    }

    buf.clear();
    buf.resize(len as usize, 0);
    reader.read_exact(buf).await?;

    Request::decode(buf).map(Some)
}

pub async fn write_response<W>(writer: &mut W, response: &Response) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut out = vec![0u8, 0, 0, 0];

    match response {
        Response::Ok => out.push(ST_OK),
        Response::NotFound => out.push(ST_NOT_FOUND),
        Response::Denied => out.push(ST_DENIED),
        Response::BadRequest => out.push(ST_BAD_REQUEST),
        Response::Internal => out.push(ST_INTERNAL),
        Response::Value(bytes) => {
            out.push(ST_VALUE);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }

    let len = (out.len() - 4) as u32;
    out[..4].copy_from_slice(&len.to_be_bytes());

    writer.write_all(&out).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_frame, Request, MAX_FRAME_BYTES};
    use crate::Error;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn a_giant_length_is_refused_before_allocating() {
        let mut input: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        let mut buf = Vec::new();
        match read_frame(&mut input, &mut buf).await {
            Err(Error::FrameTooLarge(got, limit)) => {
                assert_eq!(got, u32::MAX);
                assert_eq!(limit, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn a_clean_close_is_not_an_error() {
        let mut input: &[u8] = &[];
        let mut buf = Vec::new();
        assert!(read_frame(&mut input, &mut buf).await.unwrap().is_none());
    }

    #[test]
    fn a_length_that_overruns_the_body_is_rejected() {
        assert!(Request::decode(&[0x03, 0x00, 0x00, 0x10, 0x00, b'a']).is_err());
    }

    #[test]
    fn trailing_junk_is_rejected() {
        let mut body = vec![0x03, 0x00, 0x00, 0x00, 0x01, b'a'];
        body.push(0xde);
        assert!(Request::decode(&body).is_err());
    }

    #[test]
    fn unknown_opcodes_are_rejected() {
        assert!(Request::decode(&[0x7f]).is_err());
        assert!(Request::decode(&[]).is_err());
    }

    #[test]
    fn empty_keys_are_rejected() {
        assert!(Request::decode(&[0x03, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[tokio::test]
    async fn a_well_formed_set_round_trips() {
        let body = {
            let mut b = vec![0x04];
            b.extend_from_slice(&1u32.to_be_bytes());
            b.push(b'k');
            b.extend_from_slice(&2u32.to_be_bytes());
            b.extend_from_slice(b"hi");
            b
        };
        let wire = frame(&body);
        let mut input: &[u8] = &wire;
        let mut buf = Vec::new();
        match read_frame(&mut input, &mut buf).await.unwrap() {
            Some(Request::Set(key, value)) => {
                assert_eq!(key, b"k");
                assert_eq!(value, b"hi");
            }
            other => panic!("expected a Set, got {other:?}"),
        }
    }
}
