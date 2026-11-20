// end to end over a real socket. spins up the server on an ephemeral port and talks to it
// with hand built frames, so the wire format gets exercised the same way a stranger would.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use mariana::config::Config;
use mariana::net::auth::Token;
use mariana::net::Server;
use mariana::store::Store;

const OP_PING: u8 = 0x01;
const OP_AUTH: u8 = 0x02;
const OP_GET: u8 = 0x03;
const OP_SET: u8 = 0x04;
const OP_DEL: u8 = 0x05;

const ST_OK: u8 = 0x00;
const ST_VALUE: u8 = 0x01;
const ST_NOT_FOUND: u8 = 0x02;
const ST_DENIED: u8 = 0x03;

struct Harness {
    addr: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

async fn start(token: Option<Token>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = Arc::new(Config {
        listen: "127.0.0.1:0".parse().expect("addr"),
        data_dir: dir.path().to_path_buf(),
        ..Config::default()
    });

    let store = Arc::new(Store::open(&config).expect("store"));
    let bound = Server::new(config, store, token).bind().await.expect("bind");
    let addr = bound.local_addr().expect("local addr");

    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        bound
            .serve(async move {
                rx.await.ok();
            })
            .await
            .expect("serve");
    });

    Harness {
        addr,
        shutdown: Some(tx),
        handle: Some(handle),
        _dir: dir,
    }
}

impl Harness {
    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            tx.send(()).ok();
        }
        if let Some(handle) = self.handle.take() {
            handle.await.ok();
        }
    }
}

fn with_len(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn frame(opcode: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut body = vec![opcode];
    for part in parts {
        body.extend_from_slice(&with_len(part));
    }
    with_len(&body)
}

async fn send(stream: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
    stream.write_all(bytes).await.expect("write");
    stream.flush().await.expect("flush");

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.expect("read len");
    let len = u32::from_be_bytes(len_bytes) as usize;
    assert!(len > 0 && len < 1 << 24, "implausible response length {len}");

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.expect("read body");
    body
}

#[tokio::test]
async fn set_then_get_returns_the_value() {
    let harness = start(None).await;
    let mut stream = TcpStream::connect(harness.addr).await.expect("connect");

    assert_eq!(send(&mut stream, &frame(OP_PING, &[])).await, vec![ST_OK]);

    let set = frame(OP_SET, &[b"greeting", b"hello there"]);
    assert_eq!(send(&mut stream, &set).await, vec![ST_OK]);

    let got = send(&mut stream, &frame(OP_GET, &[b"greeting"])).await;
    assert_eq!(got[0], ST_VALUE);
    assert_eq!(&got[5..], b"hello there");

    let missing = send(&mut stream, &frame(OP_GET, &[b"nothing"])).await;
    assert_eq!(missing, vec![ST_NOT_FOUND]);

    harness.stop().await;
}

#[tokio::test]
async fn delete_hides_the_key() {
    let harness = start(None).await;
    let mut stream = TcpStream::connect(harness.addr).await.expect("connect");

    send(&mut stream, &frame(OP_SET, &[b"k", b"v"])).await;
    assert_eq!(send(&mut stream, &frame(OP_DEL, &[b"k"])).await, vec![ST_OK]);
    assert_eq!(
        send(&mut stream, &frame(OP_GET, &[b"k"])).await,
        vec![ST_NOT_FOUND]
    );

    harness.stop().await;
}

#[tokio::test]
async fn reads_are_denied_until_the_token_is_presented() {
    let secret = b"a token long enough to pass the minimum";
    let harness = start(Some(Token::new(secret))).await;

    let mut stream = TcpStream::connect(harness.addr).await.expect("connect");
    assert_eq!(
        send(&mut stream, &frame(OP_GET, &[b"k"])).await,
        vec![ST_DENIED]
    );

    let mut stream = TcpStream::connect(harness.addr).await.expect("reconnect");
    assert_eq!(
        send(&mut stream, &frame(OP_AUTH, &[b"wrong token entirely"])).await,
        vec![ST_DENIED]
    );

    let mut stream = TcpStream::connect(harness.addr).await.expect("reconnect");
    assert_eq!(send(&mut stream, &frame(OP_AUTH, &[secret])).await, vec![ST_OK]);
    assert_eq!(send(&mut stream, &frame(OP_SET, &[b"k", b"v"])).await, vec![ST_OK]);

    harness.stop().await;
}

#[tokio::test]
async fn an_absurd_frame_length_is_refused_and_the_socket_closes() {
    let harness = start(None).await;
    let mut stream = TcpStream::connect(harness.addr).await.expect("connect");

    stream
        .write_all(&[0xff, 0xff, 0xff, 0xff])
        .await
        .expect("write");
    stream.flush().await.expect("flush");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    assert_eq!(response, vec![0, 0, 0, 1, 0x04]);

    harness.stop().await;
}

#[tokio::test]
async fn a_truncated_body_does_not_wedge_the_server() {
    let harness = start(None).await;

    let mut stream = TcpStream::connect(harness.addr).await.expect("connect");
    let mut junk = frame(OP_SET, &[b"key", b"value"]);
    junk.truncate(junk.len() - 3);
    stream.write_all(&junk).await.expect("write");
    stream.flush().await.expect("flush");
    drop(stream);

    let mut stream = TcpStream::connect(harness.addr).await.expect("reconnect");
    assert_eq!(send(&mut stream, &frame(OP_PING, &[])).await, vec![ST_OK]);

    harness.stop().await;
}
