// accept loop. one task per connection, hard cap on how many can exist at once.
//
// the limits are the interesting part. a connection that shows up when we are full gets
// dropped rather than parked, otherwise a client can queue up work forever and we pay for
// it in memory. a connection that goes quiet gets closed on the idle timer, which is what
// stops a few hundred half open sockets from holding the whole server hostage. store calls
// fsync so they run on the blocking pool, never on an async worker thread.

use std::future::Future;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::net::auth::Token;
use crate::net::codec::{read_frame, write_response, Request, Response};
use crate::store::Store;
use crate::{Error, Result};

pub struct Server {
    config: Arc<Config>,
    store: Arc<Store>,
    token: Option<Arc<Token>>,
    permits: Arc<Semaphore>,
}

impl Server {
    pub fn new(config: Arc<Config>, store: Arc<Store>, token: Option<Token>) -> Server {
        let permits = Arc::new(Semaphore::new(config.max_connections));
        Server {
            config,
            store,
            token: token.map(Arc::new),
            permits,
        }
    }

    pub async fn bind(self) -> Result<Bound> {
        let listener = TcpListener::bind(self.config.listen).await?;
        info!(addr = %listener.local_addr()?, "listening");
        Ok(Bound {
            listener,
            server: self,
        })
    }

    pub async fn run<S>(self, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        self.bind().await?.serve(shutdown).await
    }
}

pub struct Bound {
    listener: TcpListener,
    server: Server,
}

impl Bound {
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve<S>(self, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        let Bound { listener, server } = self;
        let Server {
            config,
            store,
            token,
            permits,
        } = server;

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received, draining");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!(error = %e, "accept failed");
                            continue;
                        }
                    };

                    let permit = match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            debug!(%peer, "connection limit reached, refusing");
                            drop(stream);
                            continue;
                        }
                    };

                    let conn_config = Arc::clone(&config);
                    let conn_store = Arc::clone(&store);
                    let conn_token = token.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = serve(stream, conn_config, conn_store, conn_token).await {
                            debug!(%peer, error = %e, "connection closed");
                        }
                    });
                }
            }
        }

        store.flush()?;
        info!("flushed, goodbye");
        Ok(())
    }
}

async fn serve(
    stream: TcpStream,
    config: Arc<Config>,
    store: Arc<Store>,
    token: Option<Arc<Token>>,
) -> Result<()> {
    stream.set_nodelay(true)?;

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    let mut authenticated = token.is_none();
    let mut buf = Vec::with_capacity(1024);

    let handshake = Duration::from_millis(config.handshake_timeout_ms);
    let idle = Duration::from_millis(config.idle_timeout_ms);
    let mut budget = handshake;

    loop {
        let frame = match timeout(budget, read_frame(&mut reader, &mut buf)).await {
            Err(_) => {
                debug!("client timed out");
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(request))) => request,
            Ok(Err(e)) => {
                write_response(&mut writer, &Response::BadRequest).await.ok();
                return Err(e);
            }
        };

        if frame.needs_auth() && !authenticated {
            write_response(&mut writer, &Response::Denied).await?;
            return Err(Error::Unauthenticated);
        }

        let response = match frame {
            Request::Ping => Response::Ok,
            Request::Auth(presented) => match &token {
                None => Response::Ok,
                Some(expected) => {
                    if expected.verify(&presented) {
                        authenticated = true;
                        budget = idle;
                        Response::Ok
                    } else {
                        write_response(&mut writer, &Response::Denied).await?;
                        return Err(Error::Unauthenticated);
                    }
                }
            },
            Request::Get(key) => {
                let store = Arc::clone(&store);
                match blocking(move || store.get(&key)).await {
                    Ok(Some(value)) => Response::Value(value),
                    Ok(None) => Response::NotFound,
                    Err(e) => {
                        warn!(error = %e, "get failed");
                        Response::Internal
                    }
                }
            }
            Request::Set(key, value) => {
                let store = Arc::clone(&store);
                match blocking(move || store.set(&key, &value)).await {
                    Ok(()) => Response::Ok,
                    Err(e) => {
                        warn!(error = %e, "set failed");
                        Response::Internal
                    }
                }
            }
            Request::Del(key) => {
                let store = Arc::clone(&store);
                match blocking(move || store.delete(&key)).await {
                    Ok(()) => Response::Ok,
                    Err(e) => {
                        warn!(error = %e, "delete failed");
                        Response::Internal
                    }
                }
            }
        };

        write_response(&mut writer, &response).await?;

        if authenticated {
            budget = idle;
        }
    }

    writer.shutdown().await.ok();
    Ok(())
}

async fn blocking<T, F>(job: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(result) => result,
        Err(e) => Err(Error::Config(format!("worker panicked: {e}"))),
    }
}
