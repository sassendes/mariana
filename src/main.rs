// entry point. read the config, open the store, serve until ctrl-c.
// the one opinionated bit is that we refuse to start if you bind a public address without
// a token. an open key value store on the internet is not a hypothetical problem.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use mariana::config::Config;
use mariana::net::auth::{Token, TOKEN_ENV};
use mariana::net::Server;
use mariana::store::Store;
use mariana::{Error, Result};

const BANNER: &str = r"
 mariana
 a key value store for people who looked at postgres and quietly closed the tab
 it remembers things. that is the entire pitch.
";

#[derive(Parser, Debug)]
#[command(name = "mariana", version, about = "a small durable key value store")]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[arg(long, value_name = "ADDR")]
    listen: Option<std::net::SocketAddr>,

    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mariana: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    let mut config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    if let Some(listen) = args.listen {
        config.listen = listen;
    }
    if let Some(dir) = args.data_dir {
        config.data_dir = dir;
    }
    config.validate()?;

    let token = Token::from_env().map_err(Error::Config)?;

    if config.exposed_publicly() && token.is_none() {
        return Err(Error::Config(format!(
            "refusing to bind {} with no token, set {TOKEN_ENV} or listen on loopback",
            config.listen
        )));
    }
    if token.is_none() {
        warn!("no {TOKEN_ENV} set, running unauthenticated on loopback");
    }

    print!("{BANNER}");

    let config = Arc::new(config);
    let store = Arc::new(Store::open(&config)?);
    info!(
        tables = store.table_count(),
        sequence = store.sequence(),
        dir = %config.data_dir.display(),
        "store opened"
    );

    let server = Server::new(Arc::clone(&config), Arc::clone(&store), token);
    server.run(shutdown_signal()).await
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
