// knobs, plus the hard limits that keep a hostile client from eating all the memory.
// defaults are deliberately paranoid. loopback only, everything bounded.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOKEN_BYTES: usize = 512;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub max_connections: usize,
    pub handshake_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub memtable_bytes: usize,
    pub fsync_on_write: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 7878)),
            data_dir: PathBuf::from("./data"),
            max_connections: 512,
            handshake_timeout_ms: 5_000,
            idle_timeout_ms: 60_000,
            memtable_bytes: 64 * 1024 * 1024,
            fsync_on_write: true,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> crate::Result<Config> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw).map_err(|e| crate::Error::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.max_connections == 0 {
            return Err(crate::Error::Config("max_connections must be > 0".into()));
        }
        if self.memtable_bytes < 1024 * 1024 {
            return Err(crate::Error::Config("memtable_bytes must be at least 1 MiB".into()));
        }
        if self.handshake_timeout_ms == 0 || self.idle_timeout_ms == 0 {
            return Err(crate::Error::Config("timeouts must be > 0".into()));
        }
        Ok(())
    }

    pub fn exposed_publicly(&self) -> bool {
        !self.listen.ip().is_loopback()
    }
}
