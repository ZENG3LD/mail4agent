//! `mail4agent.toml` -- every field defaulted so the file may be absent,
//! resolved the way `smm8mail` resolves its own config
//! (`smm8mail/src/config.rs::load_config`): look in the current working
//! directory only, fall back to full defaults when it is not there. A
//! present-but-unparsable file is a real configuration mistake and is
//! surfaced as an error, never silently ignored.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

const CONFIG_FILE_NAME: &str = "mail4agent.toml";
const DEFAULT_BIND: &str = "127.0.0.1:18301";

/// Environment override for the sqlite path. Wins unconditionally over
/// both [`Config::db_path`] and the per-user-data-directory default.
const DB_PATH_ENV: &str = "MAIL4AGENT_DB_PATH";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: SocketAddr,
    /// Absent -> a per-user data directory
    /// (`directories::ProjectDirs::from("", "", "mail4agent")`) -- see
    /// [`Config::resolve_db_path`].
    pub db_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND
                .parse()
                .expect("DEFAULT_BIND is a valid socket address literal"),
            db_path: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("parse {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error(
        "no home/data directory available to place the default mailbox database -- \
         set {DB_PATH_ENV} explicitly"
    )]
    NoDataDir,
}

impl Config {
    /// Loads `./mail4agent.toml` if present; every field defaults when the
    /// file is absent, so a bare `mail4agent` invocation with no config at
    /// all is a supported first run.
    pub fn load() -> Result<Self, ConfigError> {
        let path = PathBuf::from(CONFIG_FILE_NAME);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(|err| ConfigError::Read(path.clone(), err))?;
        toml::from_str(&raw).map_err(|err| ConfigError::Parse(path, err))
    }

    /// Resolves the sqlite path: [`DB_PATH_ENV`] wins unconditionally over
    /// [`Config::db_path`], which in turn wins over the per-user data
    /// directory default.
    pub fn resolve_db_path(&self) -> Result<PathBuf, ConfigError> {
        if let Ok(from_env) = std::env::var(DB_PATH_ENV) {
            return Ok(PathBuf::from(from_env));
        }
        if let Some(path) = &self.db_path {
            return Ok(path.clone());
        }
        let dirs = directories::ProjectDirs::from("", "", "mail4agent").ok_or(ConfigError::NoDataDir)?;
        Ok(dirs.data_dir().join("mail4agent.sqlite"))
    }
}
