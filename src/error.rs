use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum S2Error {
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("file {path} has unsafe permissions {mode:#o} (expected 0600)")]
    UnsafePermissions { path: PathBuf, mode: u32 },

    #[error("parse error in {path} at line {line}: {message}")]
    ParseError {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("no files specified and no default_files in config")]
    NoFiles,

    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("editor not found: set $EDITOR or $VISUAL")]
    NoEditor,

    #[error("exec failed: {0}")]
    ExecFailed(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
