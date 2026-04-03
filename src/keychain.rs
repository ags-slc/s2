use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::S2Error;

const SERVICE_NAME: &str = "s2-secrets";

/// Store a passphrase, trying system keyring first, then file-based fallback.
pub fn store_passphrase(file_key: &str, passphrase: &str) -> Result<(), S2Error> {
    // Try system keyring
    if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, file_key) {
        if entry.set_password(passphrase).is_ok() {
            return Ok(());
        }
    }
    // Fall back to file-based storage
    store_passphrase_file(file_key, passphrase)
}

/// Retrieve a passphrase, trying system keyring first, then file-based fallback.
pub fn get_passphrase(file_key: &str) -> Result<String, S2Error> {
    // Try system keyring
    if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, file_key) {
        if let Ok(pw) = entry.get_password() {
            return Ok(pw);
        }
    }
    // Fall back to file-based storage
    get_passphrase_file(file_key)
}

/// Generate a canonical key for a file path (used as keychain username).
pub fn file_key(path: &std::path::Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

// --- File-based fallback ---

fn keys_dir() -> Result<PathBuf, S2Error> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    let dir = base.join("s2").join("keys");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn key_filename(file_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_key.as_bytes());
    format!("{:x}.key", hasher.finalize())
}

fn store_passphrase_file(file_key: &str, passphrase: &str) -> Result<(), S2Error> {
    let dir = keys_dir()?;
    let path = dir.join(key_filename(file_key));
    std::fs::write(&path, passphrase)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn get_passphrase_file(file_key: &str) -> Result<String, S2Error> {
    let dir = keys_dir()?;
    let path = dir.join(key_filename(file_key));
    if !path.exists() {
        return Err(S2Error::Keychain(
            "passphrase not found in keychain or file store".to_string(),
        ));
    }
    std::fs::read_to_string(&path)
        .map_err(|e| S2Error::Keychain(format!("failed to read passphrase file: {}", e)))
}
