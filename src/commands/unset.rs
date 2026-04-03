use std::path::PathBuf;

use crate::config::{self, Config};
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::parser;
use crate::permissions;

/// Remove a key from a secret file.
pub fn run(config: &Config, key: String, file: Option<PathBuf>) -> Result<(), S2Error> {
    let path = config::resolve_single_file(config, &file)?;

    if !path.exists() {
        return Err(S2Error::FileNotFound(path));
    }

    permissions::check_permissions(&path)?;
    let raw = std::fs::read(&path)?;

    let (entries, was_encrypted) = if crypto::is_age_encrypted(&raw) {
        let plaintext = crypto::decrypt_file_content(&path, &raw)?;
        (parser::parse_file(&path, &plaintext)?, true)
    } else {
        let content = String::from_utf8(raw).map_err(|e| S2Error::ParseError {
            path: path.clone(),
            line: 0,
            message: format!("invalid UTF-8: {}", e),
        })?;
        (parser::parse_file(&path, &content)?, false)
    };

    let original_len = entries.len();
    let entries: Vec<_> = entries.into_iter().filter(|e| e.key != key).collect();

    if entries.len() == original_len {
        eprintln!("Key not found: {}", key);
        std::process::exit(1);
    }

    let content = parser::serialize_entries(&entries);
    if was_encrypted {
        let file_key = keychain::file_key(&path);
        let passphrase = keychain::get_passphrase(&file_key)?;
        let encrypted = crypto::encrypt_with_passphrase(content.as_bytes(), &passphrase)?;
        std::fs::write(&path, &encrypted)?;
    } else {
        std::fs::write(&path, content)?;
    }
    permissions::set_secure_permissions(&path)?;

    eprintln!("Removed: {}", key);
    Ok(())
}
