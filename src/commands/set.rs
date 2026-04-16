use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use secrecy::SecretString;

use crate::config::{self, Config};
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::parser::{self, ParsedEntry};
use crate::permissions;

/// Set a secret by reading the value from stdin.
/// Never accepts the value as a CLI argument (prevents shell history exposure).
pub fn run(config: &Config, key: String, file: Option<PathBuf>) -> Result<(), S2Error> {
    let path = config::resolve_single_file(config, &file)?;

    // Read value from stdin
    if std::io::stdin().is_terminal() {
        eprint!("Enter value for {}: ", key);
    }

    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    let value = value.trim_end_matches('\n').to_string();

    if value.is_empty() {
        eprintln!("Error: empty value");
        std::process::exit(1);
    }

    // Load existing file content (or create new)
    let (mut entries, was_encrypted) = if path.exists() {
        permissions::check_permissions(&path)?;
        let raw = std::fs::read(&path)?;
        if crypto::is_age_encrypted(&raw) {
            let plaintext = crypto::decrypt_file_content(&path, &raw, config.biometric)?;
            (parser::parse_file(&path, &plaintext)?, true)
        } else {
            let content = String::from_utf8(raw).map_err(|e| S2Error::ParseError {
                path: path.clone(),
                line: 0,
                message: format!("invalid UTF-8: {}", e),
            })?;
            (parser::parse_file(&path, &content)?, false)
        }
    } else {
        (Vec::new(), false)
    };

    // Replace existing or append
    let mut found = false;
    for entry in &mut entries {
        if entry.key == key {
            entry.value = SecretString::from(value.clone());
            found = true;
            break;
        }
    }

    if !found {
        entries.push(ParsedEntry {
            key: key.clone(),
            value: SecretString::from(value),
            source_uri: None,
        });
    }

    // Write back, re-encrypting if the file was encrypted
    let content = parser::serialize_entries(&entries);
    if was_encrypted {
        let file_key = keychain::file_key(&path);
        let passphrase = keychain::get_passphrase(&file_key, config.biometric)?;
        let encrypted = crypto::encrypt_with_passphrase(content.as_bytes(), &passphrase)?;
        std::fs::write(&path, &encrypted)?;
    } else {
        std::fs::write(&path, content)?;
    }
    permissions::set_secure_permissions(&path)?;

    if found {
        eprintln!("Updated: {}", key);
    } else {
        eprintln!("Added: {}", key);
    }

    Ok(())
}
