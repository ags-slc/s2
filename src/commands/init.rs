use std::path::PathBuf;

use crate::config::Config;
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::permissions;

/// Create a new secret file with secure permissions, encrypted by default.
pub fn run(config: &Config, path: Option<PathBuf>, no_encrypt: bool) -> Result<(), S2Error> {
    let path = path.unwrap_or_else(|| PathBuf::from(".env"));

    if path.exists() {
        eprintln!("File already exists: {}", path.display());
        std::process::exit(1);
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let header = "# Secrets file managed by s2\n# Format: KEY=value or export KEY=value\n\n";

    if no_encrypt {
        std::fs::write(&path, header)?;
        permissions::set_secure_permissions(&path)?;
        eprintln!("Created {} (mode 0600, plaintext)", path.display());
    } else {
        let passphrase = crypto::generate_passphrase();
        let key = keychain::file_key(&path.canonicalize().unwrap_or_else(|_| path.clone()));
        keychain::store_passphrase(&key, &passphrase, config.biometric)?;

        let encrypted = crypto::encrypt_with_passphrase(header.as_bytes(), &passphrase)?;
        std::fs::write(&path, &encrypted)?;
        permissions::set_secure_permissions(&path)?;
        eprintln!(
            "Created {} (mode 0600, encrypted, passphrase stored in keychain)",
            path.display()
        );
    }

    Ok(())
}
