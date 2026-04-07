use std::path::PathBuf;

use crate::config::Config;
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::permissions;

/// Decrypt an age-encrypted file, replacing it with the plaintext.
pub fn run(config: &Config, path: PathBuf) -> Result<(), S2Error> {
    if !path.exists() {
        return Err(S2Error::FileNotFound(path));
    }

    permissions::check_permissions(&path)?;

    let encrypted = std::fs::read(&path)?;

    if !crypto::is_age_encrypted(&encrypted) {
        eprintln!("File is not age-encrypted: {}", path.display());
        std::process::exit(1);
    }

    let key = keychain::file_key(&path);
    let passphrase = keychain::get_passphrase(&key, config.biometric)?;
    let plaintext = crypto::decrypt_with_passphrase(&encrypted, &passphrase)?;

    std::fs::write(&path, plaintext.as_bytes())?;
    permissions::set_secure_permissions(&path)?;

    eprintln!("Decrypted: {}", path.display());
    Ok(())
}
