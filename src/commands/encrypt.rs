use std::path::PathBuf;

use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::permissions;

/// Encrypt a plaintext file with age. Stores the passphrase in the system keychain.
pub fn run(path: PathBuf) -> Result<(), S2Error> {
    if !path.exists() {
        return Err(S2Error::FileNotFound(path));
    }

    permissions::check_permissions(&path)?;

    let plaintext = std::fs::read(&path)?;

    if crypto::is_age_encrypted(&plaintext) {
        eprintln!("File is already encrypted: {}", path.display());
        std::process::exit(1);
    }

    // Generate passphrase and store in keychain
    let passphrase = crypto::generate_passphrase();
    let key = keychain::file_key(&path);
    keychain::store_passphrase(&key, &passphrase)?;

    // Encrypt
    let encrypted = crypto::encrypt_with_passphrase(&plaintext, &passphrase)?;

    // Write encrypted content back (replacing plaintext)
    std::fs::write(&path, &encrypted)?;
    permissions::set_secure_permissions(&path)?;

    eprintln!(
        "Encrypted: {} (passphrase stored in keychain)",
        path.display()
    );
    Ok(())
}
