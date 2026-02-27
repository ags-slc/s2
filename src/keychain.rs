use crate::error::S2Error;

const SERVICE_NAME: &str = "s2-secrets";

/// Store a passphrase in the system keychain, keyed by file path.
pub fn store_passphrase(file_key: &str, passphrase: &str) -> Result<(), S2Error> {
    let entry = keyring::Entry::new(SERVICE_NAME, file_key)
        .map_err(|e| S2Error::Keychain(e.to_string()))?;
    entry
        .set_password(passphrase)
        .map_err(|e| S2Error::Keychain(format!("failed to store passphrase: {}", e)))?;
    Ok(())
}

/// Retrieve a passphrase from the system keychain.
pub fn get_passphrase(file_key: &str) -> Result<String, S2Error> {
    let entry = keyring::Entry::new(SERVICE_NAME, file_key)
        .map_err(|e| S2Error::Keychain(e.to_string()))?;
    entry
        .get_password()
        .map_err(|e| S2Error::Keychain(format!("passphrase not found in keychain: {}", e)))
}

/// Delete a passphrase from the system keychain.
pub fn delete_passphrase(file_key: &str) -> Result<(), S2Error> {
    let entry = keyring::Entry::new(SERVICE_NAME, file_key)
        .map_err(|e| S2Error::Keychain(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| S2Error::Keychain(format!("failed to delete passphrase: {}", e)))?;
    Ok(())
}

/// Generate a canonical key for a file path (used as keychain username).
pub fn file_key(path: &std::path::Path) -> String {
    // Use the canonical absolute path as the key
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}
