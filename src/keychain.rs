use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::error::S2Error;

const SERVICE_NAME: &str = "s2-secrets";

/// Store a passphrase, trying system keyring first, then file-based fallback.
/// When `biometric` is true on macOS, stores with Touch ID access control.
pub fn store_passphrase(file_key: &str, passphrase: &str, biometric: bool) -> Result<(), S2Error> {
    #[cfg(target_os = "macos")]
    if biometric {
        if let Ok(()) = store_passphrase_biometric(file_key, passphrase) {
            return Ok(());
        }
        // Fall through to regular keyring if biometric store fails
    }

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
/// When `biometric` is true on macOS, triggers Touch ID before returning.
pub fn get_passphrase(file_key: &str, biometric: bool) -> Result<String, S2Error> {
    #[cfg(target_os = "macos")]
    if biometric {
        // Try biometric-protected item first
        if let Ok(pw) = get_passphrase_biometric(file_key) {
            return Ok(pw);
        }
        // Try regular keyring — auto-migrate to biometric if found
        if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, file_key) {
            if let Ok(pw) = entry.get_password() {
                // Migrate: re-store with biometric, delete old entry
                if store_passphrase_biometric(file_key, &pw).is_ok() {
                    let _ = entry.delete_credential();
                }
                return Ok(pw);
            }
        }
        // Fall through to file fallback
        return get_passphrase_file(file_key);
    }

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

// --- macOS biometric (Touch ID) ---

#[cfg(target_os = "macos")]
fn store_passphrase_biometric(file_key: &str, passphrase: &str) -> Result<(), S2Error> {
    use security_framework::access_control::SecAccessControl;
    use security_framework::passwords::delete_generic_password;
    use security_framework::passwords_options::PasswordOptions;

    // Delete existing item (can't update access control in-place)
    let _ = delete_generic_password(SERVICE_NAME, file_key);

    let access_control = SecAccessControl::create_with_flags(
        security_framework::passwords_options::AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(|e| S2Error::Keychain(format!("failed to create biometric access control: {e}")))?;

    let mut options = PasswordOptions::new_generic_password(SERVICE_NAME, file_key);
    options.set_access_control(access_control);

    security_framework::passwords::set_generic_password_options(passphrase.as_bytes(), options)
        .map_err(|e| {
            S2Error::Keychain(format!("failed to store passphrase with biometric: {e}"))
        })?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn get_passphrase_biometric(file_key: &str) -> Result<String, S2Error> {
    let password = security_framework::passwords::get_generic_password(SERVICE_NAME, file_key)
        .map_err(|e| S2Error::Keychain(format!("biometric authentication failed: {e}")))?;

    String::from_utf8(password)
        .map_err(|e| S2Error::Keychain(format!("passphrase is not valid UTF-8: {e}")))
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
