use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::permissions;

/// Decrypt to a secure temp file, open in $EDITOR, re-encrypt on save.
pub fn run(path: PathBuf) -> Result<(), S2Error> {
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
    let passphrase = keychain::get_passphrase(&key)?;
    let plaintext = crypto::decrypt_with_passphrase(&encrypted, &passphrase)?;

    // Find editor
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| S2Error::NoEditor)?;

    // Create secure temp file
    let mut temp = tempfile::NamedTempFile::new()?;
    permissions::set_secure_permissions(temp.path())?;
    temp.write_all(plaintext.as_bytes())?;
    temp.flush()?;

    // Open editor
    let status = Command::new(&editor)
        .arg(temp.path())
        .status()
        .map_err(|e| S2Error::ExecFailed(format!("failed to run {}: {}", editor, e)))?;

    if !status.success() {
        eprintln!("Editor exited with non-zero status, aborting");
        std::process::exit(1);
    }

    // Read edited content
    let edited = std::fs::read(temp.path())?;

    // Re-encrypt with same passphrase
    let re_encrypted = crypto::encrypt_with_passphrase(&edited, &passphrase)?;
    std::fs::write(&path, &re_encrypted)?;
    permissions::set_secure_permissions(&path)?;

    // Temp file is automatically deleted by NamedTempFile drop,
    // but overwrite it first for defense in depth
    let zeros = vec![0u8; edited.len()];
    let _ = std::fs::write(temp.path(), &zeros);

    eprintln!("Saved and re-encrypted: {}", path.display());
    Ok(())
}
