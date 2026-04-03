use std::io::{Read, Write};
use std::iter;
use std::path::Path;

use secrecy::SecretString;

use crate::error::S2Error;
use crate::keychain;

const AGE_ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_BINARY_HEADER: &[u8] = b"age-encryption.org/";

/// Check if file content appears to be age-encrypted.
pub fn is_age_encrypted(content: &[u8]) -> bool {
    content.starts_with(AGE_ARMOR_HEADER) || content.starts_with(AGE_BINARY_HEADER)
}

/// Decrypt an age-encrypted file using the passphrase from the keychain.
pub fn decrypt_file_content(path: &Path, encrypted: &[u8]) -> Result<String, S2Error> {
    let key = keychain::file_key(path);
    let passphrase = keychain::get_passphrase(&key)?;

    decrypt_with_passphrase(encrypted, &passphrase)
}

/// Decrypt age-encrypted bytes with a given passphrase.
pub fn decrypt_with_passphrase(encrypted: &[u8], passphrase: &str) -> Result<String, S2Error> {
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| S2Error::Encryption(format!("invalid age file: {}", e)))?;

    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_string()));

    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|e| S2Error::Encryption(format!("decryption failed: {}", e)))?;

    let mut plaintext = String::new();
    reader
        .read_to_string(&mut plaintext)
        .map_err(|e| S2Error::Encryption(format!("failed to read decrypted content: {}", e)))?;

    Ok(plaintext)
}

/// Encrypt content with a passphrase, returning armored age ciphertext.
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, S2Error> {
    let secret = SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);

    let mut encrypted = Vec::new();
    let armor =
        age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
            .map_err(|e| S2Error::Encryption(format!("failed to create armor writer: {}", e)))?;

    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|e| S2Error::Encryption(format!("encryption failed: {}", e)))?;

    writer
        .write_all(plaintext)
        .map_err(|e| S2Error::Encryption(format!("failed to write encrypted content: {}", e)))?;

    let armor = writer
        .finish()
        .map_err(|e| S2Error::Encryption(format!("failed to finalize encryption: {}", e)))?;

    armor
        .finish()
        .map_err(|e| S2Error::Encryption(format!("failed to finalize armor: {}", e)))?;

    Ok(encrypted)
}

/// Generate a random passphrase for file encryption.
pub fn generate_passphrase() -> String {
    let mut bytes = [0u8; 32];
    let mut rng = std::fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
    rng.read_exact(&mut bytes)
        .expect("failed to read random bytes");

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    bytes
        .iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}
