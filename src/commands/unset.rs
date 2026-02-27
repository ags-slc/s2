use std::path::PathBuf;

use crate::config::{self, Config};
use crate::error::S2Error;
use crate::parser;
use crate::permissions;

/// Remove a key from a secret file.
pub fn run(config: &Config, key: String, file: Option<PathBuf>) -> Result<(), S2Error> {
    let path = config::resolve_single_file(config, &file)?;

    if !path.exists() {
        return Err(S2Error::FileNotFound(path));
    }

    permissions::check_permissions(&path)?;
    let content = std::fs::read_to_string(&path)?;
    let entries = parser::parse_file(&path, &content)?;

    let original_len = entries.len();
    let entries: Vec<_> = entries.into_iter().filter(|e| e.key != key).collect();

    if entries.len() == original_len {
        eprintln!("Key not found: {}", key);
        std::process::exit(1);
    }

    let content = parser::serialize_entries(&entries);
    std::fs::write(&path, content)?;
    permissions::set_secure_permissions(&path)?;

    eprintln!("Removed: {}", key);
    Ok(())
}
