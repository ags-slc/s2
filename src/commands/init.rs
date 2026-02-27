use std::path::PathBuf;

use crate::error::S2Error;
use crate::permissions;

/// Create a new secret file with secure permissions and a header comment.
pub fn run(path: Option<PathBuf>) -> Result<(), S2Error> {
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

    let header = "# Secrets file managed by s2\n# Format: KEY=value or export KEY=value\n# This file should be 0600 — s2 refuses to read group/world-readable files.\n\n";

    std::fs::write(&path, header)?;
    permissions::set_secure_permissions(&path)?;

    eprintln!("Created {} (mode 0600)", path.display());
    Ok(())
}
