use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use chrono::Utc;

use crate::config::Config;

/// Append an entry to the audit log.
/// Format: `TIMESTAMP | COMMAND | DETAILS`
/// Silently ignores errors (audit should never block operation).
pub fn log_access(config: &Config, command: &str, details: &str) {
    let Some(log_path) = config.audit_log_path() else {
        return;
    };

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let line = format!("{} | {} | {}\n", timestamp, command, details);

    let _ = append_to_file(&log_path, &line);
}

fn append_to_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
