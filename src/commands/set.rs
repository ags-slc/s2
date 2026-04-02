use std::io::Read;
use std::path::PathBuf;

use secrecy::SecretString;

use crate::config::{self, Config};
use crate::error::S2Error;
use crate::parser::{self, ParsedEntry};
use crate::permissions;

/// Set a secret by reading the value from stdin.
/// Never accepts the value as a CLI argument (prevents shell history exposure).
pub fn run(config: &Config, key: String, file: Option<PathBuf>) -> Result<(), S2Error> {
    let path = config::resolve_single_file(config, &file)?;

    // Read value from stdin
    if atty::is(atty::Stream::Stdin) {
        eprint!("Enter value for {}: ", key);
    }

    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;
    let value = value.trim_end_matches('\n').to_string();

    if value.is_empty() {
        eprintln!("Error: empty value");
        std::process::exit(1);
    }

    // Load existing file content (or create new)
    let mut entries = if path.exists() {
        permissions::check_permissions(&path)?;
        let content = std::fs::read_to_string(&path)?;
        parser::parse_file(&path, &content)?
    } else {
        Vec::new()
    };

    // Replace existing or append
    let mut found = false;
    for entry in &mut entries {
        if entry.key == key {
            entry.value = SecretString::from(value.clone());
            found = true;
            break;
        }
    }

    if !found {
        entries.push(ParsedEntry {
            key: key.clone(),
            value: SecretString::from(value),
            source_uri: None,
        });
    }

    // Write back
    let content = parser::serialize_entries(&entries);
    std::fs::write(&path, content)?;
    permissions::set_secure_permissions(&path)?;

    if found {
        eprintln!("Updated: {}", key);
    } else {
        eprintln!("Added: {}", key);
    }

    Ok(())
}
