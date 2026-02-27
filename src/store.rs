use std::collections::HashMap;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::crypto;
use crate::error::S2Error;
use crate::parser;
use crate::permissions;

/// Metadata for a loaded secret.
pub struct SecretEntry {
    pub value: SecretString,
    pub source_file: PathBuf,
}

/// In-memory store for loaded secrets. Values are zeroized on drop via SecretString.
pub struct SecretStore {
    secrets: HashMap<String, SecretEntry>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Load secrets from a file. Automatically detects and decrypts age-encrypted files.
    pub fn load_file(&mut self, path: &Path) -> Result<(), S2Error> {
        let canonical = path
            .canonicalize()
            .map_err(|_| S2Error::FileNotFound(path.to_path_buf()))?;

        permissions::check_permissions(&canonical)?;

        let raw_bytes = std::fs::read(&canonical)?;
        let content = if crypto::is_age_encrypted(&raw_bytes) {
            crypto::decrypt_file_content(&canonical, &raw_bytes)?
        } else {
            String::from_utf8(raw_bytes).map_err(|e| {
                S2Error::ParseError {
                    path: canonical.clone(),
                    line: 0,
                    message: format!("invalid UTF-8: {}", e),
                }
            })?
        };

        let entries = parser::parse_file(&canonical, &content)?;
        for entry in entries {
            self.secrets.insert(
                entry.key,
                SecretEntry {
                    value: entry.value,
                    source_file: canonical.clone(),
                },
            );
        }

        Ok(())
    }

    /// Load multiple files.
    pub fn load_files(&mut self, paths: &[PathBuf]) -> Result<(), S2Error> {
        for path in paths {
            self.load_file(path)?;
        }
        Ok(())
    }

    /// Get all key names.
    pub fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self.secrets.keys().map(|s| s.as_str()).collect();
        keys.sort();
        keys
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    /// Get a secret entry by key.
    pub fn get(&self, key: &str) -> Option<&SecretEntry> {
        self.secrets.get(key)
    }

    /// Get all entries, optionally filtered by key list.
    pub fn entries(&self, filter_keys: &[String]) -> Vec<(&str, &SecretEntry)> {
        if filter_keys.is_empty() {
            let mut entries: Vec<_> = self
                .secrets
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect();
            entries.sort_by_key(|(k, _)| *k);
            entries
        } else {
            let mut entries = Vec::new();
            for key in filter_keys {
                if let Some((k, entry)) = self.secrets.get_key_value(key.as_str()) {
                    entries.push((k.as_str(), entry));
                }
            }
            entries.sort_by_key(|(k, _)| *k);
            entries
        }
    }

    /// Get all secret values (for redaction pattern building).
    pub fn values(&self) -> Vec<&SecretString> {
        self.secrets.values().map(|e| &e.value).collect()
    }

    /// Build an environment map from loaded secrets.
    pub fn to_env_map(&self, filter_keys: &[String]) -> HashMap<String, String> {
        let entries = self.entries(filter_keys);
        entries
            .into_iter()
            .map(|(k, e)| (k.to_string(), e.value.expose_secret().to_string()))
            .collect()
    }
}
