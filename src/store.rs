use std::collections::HashMap;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::crypto;
use crate::error::S2Error;
use crate::parser;
use crate::permissions;
use crate::provider::cache::ProviderCache;
use crate::provider::ProviderRegistry;

/// Metadata for a loaded secret.
pub struct SecretEntry {
    pub value: SecretString,
    pub source_file: PathBuf,
    /// If this value was resolved from a provider URI, stores the original URI.
    pub source_uri: Option<String>,
}

/// In-memory store for loaded secrets. Values are zeroized on drop via SecretString.
pub struct SecretStore {
    secrets: HashMap<String, SecretEntry>,
    registry: Option<ProviderRegistry>,
    cache: Option<ProviderCache>,
}

impl SecretStore {
    pub fn new(registry: Option<ProviderRegistry>, cache: Option<ProviderCache>) -> Self {
        Self {
            secrets: HashMap::new(),
            registry,
            cache,
        }
    }

    /// Load secrets from a file. Automatically detects and decrypts age-encrypted files.
    /// If a provider registry is present, resolves any provider URI references.
    pub fn load_file(
        &mut self,
        path: &Path,
        config: &crate::config::Config,
    ) -> Result<(), S2Error> {
        let canonical = path
            .canonicalize()
            .map_err(|_| S2Error::FileNotFound(path.to_path_buf()))?;

        permissions::check_permissions(&canonical)?;

        let raw_bytes = std::fs::read(&canonical)?;
        let content = if crypto::is_age_encrypted(&raw_bytes) {
            crypto::decrypt_file_content(&canonical, &raw_bytes)?
        } else {
            String::from_utf8(raw_bytes).map_err(|e| S2Error::ParseError {
                path: canonical.clone(),
                line: 0,
                message: format!("invalid UTF-8: {}", e),
            })?
        };

        let mut entries = parser::parse_file(&canonical, &content)?;

        // Resolve provider URI references if we have a registry
        if let (Some(registry), Some(cache)) = (&self.registry, &mut self.cache) {
            entries = crate::provider::resolve_entries(entries, registry, cache, config)?;
        }

        for entry in entries {
            self.secrets.insert(
                entry.key,
                SecretEntry {
                    value: entry.value,
                    source_file: canonical.clone(),
                    source_uri: entry.source_uri,
                },
            );
        }

        Ok(())
    }

    /// Load multiple files.
    pub fn load_files(
        &mut self,
        paths: &[PathBuf],
        config: &crate::config::Config,
    ) -> Result<(), S2Error> {
        for path in paths {
            self.load_file(path, config)?;
        }
        Ok(())
    }

    /// Flush the provider cache to disk. Must be called before execve
    /// since destructors won't run after process replacement.
    pub fn flush_cache(&mut self) -> Result<(), S2Error> {
        if let Some(ref cache) = self.cache {
            if !cache.is_empty() {
                cache.save()?;
            }
        }
        Ok(())
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    /// Get all entries, optionally filtered by key list.
    pub fn entries(&self, filter_keys: &[String]) -> Vec<(&str, &SecretEntry)> {
        if filter_keys.is_empty() {
            let mut entries: Vec<_> = self.secrets.iter().map(|(k, v)| (k.as_str(), v)).collect();
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
