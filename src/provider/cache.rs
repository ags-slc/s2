use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::config::expand_tilde;
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::permissions;

const CACHE_KEYCHAIN_ID: &str = "provider-cache";

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    value: String,
    fetched_at: DateTime<Utc>,
    ttl_seconds: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProviderCache {
    #[serde(flatten)]
    entries: HashMap<String, CacheEntry>,
}

/// Result of a cache lookup.
pub enum CacheStatus {
    /// Fresh entry within TTL.
    Hit(SecretString),
    /// Expired entry — usable as offline fallback.
    Stale(SecretString),
    /// No entry for this URI.
    Miss,
}

impl ProviderCache {
    /// Load the cache from disk. Returns empty cache if file doesn't exist.
    pub fn load() -> Result<Self, S2Error> {
        let path = cache_path();
        if !path.exists() {
            return Ok(Self::default());
        }

        permissions::check_permissions(&path)?;
        let encrypted = std::fs::read(&path)?;
        let passphrase = keychain::get_passphrase(CACHE_KEYCHAIN_ID)?;
        let plaintext = crypto::decrypt_with_passphrase(&encrypted, &passphrase)?;
        let cache: ProviderCache = toml::from_str(&plaintext)
            .map_err(|e| S2Error::Config(format!("corrupt provider cache: {}", e)))?;
        Ok(cache)
    }

    /// Write the cache to disk (age-encrypted, atomic).
    pub fn save(&self) -> Result<(), S2Error> {
        let path = cache_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let plaintext = toml::to_string_pretty(self)
            .map_err(|e| S2Error::Config(format!("cache serialization: {}", e)))?;

        let passphrase = match keychain::get_passphrase(CACHE_KEYCHAIN_ID) {
            Ok(p) => p,
            Err(_) => {
                let p = crypto::generate_passphrase();
                keychain::store_passphrase(CACHE_KEYCHAIN_ID, &p)?;
                p
            }
        };

        let encrypted = crypto::encrypt_with_passphrase(plaintext.as_bytes(), &passphrase)?;

        // Atomic write via tempfile
        let tmp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap_or(std::path::Path::new("/tmp")))?;
        std::io::Write::write_all(&mut &tmp, &encrypted)?;
        tmp.persist(&path).map_err(|e| S2Error::Io(e.error))?;

        permissions::set_secure_permissions(&path)?;
        Ok(())
    }

    /// Look up a URI in the cache.
    pub fn lookup(&self, uri: &str) -> CacheStatus {
        match self.entries.get(uri) {
            None => CacheStatus::Miss,
            Some(entry) => {
                let age = Utc::now().signed_duration_since(entry.fetched_at);
                let ttl = chrono::Duration::seconds(entry.ttl_seconds as i64);
                if age <= ttl {
                    CacheStatus::Hit(SecretString::from(entry.value.clone()))
                } else {
                    CacheStatus::Stale(SecretString::from(entry.value.clone()))
                }
            }
        }
    }

    /// Insert or update a cache entry.
    pub fn insert(&mut self, uri: String, value: &SecretString, ttl_seconds: u64) {
        self.entries.insert(
            uri,
            CacheEntry {
                value: value.expose_secret().to_string(),
                fetched_at: Utc::now(),
                ttl_seconds,
            },
        );
    }

    /// Returns true if the cache has any entries (indicating it was used and may need flushing).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn cache_path() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| expand_tilde("~/.cache"));
    base.join("s2").join("provider_cache.age")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_miss() {
        let cache = ProviderCache::default();
        assert!(matches!(cache.lookup("ssm:///foo"), CacheStatus::Miss));
    }

    #[test]
    fn test_cache_hit() {
        let mut cache = ProviderCache::default();
        let value = SecretString::from("secret123".to_string());
        cache.insert("ssm:///foo".into(), &value, 3600);

        match cache.lookup("ssm:///foo") {
            CacheStatus::Hit(v) => assert_eq!(v.expose_secret(), "secret123"),
            _ => panic!("expected cache hit"),
        }
    }

    #[test]
    fn test_cache_stale() {
        let mut cache = ProviderCache::default();
        // Insert with TTL of 0 seconds so it's immediately stale
        cache.entries.insert(
            "ssm:///foo".into(),
            CacheEntry {
                value: "old_value".into(),
                fetched_at: Utc::now() - chrono::Duration::seconds(10),
                ttl_seconds: 0,
            },
        );

        match cache.lookup("ssm:///foo") {
            CacheStatus::Stale(v) => assert_eq!(v.expose_secret(), "old_value"),
            _ => panic!("expected stale cache"),
        }
    }
}
