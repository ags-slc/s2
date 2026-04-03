pub mod cache;
pub mod env;

#[cfg(feature = "provider-ssm")]
pub mod ssm;

#[cfg(feature = "provider-vault")]
pub mod vault;

use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};

use crate::audit;
use crate::config::{Config, ProviderConfig};
use crate::error::S2Error;
use crate::parser::ParsedEntry;

use cache::{CacheStatus, ProviderCache};

/// A parsed URI reference found in a secret value.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SecretUri {
    pub scheme: String,
    pub authority: Option<String>,
    pub path: String,
    pub fragment: Option<String>,
    pub raw: String,
}

/// Trait that all secret providers implement.
#[allow(dead_code)]
pub trait SecretProvider: Send + Sync {
    /// The URI scheme this provider handles (e.g., "ssm", "vault", "env").
    fn scheme(&self) -> &str;

    /// Resolve a URI to a secret value.
    fn resolve(&self, uri: &SecretUri) -> Result<SecretString, S2Error>;

    /// Human-readable name for audit logs.
    fn display_name(&self) -> &str;
}

/// Registry of all compiled-in providers.
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn SecretProvider>>,
}

impl ProviderRegistry {
    /// Build registry from config. Only includes providers whose feature flags are enabled.
    pub fn from_config(
        provider_configs: &HashMap<String, ProviderConfig>,
    ) -> Result<Self, S2Error> {
        let mut providers = HashMap::<String, Box<dyn SecretProvider>>::new();

        // env:// is always available
        providers.insert("env".into(), Box::new(env::EnvProvider));

        #[cfg(feature = "provider-ssm")]
        {
            let cfg = provider_configs.get("ssm");
            providers.insert("ssm".into(), Box::new(ssm::SsmProvider::new(cfg)?));
        }

        #[cfg(feature = "provider-vault")]
        {
            let cfg = provider_configs.get("vault");
            match vault::VaultProvider::new(cfg) {
                Ok(p) => {
                    providers.insert("vault".into(), Box::new(p));
                }
                Err(_) => {
                    // Vault not configured — skip (no address/VAULT_ADDR). Will error
                    // at resolve time if a vault:// URI is actually used.
                }
            }
        }

        Ok(Self { providers })
    }

    pub fn get(&self, scheme: &str) -> Option<&dyn SecretProvider> {
        self.providers.get(scheme).map(|b| b.as_ref())
    }
}

/// Parse a provider URI string into its components.
/// Returns None if the string doesn't match a known `scheme://` pattern.
pub fn parse_uri(raw: &str) -> Option<SecretUri> {
    let scheme_end = raw.find("://")?;
    let scheme = &raw[..scheme_end];

    // Only recognize known schemes to avoid false positives on literal values
    if !matches!(scheme, "ssm" | "vault" | "env") {
        return None;
    }

    let rest = &raw[scheme_end + 3..];

    // Split off fragment
    let (rest, fragment) = match rest.rfind('#') {
        Some(pos) => (&rest[..pos], Some(rest[pos + 1..].to_string())),
        None => (rest, None),
    };

    // Determine authority vs path.
    // ssm:///path → authority=None, path="/path" (triple-slash = no authority)
    // vault://secret/data/api → authority="secret", path="/data/api"
    let (authority, path) = if rest.starts_with('/') {
        (None, rest.to_string())
    } else {
        match rest.find('/') {
            Some(pos) => (Some(rest[..pos].to_string()), rest[pos..].to_string()),
            None => (Some(rest.to_string()), String::new()),
        }
    };

    Some(SecretUri {
        scheme: scheme.to_string(),
        authority,
        path,
        fragment,
        raw: raw.to_string(),
    })
}

/// Resolve all provider URI references in a list of parsed entries.
/// Literal values pass through unchanged. Provider URIs are resolved via:
/// cache (hit) → provider (fresh) → cache (stale fallback) → error.
pub fn resolve_entries(
    entries: Vec<ParsedEntry>,
    registry: &ProviderRegistry,
    cache: &mut ProviderCache,
    config: &Config,
) -> Result<Vec<ParsedEntry>, S2Error> {
    let mut resolved = Vec::with_capacity(entries.len());
    let mut cache_dirty = false;

    for entry in entries {
        let raw_value = entry.value.expose_secret().to_string();

        if let Some(uri) = parse_uri(&raw_value) {
            let provider = registry.get(&uri.scheme).ok_or_else(|| {
                S2Error::Provider(format!(
                    "no provider for scheme '{}' (is the feature flag enabled?): {}",
                    uri.scheme, uri.raw
                ))
            })?;

            let ttl = config
                .providers
                .get(&uri.scheme)
                .and_then(|pc| pc.ttl_seconds)
                .unwrap_or(config.provider_ttl_seconds);

            let (secret, wrote_cache) = resolve_single(&uri, provider, cache, ttl)?;

            if wrote_cache {
                cache_dirty = true;
            }

            audit::log_access(
                config,
                "provider",
                &format!("scheme={} provider={}", uri.scheme, provider.display_name()),
            );

            resolved.push(ParsedEntry {
                key: entry.key,
                value: secret,
                source_uri: Some(uri.raw),
            });
        } else {
            resolved.push(entry);
        }
    }

    if cache_dirty {
        cache.save()?;
    }

    Ok(resolved)
}

/// Resolve a single provider URI with cache + offline fallback.
fn resolve_single(
    uri: &SecretUri,
    provider: &dyn SecretProvider,
    cache: &mut ProviderCache,
    ttl: u64,
) -> Result<(SecretString, bool), S2Error> {
    match cache.lookup(&uri.raw) {
        CacheStatus::Hit(value) => Ok((value, false)),

        CacheStatus::Stale(stale_value) => {
            // TTL expired — try provider, fall back to stale cache (offline resilience)
            match provider.resolve(uri) {
                Ok(fresh) => {
                    cache.insert(uri.raw.clone(), &fresh, ttl);
                    Ok((fresh, true))
                }
                Err(_) => Ok((stale_value, false)),
            }
        }

        CacheStatus::Miss => {
            // No cache — must reach provider
            match provider.resolve(uri) {
                Ok(fresh) => {
                    cache.insert(uri.raw.clone(), &fresh, ttl);
                    Ok((fresh, true))
                }
                Err(e) => Err(S2Error::Provider(format!(
                    "failed to resolve '{}' and no cached value available: {}",
                    uri.raw, e
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uri_ssm() {
        let uri = parse_uri("ssm:///prod/db/password").unwrap();
        assert_eq!(uri.scheme, "ssm");
        assert!(uri.authority.is_none());
        assert_eq!(uri.path, "/prod/db/password");
        assert!(uri.fragment.is_none());
    }

    #[test]
    fn test_parse_uri_vault_with_fragment() {
        let uri = parse_uri("vault://secret/data/api#key").unwrap();
        assert_eq!(uri.scheme, "vault");
        assert_eq!(uri.authority.as_deref(), Some("secret"));
        assert_eq!(uri.path, "/data/api");
        assert_eq!(uri.fragment.as_deref(), Some("key"));
    }

    #[test]
    fn test_parse_uri_env() {
        let uri = parse_uri("env://DATABASE_URL").unwrap();
        assert_eq!(uri.scheme, "env");
        assert_eq!(uri.authority.as_deref(), Some("DATABASE_URL"));
        assert_eq!(uri.path, "");
        assert!(uri.fragment.is_none());
    }

    #[test]
    fn test_parse_uri_unknown_scheme() {
        assert!(parse_uri("ftp://example.com/file").is_none());
    }

    #[test]
    fn test_parse_uri_not_a_uri() {
        assert!(parse_uri("just-a-plain-value").is_none());
        assert!(parse_uri("key=value").is_none());
        assert!(parse_uri("").is_none());
    }
}
