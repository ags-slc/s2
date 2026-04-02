use std::path::PathBuf;

use secrecy::SecretString;

use crate::config::{expand_tilde, ProviderConfig};
use crate::error::S2Error;
use crate::provider::{SecretProvider, SecretUri};

/// Provider for HashiCorp Vault KV v2 secrets engine.
/// URI format: vault://mount/path/to/secret#field
///   - authority = mount point (e.g., "secret")
///   - path = secret path (e.g., "/data/api")
///   - fragment = JSON field to extract (optional, returns full JSON if absent)
pub struct VaultProvider {
    address: String,
    token_path: PathBuf,
}

impl VaultProvider {
    pub fn new(config: Option<&ProviderConfig>) -> Result<Self, S2Error> {
        let address = config
            .and_then(|c| c.settings.get("address"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| std::env::var("VAULT_ADDR").ok())
            .ok_or_else(|| {
                S2Error::Provider(
                    "vault provider requires 'address' in config or VAULT_ADDR env var".into(),
                )
            })?;

        let token_path = config
            .and_then(|c| c.settings.get("token_path"))
            .and_then(|v| v.as_str())
            .map(|p| expand_tilde(p))
            .unwrap_or_else(|| expand_tilde("~/.vault-token"));

        Ok(Self {
            address,
            token_path,
        })
    }

    fn read_token(&self) -> Result<String, S2Error> {
        // Try VAULT_TOKEN env var first, then token file
        if let Ok(token) = std::env::var("VAULT_TOKEN") {
            return Ok(token);
        }

        std::fs::read_to_string(&self.token_path)
            .map(|t| t.trim().to_string())
            .map_err(|e| {
                S2Error::Provider(format!(
                    "vault token not found (set VAULT_TOKEN or create {}): {}",
                    self.token_path.display(),
                    e
                ))
            })
    }
}

impl SecretProvider for VaultProvider {
    fn scheme(&self) -> &str {
        "vault"
    }

    fn display_name(&self) -> &str {
        "HashiCorp Vault"
    }

    fn resolve(&self, uri: &SecretUri) -> Result<SecretString, S2Error> {
        let token = self.read_token()?;

        let mount = uri.authority.as_deref().unwrap_or("secret");

        // Build the KV v2 API URL: /v1/{mount}/data/{path}
        let api_path = format!(
            "{}/v1/{}/data{}",
            self.address.trim_end_matches('/'),
            mount,
            uri.path
        );

        let response = reqwest::blocking::Client::new()
            .get(&api_path)
            .header("X-Vault-Token", &token)
            .send()
            .map_err(|e| S2Error::Provider(format!("Vault request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(S2Error::Provider(format!(
                "Vault returned {}: {}",
                response.status(),
                uri.raw
            )));
        }

        let body: serde_json::Value = response
            .json()
            .map_err(|e| S2Error::Provider(format!("Vault response parse error: {}", e)))?;

        // KV v2 response structure: { "data": { "data": { "field": "value" } } }
        let data = body
            .get("data")
            .and_then(|d| d.get("data"))
            .ok_or_else(|| {
                S2Error::Provider(format!("Vault: unexpected response structure for {}", uri.raw))
            })?;

        let value = if let Some(ref field) = uri.fragment {
            data.get(field)
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    S2Error::Provider(format!(
                        "Vault: field '{}' not found in {}",
                        field, uri.raw
                    ))
                })?
                .to_string()
        } else {
            // No fragment — return the full data object as JSON string
            data.to_string()
        };

        Ok(SecretString::from(value))
    }
}
