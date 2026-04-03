use secrecy::SecretString;

use crate::error::S2Error;
use crate::provider::{SecretProvider, SecretUri};

/// Provider that reads values from the process environment.
/// URI format: env://VAR_NAME
pub struct EnvProvider;

impl SecretProvider for EnvProvider {
    fn scheme(&self) -> &str {
        "env"
    }

    fn display_name(&self) -> &str {
        "environment"
    }

    fn resolve(&self, uri: &SecretUri) -> Result<SecretString, S2Error> {
        // env://VAR_NAME → authority="VAR_NAME", path=""
        // env:///VAR_NAME → authority=None, path="/VAR_NAME"
        let var_name = uri
            .authority
            .as_deref()
            .unwrap_or_else(|| uri.path.trim_start_matches('/'));

        std::env::var(var_name)
            .map(SecretString::from)
            .map_err(|_| S2Error::Provider(format!("environment variable '{}' not set", var_name)))
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::provider::parse_uri;

    #[test]
    fn test_resolve_existing_var() {
        std::env::set_var("S2_TEST_ENV_PROVIDER", "test_value_42");
        let uri = parse_uri("env://S2_TEST_ENV_PROVIDER").unwrap();
        let provider = EnvProvider;
        let result = provider.resolve(&uri).unwrap();
        assert_eq!(result.expose_secret(), "test_value_42");
        std::env::remove_var("S2_TEST_ENV_PROVIDER");
    }

    #[test]
    fn test_resolve_missing_var() {
        let uri = parse_uri("env://S2_NONEXISTENT_VAR_12345").unwrap();
        let provider = EnvProvider;
        assert!(provider.resolve(&uri).is_err());
    }
}
