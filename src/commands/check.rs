use std::path::PathBuf;

use crate::config::Config;
use crate::error::S2Error;
use crate::provider::cache::ProviderCache;
use crate::provider::ProviderRegistry;
use crate::store::SecretStore;

/// Check if all specified keys exist. Exit 0 if yes, exit 1 with missing key names if not.
pub fn run(
    config: &Config,
    registry: ProviderRegistry,
    cache: ProviderCache,
    keys: Vec<String>,
    files: Vec<PathBuf>,
    profile: Option<String>,
) -> Result<(), S2Error> {
    let files = config.resolve_files(&files, &profile)?;

    let mut store = SecretStore::new(Some(registry), Some(cache));
    store.load_files(&files, config)?;

    let mut missing = Vec::new();
    for key in &keys {
        if !store.contains(key) {
            missing.push(key.as_str());
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        for key in &missing {
            eprintln!("missing: {}", key);
        }
        std::process::exit(1);
    }
}
