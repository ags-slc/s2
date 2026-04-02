use std::path::PathBuf;

use crate::audit;
use crate::config::Config;
use crate::error::S2Error;
use crate::provider::cache::ProviderCache;
use crate::provider::ProviderRegistry;
use crate::store::SecretStore;

/// List secret key names, source files, and file modification times.
/// Never shows values.
pub fn run(
    config: &Config,
    registry: ProviderRegistry,
    cache: ProviderCache,
    files: Vec<PathBuf>,
    profile: Option<String>,
) -> Result<(), S2Error> {
    let files = config.resolve_files(&files, &profile)?;

    let mut store = SecretStore::new(Some(registry), Some(cache));
    store.load_files(&files, config)?;

    audit::log_access(config, "list", &format!("files={}", files.len()));

    let entries = store.entries(&[]);
    if entries.is_empty() {
        eprintln!("No secrets found.");
        return Ok(());
    }

    // Find max key width for alignment
    let max_key = entries.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

    for (key, entry) in &entries {
        let source = entry.source_file.display();
        if let Some(ref uri) = entry.source_uri {
            println!("{:<width$}  {}  ({})", key, source, uri, width = max_key);
        } else {
            println!("{:<width$}  {}", key, source, width = max_key);
        }
    }

    Ok(())
}
