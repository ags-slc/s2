use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use aho_corasick::AhoCorasick;
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::error::S2Error;
use crate::provider::cache::ProviderCache;
use crate::provider::ProviderRegistry;
use crate::store::SecretStore;

/// Stream stdin to stdout, replacing any secret values with [REDACTED].
/// Uses Aho-Corasick for efficient multi-pattern matching.
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

    // Build patterns from secret values (only non-empty values)
    let patterns: Vec<String> = store
        .values()
        .into_iter()
        .map(|v| v.expose_secret().to_string())
        .filter(|v| !v.is_empty())
        .collect();

    if patterns.is_empty() {
        // No patterns — just pass through
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = line?;
            writeln!(out, "{}", line)?;
        }
        return Ok(());
    }

    let ac = AhoCorasick::new(&patterns)
        .map_err(|e| S2Error::Config(format!("failed to build pattern matcher: {}", e)))?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let redacted = ac.replace_all(&line, &vec!["[REDACTED]"; patterns.len()]);
        writeln!(out, "{}", redacted)?;
    }

    Ok(())
}
