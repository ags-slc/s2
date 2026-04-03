mod audit;
mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod keychain;
mod parser;
mod permissions;
mod provider;
mod store;

use clap::Parser;

use cli::{Cli, Command};
use config::Config;
use provider::cache::ProviderCache;
use provider::ProviderRegistry;

fn init_providers(config: &Config) -> (ProviderRegistry, ProviderCache) {
    let registry = match ProviderRegistry::from_config(&config.providers) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("s2: provider init error: {}", e);
            std::process::exit(1);
        }
    };

    let cache = match ProviderCache::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("s2: warning: could not load provider cache: {}", e);
            ProviderCache::default()
        }
    };

    (registry, cache)
}

fn main() {
    let cli = Cli::parse();
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("s2: config error: {}", e);
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Command::Exec {
            files,
            keys,
            profile,
            clean_env,
            cmd,
        } => {
            let (registry, cache) = init_providers(&config);
            commands::exec::run(
                &config, registry, cache, files, keys, profile, clean_env, cmd,
            )
        }

        Command::List { files, profile } => {
            let (registry, cache) = init_providers(&config);
            commands::list::run(&config, registry, cache, files, profile)
        }

        Command::Check {
            keys,
            files,
            profile,
        } => {
            let (registry, cache) = init_providers(&config);
            commands::check::run(&config, registry, cache, keys, files, profile)
        }

        Command::Init { path, no_encrypt } => commands::init::run(path, no_encrypt),

        Command::Set { key, file } => commands::set::run(&config, key, file),

        Command::Unset { key, file } => commands::unset::run(&config, key, file),

        Command::Encrypt { path } => commands::encrypt::run(path),

        Command::Decrypt { path } => commands::decrypt::run(path),

        Command::Edit { path } => commands::edit::run(path),

        Command::Redact { files, profile } => {
            let (registry, cache) = init_providers(&config);
            commands::redact::run(&config, registry, cache, files, profile)
        }

        Command::Hook { format } => commands::hook::run(&config, &format),
    };

    if let Err(e) = result {
        eprintln!("s2: {}", e);
        std::process::exit(1);
    }
}
