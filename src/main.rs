mod audit;
mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod keychain;
mod parser;
mod permissions;
mod store;

use clap::Parser;

use cli::{Cli, Command};
use config::Config;

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
        } => commands::exec::run(&config, files, keys, profile, clean_env, cmd),

        Command::List { files, profile } => commands::list::run(&config, files, profile),

        Command::Check {
            keys,
            files,
            profile,
        } => commands::check::run(&config, keys, files, profile),

        Command::Init { path } => commands::init::run(path),

        Command::Set { key, file } => commands::set::run(&config, key, file),

        Command::Unset { key, file } => commands::unset::run(&config, key, file),

        Command::Encrypt { path } => commands::encrypt::run(path),

        Command::Decrypt { path } => commands::decrypt::run(path),

        Command::Edit { path } => commands::edit::run(path),

        Command::Redact { files, profile } => commands::redact::run(&config, files, profile),
    };

    if let Err(e) = result {
        eprintln!("s2: {}", e);
        std::process::exit(1);
    }
}
