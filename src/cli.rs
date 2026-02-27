use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "s2",
    about = "Simple Secrets — inject secrets into subprocesses without ambient environment exposure",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Load secrets and exec a command with them in the environment
    Exec {
        /// Secret files to load
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Only inject these keys (comma-separated)
        #[arg(short = 'k', long = "keys", value_delimiter = ',')]
        keys: Vec<String>,

        /// Use a named profile from config
        #[arg(short = 'p', long = "profile")]
        profile: Option<String>,

        /// Start with a clean environment (only secrets + minimal vars)
        #[arg(long = "clean-env")]
        clean_env: bool,

        /// Command and arguments to execute
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// List secret key names (never values)
    List {
        /// Secret files to load
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Use a named profile from config
        #[arg(short = 'p', long = "profile")]
        profile: Option<String>,
    },

    /// Check if keys exist (exit 0 = all present, exit 1 = missing)
    Check {
        /// Keys to check for
        keys: Vec<String>,

        /// Secret files to load
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Use a named profile from config
        #[arg(short = 'p', long = "profile")]
        profile: Option<String>,
    },

    /// Create a new secret file with secure permissions
    Init {
        /// Path for the new file (default: .env)
        path: Option<PathBuf>,
    },

    /// Set a secret (reads value from stdin, NEVER from arguments)
    Set {
        /// Key name
        key: String,

        /// Target file
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        file: Option<PathBuf>,
    },

    /// Remove a secret from a file
    Unset {
        /// Key name
        key: String,

        /// Target file
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        file: Option<PathBuf>,
    },

    /// Encrypt a file with age (passphrase stored in system keychain)
    Encrypt {
        /// File to encrypt
        path: PathBuf,
    },

    /// Decrypt an age-encrypted file
    Decrypt {
        /// File to decrypt
        path: PathBuf,
    },

    /// Decrypt a file, open in $EDITOR, re-encrypt on save
    Edit {
        /// Encrypted file to edit
        path: PathBuf,
    },

    /// Pipe filter: replace secret values with [REDACTED]
    Redact {
        /// Secret files to load (values become redaction patterns)
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        files: Vec<PathBuf>,

        /// Use a named profile from config
        #[arg(short = 'p', long = "profile")]
        profile: Option<String>,
    },
}
