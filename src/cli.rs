use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

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

    /// Create a new secret file (encrypted by default)
    Init {
        /// Path for the new file (default: .env)
        path: Option<PathBuf>,

        /// Create as plaintext instead of encrypted
        #[arg(long = "no-encrypt")]
        no_encrypt: bool,
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

    /// Scan files for secrets (pattern matching + entropy analysis)
    Scan {
        /// Files or directories to scan (default: current directory)
        paths: Vec<PathBuf>,

        /// Only scan git staged files (pre-commit hook mode)
        #[arg(long)]
        staged: bool,

        /// Include files ignored by .gitignore and hidden dotfiles like .env
        /// (vendored directories like node_modules/ and target/ are still skipped)
        #[arg(long)]
        no_ignore: bool,

        /// Output as JSON (one finding per line)
        #[arg(long)]
        json: bool,

        /// Shannon entropy threshold for medium-confidence detection (default: 4.5)
        #[arg(long, default_value = "4.5")]
        entropy: f64,

        /// Test coverage against a file of known secrets and suggest new rules
        #[arg(long, value_name = "FILE")]
        learn: Option<PathBuf>,

        /// Add finding hashes to .s2allowlist (skips them in future scans)
        #[arg(long, value_name = "HASH")]
        allow: Vec<String>,

        /// Add finding hashes to .s2allowlist with source context comments
        /// (runs a scan first to look up file, line, rule, and description)
        #[arg(long, value_name = "HASH", conflicts_with_all = ["allow", "learn", "list_rules"])]
        allow_with_context: Vec<String>,

        /// List all built-in and custom scan rules, then exit
        #[arg(long)]
        list_rules: bool,
    },

    /// AI agent PreToolUse hook (reads JSON from stdin, emits JSON to stdout)
    Hook {
        /// Agent hook format
        #[arg(long, value_enum, default_value = "claude")]
        format: HookFormat,
    },

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for
        shell: Shell,
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

#[derive(ValueEnum, Clone, Debug)]
pub enum HookFormat {
    /// Claude Code / GitHub Copilot
    Claude,
    /// GitHub Copilot (alias for claude)
    Copilot,
    /// Cursor IDE
    Cursor,
}
