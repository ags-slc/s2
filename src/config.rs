use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::S2Error;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub default_files: Vec<String>,

    #[serde(default)]
    pub audit_log: Option<String>,

    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub files: Vec<String>,

    #[serde(default)]
    pub keys: Vec<String>,
}

impl Config {
    /// Load config from the default path (~/.config/s2/config.toml).
    /// Returns default config if file doesn't exist.
    pub fn load() -> Result<Self, S2Error> {
        let config_path = config_path();
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            toml::from_str(&content).map_err(|e| S2Error::Config(e.to_string()))
        } else {
            Ok(Config::default())
        }
    }

    /// Resolve files for a command, given CLI flags and optional profile.
    /// Priority: CLI -f flags > profile files > default_files
    pub fn resolve_files(
        &self,
        cli_files: &[PathBuf],
        profile_name: &Option<String>,
    ) -> Result<Vec<PathBuf>, S2Error> {
        if !cli_files.is_empty() {
            return Ok(cli_files.to_vec());
        }

        if let Some(name) = profile_name {
            let profile = self
                .profiles
                .get(name)
                .ok_or_else(|| S2Error::ProfileNotFound(name.clone()))?;
            if !profile.files.is_empty() {
                return Ok(profile.files.iter().map(|f| expand_tilde(f)).collect());
            }
        }

        if !self.default_files.is_empty() {
            return Ok(self.default_files.iter().map(|f| expand_tilde(f)).collect());
        }

        Err(S2Error::NoFiles)
    }

    /// Resolve key filter for a command.
    /// Priority: CLI -k flags > profile keys > empty (all keys)
    pub fn resolve_keys(
        &self,
        cli_keys: &[String],
        profile_name: &Option<String>,
    ) -> Vec<String> {
        if !cli_keys.is_empty() {
            return cli_keys.to_vec();
        }

        if let Some(name) = profile_name {
            if let Some(profile) = self.profiles.get(name) {
                if !profile.keys.is_empty() {
                    return profile.keys.clone();
                }
            }
        }

        Vec::new()
    }

    /// Get audit log path.
    pub fn audit_log_path(&self) -> Option<PathBuf> {
        self.audit_log.as_ref().map(|p| expand_tilde(p))
    }
}

/// Expand `~` to home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        });
    base.join("s2").join("config.toml")
}

/// Resolve a single file for set/unset commands.
/// Uses the provided file, or first default_files entry.
pub fn resolve_single_file(
    config: &Config,
    cli_file: &Option<PathBuf>,
) -> Result<PathBuf, S2Error> {
    if let Some(f) = cli_file {
        Ok(f.clone())
    } else if let Some(first) = config.default_files.first() {
        Ok(expand_tilde(first))
    } else {
        Err(S2Error::NoFiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/foo/bar");
        assert!(expanded.to_str().unwrap().contains("foo/bar"));
        assert!(!expanded.to_str().unwrap().starts_with("~"));
    }

    #[test]
    fn test_parse_config() {
        let content = r#"
default_files = ["~/.secrets"]
audit_log = "~/.config/s2/audit.log"

[profiles.peerdb]
files = ["~/.secrets"]
keys = ["PEERDB_AUTH_TOKEN"]

[profiles.deploy]
files = ["~/.secrets", ".env.local"]
"#;
        let config: Config = toml::from_str(content).unwrap();
        assert_eq!(config.default_files.len(), 1);
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.profiles["peerdb"].keys, vec!["PEERDB_AUTH_TOKEN"]);
    }
}
