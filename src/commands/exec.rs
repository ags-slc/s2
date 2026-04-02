use std::ffi::CString;
use std::path::PathBuf;

use crate::audit;
use crate::config::Config;
use crate::error::S2Error;
use crate::provider::cache::ProviderCache;
use crate::provider::ProviderRegistry;
use crate::store::SecretStore;

/// Load secrets and exec the given command, replacing the current process.
pub fn run(
    config: &Config,
    registry: ProviderRegistry,
    cache: ProviderCache,
    files: Vec<PathBuf>,
    keys: Vec<String>,
    profile: Option<String>,
    clean_env: bool,
    cmd: Vec<String>,
) -> Result<(), S2Error> {
    let files = config.resolve_files(&files, &profile)?;
    let keys = config.resolve_keys(&keys, &profile);

    let mut store = SecretStore::new(Some(registry), Some(cache));
    store.load_files(&files, config)?;

    let env_map = store.to_env_map(&keys);

    // Audit log
    let key_names: Vec<&str> = env_map.keys().map(|s| s.as_str()).collect();
    audit::log_access(
        config,
        "exec",
        &format!("cmd={} keys=[{}]", cmd[0], key_names.join(",")),
    );

    // Flush provider cache before execve (destructors won't run after process replacement)
    store.flush_cache()?;

    // Build environment
    let mut env_vars: Vec<(String, String)> = if clean_env {
        let keep = ["PATH", "HOME", "TERM", "USER", "SHELL", "LANG"];
        keep.iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect()
    } else {
        std::env::vars().collect()
    };

    // Overlay secrets
    for (k, v) in &env_map {
        env_vars.retain(|(ek, _)| ek != k);
        env_vars.push((k.clone(), v.clone()));
    }

    // Resolve program path via PATH lookup
    let program = resolve_program(&cmd[0], &env_vars)?;

    let c_program = CString::new(program.to_string_lossy().as_ref())
        .map_err(|e| S2Error::ExecFailed(format!("invalid command: {}", e)))?;

    let c_args: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    let c_env: Vec<CString> = env_vars
        .iter()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
        .collect();

    // execve replaces the current process — this does not return on success
    nix::unistd::execve(&c_program, &c_args, &c_env)
        .map_err(|e| S2Error::ExecFailed(format!("exec failed: {}", e)))?;

    unreachable!()
}

/// Resolve a program name to an absolute path by searching PATH.
fn resolve_program(name: &str, env_vars: &[(String, String)]) -> Result<PathBuf, S2Error> {
    // If it contains a slash, use as-is
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }

    // Search PATH
    let path_var = env_vars
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("/usr/bin:/bin");

    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(S2Error::ExecFailed(format!(
        "command not found: {}",
        name
    )))
}
