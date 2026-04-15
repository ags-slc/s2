use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::S2Error;
use crate::mask::redact_match;
use crate::parser;

struct ScanRule {
    id: String,
    description: String,
    regex: Regex,
    keyword: Option<String>,
}

#[derive(serde::Serialize)]
struct Finding {
    file: String,
    line: usize,
    key: Option<String>,
    rule: String,
    description: String,
    #[serde(rename = "match")]
    matched: String,
    confidence: String,
    hash: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    allowed: bool,
}

// --- Key name patterns that boost confidence ---

const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "key",
    "credential",
    "auth",
    "private",
    "cert",
    "api_key",
    "apikey",
    "access_key",
];

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|pat| lower.contains(pat))
}

/// Common placeholder/default values that should not trigger entropy detection.
/// Only applied in the entropy branch — pattern matches (Layer 1) always fire.
fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.contains("changeme")
        || lower.contains("replace_me")
        || lower.contains("replaceme")
        || lower.contains("placeholder")
        || lower.contains("insert_your")
        || lower.contains("insert-your")
        || (lower.contains("your") && lower.contains("here"))
}

// --- Rules ---

fn build_rules(config: &Config) -> Result<Vec<ScanRule>, S2Error> {
    // (id, description, pattern, optional keyword gate)
    let builtins: Vec<(&str, &str, &str, Option<&str>)> = vec![
        (
            "aws-access-key",
            "AWS Access Key",
            r"\b(AKIA|A3T[A-Z0-9]|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
            None,
        ),
        (
            "github-token",
            "GitHub Token",
            r"\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b",
            None,
        ),
        (
            "github-fine-pat",
            "GitHub Fine-Grained PAT",
            r"github_pat_\w{82}",
            None,
        ),
        (
            "stripe-key",
            "Stripe Secret Key",
            r"\b[sr]k_(test|live|prod)_[a-zA-Z0-9]{10,99}\b",
            None,
        ),
        (
            "slack-token",
            "Slack Token",
            r"xox[bpears]-[0-9a-zA-Z\-]{10,}",
            None,
        ),
        (
            "slack-webhook",
            "Slack Webhook URL",
            r"hooks\.slack\.com/services/[A-Za-z0-9+/]{43,}",
            None,
        ),
        (
            "private-key",
            "PEM Private Key",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            None,
        ),
        (
            "jwt",
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            None,
        ),
        (
            "google-api-key",
            "Google API Key",
            r"AIza[0-9A-Za-z\-_]{35}",
            None,
        ),
        (
            "twilio-key",
            "Twilio API Key",
            r"\bSK[0-9a-fA-F]{32}\b",
            None,
        ),
        (
            "sendgrid-key",
            "SendGrid API Key",
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            None,
        ),
        // Provider-specific patterns for tokens that evade entropy detection
        // (hex-charset tokens cap at ~4.0 entropy, below the 4.5 generic threshold)
        (
            "shopify-token",
            "Shopify Access Token",
            r"\bshpat_[a-fA-F0-9]{32,}\b",
            None,
        ),
        (
            "shopify-shared-secret",
            "Shopify App Shared Secret",
            r"\bshpss_[a-fA-F0-9]{32,}\b",
            None,
        ),
        (
            "gitlab-pat",
            "GitLab Personal Access Token",
            r"\bglpat-[a-zA-Z0-9_-]{20,}\b",
            None,
        ),
        (
            "digitalocean-token",
            "DigitalOcean Token",
            r"\bdop_v1_[a-fA-F0-9]{64}\b",
            None,
        ),
        (
            "anthropic-key",
            "Anthropic API Key",
            r"\bsk-ant-[a-zA-Z0-9_-]{80,}\b",
            None,
        ),
        (
            "openai-key",
            "OpenAI API Key",
            r"\bsk-proj-[a-zA-Z0-9]{40,}\b",
            None,
        ),
        (
            "npm-token",
            "npm Access Token",
            r"\bnpm_[a-zA-Z0-9]{36,}\b",
            None,
        ),
        (
            "pypi-token",
            "PyPI API Token",
            r"\bpypi-[a-zA-Z0-9]{50,}\b",
            None,
        ),
        // Prefix-based providers
        (
            "supabase-key",
            "Supabase API Key",
            r"\bsbp_[a-fA-F0-9]{40,}\b",
            None,
        ),
        // Keyword-gated providers: generic value patterns that only fire when
        // the key name contains the provider name, avoiding false positives
        (
            "datadog-key",
            "Datadog API/App Key",
            r"\b[a-fA-F0-9]{32,40}\b",
            Some("datadog"),
        ),
        (
            "heroku-key",
            "Heroku API Key",
            r"\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b",
            Some("heroku"),
        ),
        (
            "azure-key",
            "Azure Secret",
            r"\b[a-zA-Z0-9+/]{32,}={0,2}\b",
            Some("azure"),
        ),
    ];

    let mut rules: Vec<ScanRule> = builtins
        .into_iter()
        .map(|(id, desc, pat, kw)| ScanRule {
            id: id.to_string(),
            description: desc.to_string(),
            regex: Regex::new(pat).unwrap(),
            keyword: kw.map(|s| s.to_string()),
        })
        .collect();

    for custom in &config.scan.rules {
        let regex = Regex::new(&custom.pattern).map_err(|e| {
            S2Error::Config(format!("invalid regex in scan rule '{}': {}", custom.id, e))
        })?;
        rules.push(ScanRule {
            id: custom.id.clone(),
            description: custom.description.clone(),
            regex,
            keyword: custom.keyword.as_ref().map(|k| k.to_lowercase()),
        });
    }

    Ok(rules)
}

// --- Entropy ---

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// --- Utilities ---

fn is_binary(content: &[u8]) -> bool {
    let check_len = content.len().min(8192);
    content[..check_len].contains(&0)
}

fn compute_finding_hash(key: Option<&str>, raw_value: &str) -> String {
    let mut hasher = Sha256::new();
    if let Some(k) = key {
        hasher.update(k.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(raw_value.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}

// --- Allowlist ---

fn load_allowlist() -> HashSet<String> {
    let path = Path::new(".s2allowlist");
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn is_allowed(hash: &str, allowlist: &HashSet<String>) -> bool {
    allowlist
        .iter()
        .any(|entry| entry.starts_with(hash) || hash.starts_with(entry))
}

fn validate_hashes(hashes: &[String]) -> Result<(), S2Error> {
    for h in hashes {
        if h.len() < 8 {
            return Err(S2Error::Config(format!(
                "hash too short (minimum 8 characters): {}",
                h
            )));
        }
        if !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(S2Error::Config(format!(
                "invalid hash (must be hex): {}",
                h
            )));
        }
    }
    Ok(())
}

fn open_allowlist_append() -> Result<std::fs::File, S2Error> {
    let path = Path::new(".s2allowlist");
    let needs_leading_newline = path.exists()
        && std::fs::read(path)
            .map(|bytes| !bytes.is_empty() && !bytes.ends_with(b"\n"))
            .unwrap_or(false);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| S2Error::Config(format!("failed to open .s2allowlist: {}", e)))?;

    if needs_leading_newline {
        writeln!(file)
            .map_err(|e| S2Error::Config(format!("failed to write .s2allowlist: {}", e)))?;
    }

    Ok(file)
}

fn add_to_allowlist(hashes: &[String]) -> Result<(), S2Error> {
    validate_hashes(hashes)?;

    let existing = load_allowlist();

    let added: Vec<&str> = hashes
        .iter()
        .filter(|h| {
            if is_allowed(h, &existing) {
                eprintln!("Already in .s2allowlist: {}", h);
                false
            } else {
                true
            }
        })
        .map(|h| h.as_str())
        .collect();

    if added.is_empty() {
        return Ok(());
    }

    let mut file = open_allowlist_append()?;

    for h in &added {
        writeln!(file, "{}", h)
            .map_err(|e| S2Error::Config(format!("failed to write .s2allowlist: {}", e)))?;
    }

    eprintln!("Added {} hash(es) to .s2allowlist", added.len());
    Ok(())
}

fn add_to_allowlist_with_context(hashes: &[String], findings: &[Finding]) -> Result<(), S2Error> {
    let normalized: Vec<String> = hashes.iter().map(|h| h.to_ascii_lowercase()).collect();
    validate_hashes(&normalized)?;

    let existing = load_allowlist();

    let mut seen: HashSet<String> = HashSet::new();
    let added: Vec<&str> = normalized
        .iter()
        .filter(|h| {
            if is_allowed(h, &existing) {
                eprintln!("Already in .s2allowlist: {}", h);
                return false;
            }
            if is_allowed(h, &seen) {
                eprintln!("Duplicate in input: {}", h);
                return false;
            }
            seen.insert(h.to_string());
            true
        })
        .map(|h| h.as_str())
        .collect();

    if added.is_empty() {
        return Ok(());
    }

    let mut file = open_allowlist_append()?;

    for h in &added {
        let matches: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.hash.starts_with(h) || h.starts_with(f.hash.as_str()))
            .collect();

        if matches.len() > 1 {
            eprintln!(
                "Warning: hash prefix {} matches {} findings — using first match",
                h,
                matches.len()
            );
        }

        if let Some(f) = matches.first() {
            let ctx = match &f.key {
                Some(k) => format!(
                    "# {}:{} — {} — {} ({})",
                    f.file, f.line, k, f.rule, f.description
                ),
                None => format!("# {}:{} — {} ({})", f.file, f.line, f.rule, f.description),
            };
            writeln!(file, "{}", ctx)
                .map_err(|e| S2Error::Config(format!("failed to write .s2allowlist: {}", e)))?;
        }
        writeln!(file, "{}", h)
            .map_err(|e| S2Error::Config(format!("failed to write .s2allowlist: {}", e)))?;
    }

    eprintln!(
        "Added {} hash(es) to .s2allowlist (with context)",
        added.len()
    );
    Ok(())
}

fn collect_staged_files() -> Result<Vec<PathBuf>, S2Error> {
    let output = process::Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .map_err(|e| S2Error::Config(format!("failed to run git: {}", e)))?;

    if !output.status.success() {
        return Err(S2Error::Config(
            "git diff --cached failed (not a git repository?)".to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}

/// Directories that are always skipped during scanning, even with --no-ignore.
/// These contain vendored third-party code or build artifacts — scanning them
/// produces noise with no security benefit.
const BUILTIN_SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "target",
    "dist",
    "build",
    "out",
    "_build",
    ".gradle",
    ".m2",
    ".cargo",
    ".bundle",
    "Pods",
    "bower_components",
    ".nuget",
    ".next",
    ".git",
];

fn collect_files(paths: &[PathBuf], no_ignore: bool, extra_skip_dirs: &[String]) -> Vec<PathBuf> {
    let skip_dirs: HashSet<String> = BUILTIN_SKIP_DIRS
        .iter()
        .map(|s| (*s).to_owned())
        .chain(extra_skip_dirs.iter().cloned())
        .collect();
    let skip_dirs = std::sync::Arc::new(skip_dirs);

    let mut files = Vec::new();
    for path in paths {
        if path.is_file() || (path.exists() && !path.is_dir()) {
            files.push(path.clone());
        } else if path.is_dir() {
            let mut builder = ignore::WalkBuilder::new(path);
            builder.hidden(true);
            if no_ignore {
                builder
                    .hidden(false)
                    .git_ignore(false)
                    .git_exclude(false)
                    .git_global(false);
            }
            let skip = skip_dirs.clone();
            builder.filter_entry(move |entry| {
                if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                    if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                        return !skip.contains(name);
                    }
                }
                true
            });
            for entry in builder.build().flatten() {
                if entry.file_type().is_some_and(|ft| ft.is_file()) {
                    files.push(entry.into_path());
                }
            }
        }
    }
    files
}

// --- Core scanning ---

/// Test a single value against all rules and entropy.
/// Returns the finding if detected, None otherwise.
fn test_value(
    value: &str,
    key: Option<&str>,
    rules: &[ScanRule],
    entropy_threshold: f64,
) -> Option<(String, String, String)> {
    // Layer 1: pattern matching against the value
    let line_lower = value.to_lowercase();
    for rule in rules {
        if let Some(ref kw) = rule.keyword {
            // Check keyword against both key name and value
            let key_lower = key.map(|k| k.to_lowercase()).unwrap_or_default();
            if !line_lower.contains(kw) && !key_lower.contains(kw) {
                continue;
            }
        }
        if rule.regex.is_match(value) {
            return Some((rule.id.clone(), rule.description.clone(), "high".into()));
        }
    }

    // Layer 2: entropy analysis on the value
    // Skip placeholder/default values — they inflate false positives on sensitive keys
    if is_placeholder_value(value) {
        return None;
    }

    // Sensitive key name lowers the threshold
    let effective_threshold = if key.is_some_and(is_sensitive_key) {
        (entropy_threshold - 1.0).max(2.5)
    } else {
        entropy_threshold
    };

    let min_length = if key.is_some_and(is_sensitive_key) {
        8
    } else {
        20
    };

    if value.len() >= min_length && shannon_entropy(value) > effective_threshold {
        let confidence = if key.is_some_and(is_sensitive_key) {
            "high"
        } else {
            "medium"
        };
        return Some((
            "high-entropy".into(),
            "High-entropy string (possible secret)".into(),
            confidence.into(),
        ));
    }

    None
}

fn scan_file(
    path: &Path,
    rules: &[ScanRule],
    entropy_threshold: f64,
) -> Result<Vec<Finding>, S2Error> {
    let raw = std::fs::read(path)?;
    if is_binary(&raw) {
        return Ok(Vec::new());
    }

    let content = String::from_utf8_lossy(&raw);
    let mut findings = Vec::new();
    let display_path = path.display().to_string();

    // Try to parse as KEY=value format first
    if let Ok(entries) = parser::parse_file(path, &content) {
        for (i, entry) in entries.iter().enumerate() {
            let value = entry.value.expose_secret();
            if value.is_empty() {
                continue;
            }
            if let Some((rule_id, description, confidence)) =
                test_value(value, Some(&entry.key), rules, entropy_threshold)
            {
                findings.push(Finding {
                    file: display_path.clone(),
                    line: find_key_line(&content, &entry.key, i),
                    key: Some(entry.key.clone()),
                    rule: rule_id,
                    description,
                    hash: compute_finding_hash(Some(&entry.key), value),
                    matched: redact_match(value),
                    confidence,
                    allowed: false,
                });
            }
        }
        return Ok(findings);
    }

    // Fallback: scan each line with regex (for non-KEY=value files)
    // Only pattern matches — entropy detection without key context is too noisy on prose
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((rule_id, description, confidence)) =
            test_value(line, None, rules, entropy_threshold)
        {
            if rule_id == "high-entropy" {
                continue;
            }
            findings.push(Finding {
                file: display_path.clone(),
                line: line_num + 1,
                key: None,
                rule: rule_id,
                description,
                hash: compute_finding_hash(None, line),
                matched: redact_match(line),
                confidence,
                allowed: false,
            });
        }
    }

    Ok(findings)
}

/// Find the line number for the Nth occurrence of a key in the content.
fn find_key_line(content: &str, key: &str, occurrence: usize) -> usize {
    let prefix = format!("{}=", key);
    let export_prefix = format!("export {}=", key);
    let mut count = 0;
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with(&prefix) || trimmed.starts_with(&export_prefix) {
            if count == occurrence {
                return i + 1;
            }
            count += 1;
        }
    }
    1 // fallback
}

// --- Pattern learning ---

fn find_prefix(value: &str) -> &str {
    let mut last_sep = 0;
    for (i, c) in value.char_indices() {
        if !c.is_ascii_alphanumeric() {
            let rest = &value[i + c.len_utf8()..];
            if !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                last_sep = i + c.len_utf8();
            }
        }
    }
    &value[..last_sep]
}

fn classify_chars(s: &str) -> &'static str {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_dash = s.contains('-');
    let has_underscore = s.contains('_');

    match (has_lower, has_upper, has_digit, has_dash, has_underscore) {
        (true, true, true, true, true) => "[a-zA-Z0-9_-]",
        (true, true, true, false, true) => "[a-zA-Z0-9_]",
        (true, true, true, true, false) => "[a-zA-Z0-9-]",
        (true, true, true, false, false) => "[a-zA-Z0-9]",
        (true, false, true, false, false) => "[a-z0-9]",
        (false, true, true, false, false) => "[A-Z0-9]",
        (true, true, false, false, false) => "[a-zA-Z]",
        (true, false, false, false, false) => "[a-z]",
        (false, true, false, false, false) => "[A-Z]",
        (false, false, true, false, false) => "[0-9]",
        _ => "[a-zA-Z0-9_-]",
    }
}

struct SuggestedRule {
    id: String,
    description: String,
    pattern: String,
}

fn suggest_pattern(value: &str, index: usize) -> SuggestedRule {
    let prefix = find_prefix(value);
    let rest = &value[prefix.len()..];
    let char_class = classify_chars(rest);
    let len = rest.len();

    let escaped_prefix = regex::escape(prefix);
    let pattern = format!("{}{}{{{}}}", escaped_prefix, char_class, len);

    let description = if prefix.is_empty() {
        format!("{} chars {}", len, char_class)
    } else {
        format!("Prefix '{}' + {} chars {}", prefix, len, char_class)
    };

    SuggestedRule {
        id: format!("custom-{}", index + 1),
        description,
        pattern,
    }
}

/// Returns true if a value is clearly not a secret (config, boolean, URL without creds, etc.)
fn is_non_secret_value(value: &str) -> bool {
    let v = value.trim();

    // Empty
    if v.is_empty() {
        return true;
    }

    // Booleans
    if matches!(
        v.to_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "enabled" | "disabled"
    ) {
        return true;
    }

    // Pure numeric (integers, floats)
    if v.parse::<f64>().is_ok() {
        return true;
    }

    // Short low-entropy values (hostnames, regions, env names)
    if v.len() < 8 && shannon_entropy(v) < 3.0 {
        return true;
    }

    // URLs without credentials (no user:pass@ pattern)
    if (v.starts_with("http://") || v.starts_with("https://")) && !v.contains('@') {
        return true;
    }

    // Well-known non-secret values
    if matches!(
        v,
        "localhost" | "development" | "production" | "staging" | "test"
    ) {
        return true;
    }

    false
}

fn run_learn(learn_file: &Path, rules: &[ScanRule], entropy_threshold: f64) -> Result<(), S2Error> {
    let content = std::fs::read_to_string(learn_file)?;

    // Parse each line individually as KEY=value, falling back to raw for unparseable lines
    let all_values: Vec<(String, String)> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            // Try KEY=value parse on this single line
            if let Ok(entries) = parser::parse_file(learn_file, line) {
                entries
                    .into_iter()
                    .next()
                    .map(|e| (e.key, e.value.expose_secret().to_string()))
            } else {
                // Unparseable — treat as raw value
                Some(("(raw)".to_string(), line.to_string()))
            }
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();

    if all_values.is_empty() {
        eprintln!("No entries found in {}", learn_file.display());
        return Ok(());
    }

    let mut covered = Vec::new();
    let mut missed = Vec::new();
    let mut skipped = Vec::new();

    for (i, (key, value)) in all_values.iter().enumerate() {
        if is_non_secret_value(value) {
            skipped.push((i + 1, key.clone(), value.clone()));
            continue;
        }
        if let Some((rule_id, _, _)) = test_value(value, Some(key), rules, entropy_threshold) {
            covered.push((i + 1, key.clone(), redact_match(value), rule_id));
        } else {
            missed.push((i + 1, key.clone(), redact_match(value), value.clone()));
        }
    }

    let secret_count = covered.len() + missed.len();
    eprintln!(
        "Coverage: {}/{} secrets detected ({} non-secret values skipped)\n",
        covered.len(),
        secret_count,
        skipped.len()
    );

    for (num, key, display, rule_id) in &covered {
        eprintln!(
            "  {}: {} = {}  \x1b[32m+\x1b[0m {}",
            num, key, display, rule_id
        );
    }
    for (num, key, display, _) in &missed {
        eprintln!(
            "  {}: {} = {}  \x1b[31m-\x1b[0m not detected",
            num, key, display
        );
    }

    if missed.is_empty() {
        eprintln!("\nAll secrets covered!");
        return Ok(());
    }

    let suggestions: Vec<SuggestedRule> = missed
        .iter()
        .enumerate()
        .map(|(i, (_, _, _, value))| suggest_pattern(value, i))
        .collect();

    eprintln!("\nSuggested rules:\n");
    let mut toml_block = String::new();
    for s in &suggestions {
        let entry = format!(
            "[[scan.rules]]\nid = \"{}\"\ndescription = \"{}\"\npattern = '{}'\n\n",
            s.id, s.description, s.pattern
        );
        eprint!("  {}", entry.replace('\n', "\n  "));
        toml_block.push_str(&entry);
    }

    if atty::is(atty::Stream::Stdin) {
        eprint!("Add to ~/.config/s2/config.toml? [y/n] ");
        io::stderr().flush().ok();
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer).ok();
        if answer.trim().eq_ignore_ascii_case("y") {
            let config_path = config_path();
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&config_path)
                .map_err(|e| S2Error::Config(format!("failed to open config: {}", e)))?;
            file.write_all(b"\n")
                .and_then(|_| file.write_all(toml_block.as_bytes()))
                .map_err(|e| S2Error::Config(format!("failed to write config: {}", e)))?;
            eprintln!(
                "Added {} rule(s) to {}",
                suggestions.len(),
                config_path.display()
            );
        }
    }

    Ok(())
}

fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    base.join("s2").join("config.toml")
}

// --- Entry point ---

fn print_rules_summary(rules: &[ScanRule], config: &Config) -> Result<(), S2Error> {
    let custom_count = config.scan.rules.len();
    let builtin_count = rules.len() - custom_count;

    println!(
        "s2 scan rules ({} built-in, {} custom)\n",
        builtin_count, custom_count
    );
    let header = format!("{:<28} {:<38} {}", "ID", "DESCRIPTION", "GATE");
    println!("{header}");
    println!("{}", "-".repeat(header.len()));

    for rule in rules {
        let gate = match &rule.keyword {
            Some(kw) => format!("keyword: {}", kw),
            None => String::new(),
        };
        println!("{:<28} {:<38} {}", rule.id, rule.description, gate);
    }

    println!("\n+ entropy detection (Shannon threshold, applies to KEY=VALUE patterns)");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    config: &Config,
    paths: Vec<PathBuf>,
    staged: bool,
    no_ignore: bool,
    json: bool,
    entropy_threshold: f64,
    learn: Option<PathBuf>,
    allow: Vec<String>,
    allow_with_context: Vec<String>,
    list_rules: bool,
) -> Result<(), S2Error> {
    let rules = build_rules(config)?;

    if list_rules {
        return print_rules_summary(&rules, config);
    }

    if !allow.is_empty() {
        return add_to_allowlist(&allow);
    }

    if let Some(ref learn_file) = learn {
        return run_learn(learn_file, &rules, entropy_threshold);
    }

    let files = if staged {
        collect_staged_files()?
    } else if paths.is_empty() {
        collect_files(&[PathBuf::from(".")], no_ignore, &config.scan.skip_dirs)
    } else {
        collect_files(&paths, no_ignore, &config.scan.skip_dirs)
    };

    let mut all_findings: Vec<Finding> = Vec::new();

    for file in &files {
        if !file.exists() {
            continue;
        }
        match scan_file(file, &rules, entropy_threshold) {
            Ok(findings) => all_findings.extend(findings),
            Err(_) => continue,
        }
    }

    // Apply allowlist
    let allowlist = load_allowlist();
    let mut allowed_count = 0;
    if !allowlist.is_empty() {
        for finding in &mut all_findings {
            if is_allowed(&finding.hash, &allowlist) {
                finding.allowed = true;
                allowed_count += 1;
            }
        }
    }

    if !allow_with_context.is_empty() {
        all_findings.retain(|f| !f.allowed);
        return add_to_allowlist_with_context(&allow_with_context, &all_findings);
    }

    if json {
        for finding in &all_findings {
            println!("{}", serde_json::to_string(finding).unwrap());
        }
    } else {
        let active: Vec<&Finding> = all_findings.iter().filter(|f| !f.allowed).collect();

        if active.is_empty() {
            if allowed_count > 0 {
                eprintln!(
                    "No secrets found ({} files scanned, {} allowed)",
                    files.len(),
                    allowed_count
                );
            } else {
                eprintln!("No secrets found ({} files scanned)", files.len());
            }
        } else {
            let mut by_file = active;
            by_file.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

            for f in &by_file {
                let confidence = if f.confidence == "high" {
                    ""
                } else {
                    " [medium]"
                };
                let key_display = f
                    .key
                    .as_ref()
                    .map(|k| format!("{}  ", k))
                    .unwrap_or_default();
                eprintln!(
                    "  {}:{}  {}{}  {}  {}{}",
                    f.file, f.line, key_display, f.rule, f.matched, f.hash, confidence
                );
            }

            let file_count = by_file
                .iter()
                .map(|f| &f.file)
                .collect::<HashSet<_>>()
                .len();
            let allowed_msg = if allowed_count > 0 {
                format!(" ({} allowed)", allowed_count)
            } else {
                String::new()
            };
            eprintln!(
                "\n{} secret(s) found in {} file(s){}",
                by_file.len(),
                file_count,
                allowed_msg
            );
        }
    }

    let active_count = all_findings.iter().filter(|f| !f.allowed).count();
    if active_count == 0 {
        Ok(())
    } else {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that change the process-wide current directory
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_detects_aws_key() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value("AKIAIOSFODNN7EXAMPLE", None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "aws-access-key");
    }

    #[test]
    fn test_detects_github_token() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "github-token");
    }

    #[test]
    fn test_detects_private_key() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value("-----BEGIN RSA PRIVATE KEY-----", None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "private-key");
    }

    #[test]
    fn test_detects_stripe_key() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value("sk_live_abcdefghijklmnop", None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "stripe-key");
    }

    #[test]
    fn test_detects_jwt() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "jwt");
    }

    #[test]
    fn test_sensitive_key_lowers_entropy_threshold() {
        let rules = build_rules(&default_config()).unwrap();
        // Value with moderate entropy — triggers with sensitive key (lower threshold) but not generic
        let value = "xK9mL2nP4qR7tY";
        assert!(test_value(value, Some("DB_PASSWORD"), &rules, 4.5).is_some());
        assert!(test_value(value, Some("APP_NAME"), &rules, 4.5).is_none());
    }

    #[test]
    fn test_skips_empty_and_low_entropy() {
        let rules = build_rules(&default_config()).unwrap();
        assert!(test_value("", None, &rules, 4.5).is_none());
        assert!(test_value("hello", None, &rules, 4.5).is_none());
        assert!(test_value("true", Some("IS_PRODUCTION"), &rules, 4.5).is_none());
    }

    #[test]
    fn test_shannon_entropy() {
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("hello world") < 4.0);
        assert!(shannon_entropy("aB3$kL9!mN2@pQ5#xR7^tY0&wZ8*") > 4.0);
    }

    #[test]
    fn test_is_binary() {
        assert!(is_binary(&[0x89, 0x50, 0x4E, 0x47, 0x00]));
        assert!(!is_binary(b"just plain text"));
    }

    #[test]
    fn test_find_prefix() {
        assert_eq!(find_prefix("qbo_xK9mL2nP4qR7"), "qbo_");
        assert_eq!(find_prefix("sk_live_abcdef123"), "sk_live_");
        assert_eq!(find_prefix("AKIAIOSFODNN7EXAMPLE"), "");
        assert_eq!(find_prefix("ghp_ABC123"), "ghp_");
    }

    #[test]
    fn test_classify_chars() {
        assert_eq!(classify_chars("abcDEF123"), "[a-zA-Z0-9]");
        assert_eq!(classify_chars("abc123"), "[a-z0-9]");
        assert_eq!(classify_chars("ABC123"), "[A-Z0-9]");
        assert_eq!(classify_chars("abc-DEF_123"), "[a-zA-Z0-9_-]");
        assert_eq!(classify_chars("12345"), "[0-9]");
    }

    #[test]
    fn test_suggest_pattern() {
        let s = suggest_pattern("qbo_xK9mL2nP4qR7tY0wZ3aB5cD8eF1gH6iX", 0);
        assert_eq!(s.pattern, "qbo_[a-zA-Z0-9]{32}");
        assert!(s.description.contains("qbo_"));

        let s = suggest_pattern("AKIAIOSFODNN7EXAMPLE", 1);
        assert!(s.pattern.contains("[A-Z0-9]{20}"));
    }

    #[test]
    fn test_keyword_filtering() {
        let mut config = Config::default();
        config.scan.rules.push(crate::config::CustomScanRule {
            id: "vercel".to_string(),
            description: "Vercel Token".to_string(),
            pattern: r"[a-zA-Z0-9]{24}".to_string(),
            keyword: Some("vercel".to_string()),
        });

        let rules = build_rules(&config).unwrap();

        // Matches: keyword in key name
        let result = test_value(
            "abcdefghijklmnopqrstuvwx",
            Some("VERCEL_TOKEN"),
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "vercel");

        // No match: keyword absent
        let result = test_value("abcdefghijklmnopqrstuvwx", Some("OTHER_TOKEN"), &rules, 4.5);
        // May still match via entropy, but not via the vercel rule
        if let Some((rule_id, _, _)) = result {
            assert_ne!(rule_id, "vercel");
        }
    }

    #[test]
    fn test_detects_shopify_token() {
        let rules = build_rules(&default_config()).unwrap();
        // Build value dynamically to avoid GitHub Push Protection flagging the source
        let value = format!("{}_{}", "shpat", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
        let result = test_value(&value, None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "shopify-token");
    }

    #[test]
    fn test_detects_shopify_shared_secret() {
        let rules = build_rules(&default_config()).unwrap();
        let value = format!("{}_{}", "shpss", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
        let result = test_value(&value, None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "shopify-shared-secret");
    }

    #[test]
    fn test_detects_gitlab_pat() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value("glpat-a1b2c3d4e5f6a7b8c9d0", None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "gitlab-pat");
    }

    #[test]
    fn test_detects_anthropic_key() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "sk-ant-api03-ZTuILlyrPeiioAqBznqJNysxkb3OCbBYDrRz1rWELo-JeZXsGadlfhlM1sr7FGWRRez24mfeqrEtnzkvRb4SQ-a4QM4gAA",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "anthropic-key");
    }

    #[test]
    fn test_detects_openai_key() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "sk-proj-abc123DEF456ghi789JKL012mno345PQR678stu901VWX234yz",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "openai-key");
    }

    #[test]
    fn test_detects_npm_token() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "npm_MjQ0NjcxOTkzNDEyOmRhNjkwNWZkLWNlZDItNDQ4MA",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "npm-token");
    }

    #[test]
    fn test_detects_pypi_token() {
        let rules = build_rules(&default_config()).unwrap();
        let result = test_value(
            "pypi-AgEIcHlwaS5vcmcCJGY3ZjBlNzQ5LWRkZWYtNGI1YS04MjEzLTQzZGRlNDU5NDYyOA",
            None,
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "pypi-token");
    }

    #[test]
    fn test_detects_supabase_key() {
        let rules = build_rules(&default_config()).unwrap();
        let value = format!("sbp_{}", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0");
        let result = test_value(&value, None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "supabase-key");
    }

    #[test]
    fn test_detects_datadog_key() {
        let rules = build_rules(&default_config()).unwrap();
        // Datadog keys are 32-char hex — requires keyword gate
        let result = test_value(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            Some("DATADOG_API_KEY"),
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "datadog-key");
    }

    #[test]
    fn test_datadog_key_requires_keyword() {
        let rules = build_rules(&default_config()).unwrap();
        // Same hex value without a datadog key name should NOT match the datadog rule
        let result = test_value(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            Some("SOME_HASH"),
            &rules,
            4.5,
        );
        if let Some((id, _, _)) = result {
            assert_ne!(id, "datadog-key");
        }
    }

    #[test]
    fn test_detects_heroku_key() {
        let rules = build_rules(&default_config()).unwrap();
        // Heroku keys are UUIDs — requires keyword gate
        let result = test_value(
            "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            Some("HEROKU_API_KEY"),
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "heroku-key");
    }

    #[test]
    fn test_heroku_key_requires_keyword() {
        let rules = build_rules(&default_config()).unwrap();
        // UUID without heroku key name should NOT match the heroku rule
        let result = test_value(
            "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            Some("REQUEST_ID"),
            &rules,
            4.5,
        );
        if let Some((id, _, _)) = result {
            assert_ne!(id, "heroku-key");
        }
    }

    #[test]
    fn test_detects_azure_key() {
        let rules = build_rules(&default_config()).unwrap();
        // Azure secrets are base64 — requires keyword gate
        let result = test_value(
            "dGhpcyBpcyBhIHRlc3QgYXp1cmUgc2VjcmV0IGtleQ==",
            Some("AZURE_CLIENT_SECRET"),
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "azure-key");
    }

    #[test]
    fn test_azure_key_requires_keyword() {
        let rules = build_rules(&default_config()).unwrap();
        // Base64 without azure key name should NOT match the azure rule
        let result = test_value(
            "dGhpcyBpcyBhIHRlc3QgYXp1cmUgc2VjcmV0IGtleQ==",
            Some("ENCODED_DATA"),
            &rules,
            4.5,
        );
        if let Some((id, _, _)) = result {
            assert_ne!(id, "azure-key");
        }
    }

    #[test]
    fn test_placeholder_values_not_flagged() {
        let rules = build_rules(&default_config()).unwrap();
        // These should NOT be detected despite sensitive key names
        assert!(test_value("changeme12345", Some("TEST_PASSWORD"), &rules, 4.5).is_none());
        assert!(test_value(
            "REPLACE_ME_WITH_REAL_TOKEN",
            Some("SAMPLE_TOKEN"),
            &rules,
            4.5,
        )
        .is_none());
        assert!(test_value("your-api-key-here", Some("EXAMPLE_KEY"), &rules, 4.5).is_none());
        assert!(test_value("insert_your_token_here", Some("AUTH_TOKEN"), &rules, 4.5,).is_none());
        assert!(test_value("placeholder_value", Some("SECRET_KEY"), &rules, 4.5).is_none());
    }

    #[test]
    fn test_placeholder_filter_does_not_block_pattern_matches() {
        let rules = build_rules(&default_config()).unwrap();
        // A value that contains "changeme" but also matches a pattern should still be caught
        // (placeholder filter is only in the entropy branch)
        let result = test_value(
            "-----BEGIN RSA PRIVATE KEY-----",
            Some("CHANGEME_KEY"),
            &rules,
            4.5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "private-key");
    }

    #[test]
    fn test_custom_rules_from_config() {
        let mut config = Config::default();
        config.scan.rules.push(crate::config::CustomScanRule {
            id: "test-rule".to_string(),
            description: "Test Rule".to_string(),
            pattern: r"test_[a-z]{10}".to_string(),
            keyword: None,
        });

        let rules = build_rules(&config).unwrap();
        let result = test_value("test_abcdefghij", None, &rules, 4.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "test-rule");
    }

    #[test]
    fn test_compute_finding_hash_deterministic() {
        let h1 = compute_finding_hash(Some("DB_PASSWORD"), "s3cr3t_v4lue!");
        let h2 = compute_finding_hash(Some("DB_PASSWORD"), "s3cr3t_v4lue!");
        assert_eq!(h1.len(), 16);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_finding_hash_differs_by_key() {
        let h1 = compute_finding_hash(Some("DB_PASSWORD"), "s3cr3t_v4lue!");
        let h2 = compute_finding_hash(Some("OTHER_KEY"), "s3cr3t_v4lue!");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_finding_hash_none_vs_empty_key() {
        let h1 = compute_finding_hash(None, "some value");
        let h2 = compute_finding_hash(Some(""), "some value");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_is_allowed_exact_match() {
        let mut allowlist = HashSet::new();
        allowlist.insert("a1b2c3d4e5f6a7b8".to_string());
        assert!(is_allowed("a1b2c3d4e5f6a7b8", &allowlist));
        assert!(!is_allowed("ffffffffffffffff", &allowlist));
    }

    #[test]
    fn test_is_allowed_prefix_match() {
        let mut allowlist = HashSet::new();
        allowlist.insert("a1b2c3d4e5f6a7b8".to_string());
        // Short hash matches full entry via prefix
        assert!(is_allowed("a1b2c3d4e5f6a7b8", &allowlist));
        // Finding hash is longer, entry is prefix
        let mut short_allowlist = HashSet::new();
        short_allowlist.insert("a1b2c3d4".to_string());
        assert!(is_allowed("a1b2c3d4e5f6a7b8", &short_allowlist));
        assert!(!is_allowed("ffffffffffffffff", &short_allowlist));
    }

    #[test]
    fn test_collect_files_no_ignore_includes_hidden_dotfiles() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "SECRET=value\n").unwrap();
        std::fs::write(dir.path().join("plain.txt"), "hello\n").unwrap();

        let paths = vec![dir.path().to_path_buf()];

        let without = collect_files(&paths, false, &[]);
        assert!(
            without.iter().all(|p| p.file_name().unwrap() != ".env"),
            "default scan must skip hidden dotfiles, got: {:?}",
            without
        );

        let with = collect_files(&paths, true, &[]);
        assert!(
            with.iter().any(|p| p.file_name().unwrap() == ".env"),
            "--no-ignore must include hidden dotfiles, got: {:?}",
            with
        );
    }

    #[test]
    fn test_collect_files_explicit_file_path_always_included() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "SECRET=value\n").unwrap();

        let files = collect_files(&[env_path.clone()], false, &[]);
        assert_eq!(files, vec![env_path]);
    }

    #[test]
    fn test_allow_with_context_writes_comment_and_hash() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        let _guard = SetCwd::new(dir.path());

        let findings = vec![Finding {
            file: "src/config.rs".to_string(),
            line: 42,
            key: Some("DB_PASSWORD".to_string()),
            rule: "high-entropy".to_string(),
            description: "High-entropy string".to_string(),
            matched: "xK9m████████".to_string(),
            confidence: "high".to_string(),
            hash: "a1b2c3d4e5f6a7b8".to_string(),
            allowed: false,
        }];

        add_to_allowlist_with_context(&["a1b2c3d4e5f6a7b8".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "# src/config.rs:42 — DB_PASSWORD — high-entropy (High-entropy string)"
        );
        assert_eq!(lines[1], "a1b2c3d4e5f6a7b8");
    }

    #[test]
    fn test_allow_with_context_no_key_omits_key_from_comment() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        let _guard = SetCwd::new(dir.path());

        let findings = vec![Finding {
            file: "deploy.sh".to_string(),
            line: 7,
            key: None,
            rule: "aws-access-key".to_string(),
            description: "AWS Access Key".to_string(),
            matched: "AKIA████████".to_string(),
            confidence: "high".to_string(),
            hash: "b2c3d4e5f6a7b8c9".to_string(),
            allowed: false,
        }];

        add_to_allowlist_with_context(&["b2c3d4e5f6a7b8c9".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "# deploy.sh:7 — aws-access-key (AWS Access Key)");
        assert_eq!(lines[1], "b2c3d4e5f6a7b8c9");
    }

    #[test]
    fn test_allow_with_context_no_matching_finding_writes_bare_hash() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        let _guard = SetCwd::new(dir.path());

        let findings: Vec<Finding> = vec![];

        add_to_allowlist_with_context(&["c3d4e5f6a7b8c9d0".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "c3d4e5f6a7b8c9d0");
    }

    #[test]
    fn test_allow_with_context_skips_duplicates() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        std::fs::write(&allowlist_path, "d4e5f6a7b8c9d0e1\n").unwrap();
        let _guard = SetCwd::new(dir.path());

        let findings = vec![Finding {
            file: "test.rs".to_string(),
            line: 1,
            key: None,
            rule: "test".to_string(),
            description: "Test".to_string(),
            matched: "test".to_string(),
            confidence: "high".to_string(),
            hash: "d4e5f6a7b8c9d0e1".to_string(),
            allowed: false,
        }];

        add_to_allowlist_with_context(&["d4e5f6a7b8c9d0e1".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        // Should still be just the original line — no duplicate added
        assert_eq!(content, "d4e5f6a7b8c9d0e1\n");
    }

    #[test]
    fn test_allow_with_context_normalizes_uppercase_hash() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        let _guard = SetCwd::new(dir.path());

        let findings = vec![Finding {
            file: "app.rs".to_string(),
            line: 10,
            key: None,
            rule: "test-rule".to_string(),
            description: "Test".to_string(),
            matched: "test".to_string(),
            confidence: "high".to_string(),
            hash: "aabb1122ccdd3344".to_string(),
            allowed: false,
        }];

        // Pass uppercase — should normalize and still match finding
        add_to_allowlist_with_context(&["AABB1122CCDD3344".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("# app.rs:10"));
        assert_eq!(lines[1], "aabb1122ccdd3344");
    }

    #[test]
    fn test_allow_with_context_handles_missing_trailing_newline() {
        let _lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let allowlist_path = dir.path().join(".s2allowlist");
        // Write without trailing newline
        std::fs::write(&allowlist_path, "aaaa1111bbbb2222").unwrap();
        let _guard = SetCwd::new(dir.path());

        let findings: Vec<Finding> = vec![];

        add_to_allowlist_with_context(&["cccc3333dddd4444".to_string()], &findings).unwrap();

        let content = std::fs::read_to_string(&allowlist_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "aaaa1111bbbb2222");
        assert_eq!(lines[1], "cccc3333dddd4444");
    }

    /// RAII guard to change cwd for a test and restore it after
    struct SetCwd {
        prev: PathBuf,
    }

    impl SetCwd {
        fn new(dir: &Path) -> Self {
            let prev = std::env::current_dir().unwrap();
            std::env::set_current_dir(dir).unwrap();
            SetCwd { prev }
        }
    }

    impl Drop for SetCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }
}
