use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::error::S2Error;
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

// --- Rules ---

fn build_rules(config: &Config) -> Result<Vec<ScanRule>, S2Error> {
    let builtins: Vec<(&str, &str, &str)> = vec![
        (
            "aws-access-key",
            "AWS Access Key",
            r"\b(AKIA|A3T[A-Z0-9]|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
        ),
        (
            "github-token",
            "GitHub Token",
            r"\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b",
        ),
        (
            "github-fine-pat",
            "GitHub Fine-Grained PAT",
            r"github_pat_\w{82}",
        ),
        (
            "stripe-key",
            "Stripe Secret Key",
            r"\b[sr]k_(test|live|prod)_[a-zA-Z0-9]{10,99}\b",
        ),
        (
            "slack-token",
            "Slack Token",
            r"xox[bpears]-[0-9a-zA-Z\-]{10,}",
        ),
        (
            "slack-webhook",
            "Slack Webhook URL",
            r"hooks\.slack\.com/services/[A-Za-z0-9+/]{43,}",
        ),
        (
            "private-key",
            "PEM Private Key",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        ),
        (
            "jwt",
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        ),
        (
            "google-api-key",
            "Google API Key",
            r"AIza[0-9A-Za-z\-_]{35}",
        ),
        ("twilio-key", "Twilio API Key", r"\bSK[0-9a-fA-F]{32}\b"),
        (
            "sendgrid-key",
            "SendGrid API Key",
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        ),
    ];

    let mut rules: Vec<ScanRule> = builtins
        .into_iter()
        .map(|(id, desc, pat)| ScanRule {
            id: id.to_string(),
            description: desc.to_string(),
            regex: Regex::new(pat).unwrap(),
            keyword: None,
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

fn redact_match(s: &str) -> String {
    if s.len() <= 8 {
        return s.to_string();
    }
    let prefix: String = s.chars().take(4).collect();
    let suffix_len = s.len().min(40) - 4;
    format!("{}{}", prefix, "\u{2588}".repeat(suffix_len.min(16)))
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

fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            let walker = ignore::WalkBuilder::new(path).hidden(true).build();
            for entry in walker.flatten() {
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
                    matched: redact_match(value),
                    confidence,
                });
            }
        }
        return Ok(findings);
    }

    // Fallback: scan each line with regex (for non-KEY=value files)
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((rule_id, description, confidence)) =
            test_value(line, None, rules, entropy_threshold)
        {
            findings.push(Finding {
                file: display_path.clone(),
                line: line_num + 1,
                key: None,
                rule: rule_id,
                description,
                matched: redact_match(line),
                confidence,
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

fn run_learn(learn_file: &Path, rules: &[ScanRule], entropy_threshold: f64) -> Result<(), S2Error> {
    let content = std::fs::read_to_string(learn_file)?;

    // Try parsing as KEY=value format
    let values: Vec<(String, String)> =
        if let Ok(entries) = parser::parse_file(learn_file, &content) {
            entries
                .iter()
                .map(|e| (e.key.clone(), e.value.expose_secret().to_string()))
                .filter(|(_, v)| !v.is_empty())
                .collect()
        } else {
            // Fallback: each non-empty, non-comment line is a raw value
            content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| ("(raw)".to_string(), l.to_string()))
                .collect()
        };

    if values.is_empty() {
        eprintln!("No secrets found in {}", learn_file.display());
        return Ok(());
    }

    let mut covered = Vec::new();
    let mut missed = Vec::new();

    for (i, (key, value)) in values.iter().enumerate() {
        if let Some((rule_id, _, _)) = test_value(value, Some(key), rules, entropy_threshold) {
            covered.push((i + 1, key.clone(), redact_match(value), rule_id));
        } else {
            missed.push((i + 1, key.clone(), redact_match(value), value.clone()));
        }
    }

    eprintln!(
        "Coverage: {}/{} secrets detected by existing rules\n",
        covered.len(),
        values.len()
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

pub fn run(
    config: &Config,
    paths: Vec<PathBuf>,
    staged: bool,
    json: bool,
    entropy_threshold: f64,
    learn: Option<PathBuf>,
) -> Result<(), S2Error> {
    let rules = build_rules(config)?;

    if let Some(ref learn_file) = learn {
        return run_learn(learn_file, &rules, entropy_threshold);
    }

    let files = if staged {
        collect_staged_files()?
    } else if paths.is_empty() {
        collect_files(&[PathBuf::from(".")])
    } else {
        collect_files(&paths)
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

    if json {
        for finding in &all_findings {
            println!("{}", serde_json::to_string(finding).unwrap());
        }
    } else if all_findings.is_empty() {
        eprintln!("No secrets found ({} files scanned)", files.len());
    } else {
        let mut by_file: Vec<&Finding> = all_findings.iter().collect();
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
                "  {}:{}  {}{}  {}{}",
                f.file, f.line, key_display, f.rule, f.matched, confidence
            );
        }

        let file_count = by_file
            .iter()
            .map(|f| &f.file)
            .collect::<std::collections::HashSet<_>>()
            .len();
        eprintln!(
            "\n{} secret(s) found in {} file(s)",
            all_findings.len(),
            file_count
        );
    }

    if all_findings.is_empty() {
        Ok(())
    } else {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_redact_match() {
        assert_eq!(
            redact_match("AKIAIOSFODNN7EXAMPLE"),
            "AKIA\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}"
        );
        assert_eq!(redact_match("short"), "short");
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
}
