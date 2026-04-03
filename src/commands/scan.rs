use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use crate::config::Config;
use crate::error::S2Error;

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
    rule: String,
    description: String,
    #[serde(rename = "match")]
    matched: String,
    confidence: String,
}

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
        (
            "generic-secret",
            "Generic Secret Assignment",
            r#"(?i)(secret|password|token|api_key|apikey|secret_key)\s*[=:]\s*['"][A-Za-z0-9+/=\-_.]{8,}['"]"#,
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

    // Append custom rules from config
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

    let quoted_re = Regex::new(r#"['"]([A-Za-z0-9+/=\-_.]{20,})['"]"#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;

        let mut matched_by_rule = false;
        let line_lower = line.to_lowercase();

        for rule in rules {
            // Skip if keyword required but not present on this line
            if let Some(ref kw) = rule.keyword {
                if !line_lower.contains(kw) {
                    continue;
                }
            }

            if let Some(m) = rule.regex.find(line) {
                matched_by_rule = true;
                findings.push(Finding {
                    file: display_path.clone(),
                    line: line_num,
                    rule: rule.id.clone(),
                    description: rule.description.clone(),
                    matched: redact_match(m.as_str()),
                    confidence: "high".to_string(),
                });
            }
        }

        if !matched_by_rule {
            for cap in quoted_re.captures_iter(line) {
                let value = &cap[1];
                if value.len() >= 20 && shannon_entropy(value) > entropy_threshold {
                    findings.push(Finding {
                        file: display_path.clone(),
                        line: line_num,
                        rule: "high-entropy".to_string(),
                        description: "High-entropy string (possible secret)".to_string(),
                        matched: redact_match(value),
                        confidence: "medium".to_string(),
                    });
                }
            }
        }
    }

    Ok(findings)
}

// --- Pattern learning ---

fn find_prefix(value: &str) -> &str {
    // Find the last non-alphanumeric separator where everything after is alphanumeric-ish
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

fn run_learn(learn_file: &Path, rules: &[ScanRule]) -> Result<(), S2Error> {
    let content = std::fs::read_to_string(learn_file)?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        eprintln!("No secrets found in {}", learn_file.display());
        return Ok(());
    }

    let mut covered = Vec::new();
    let mut missed = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let value = line.trim();
        let mut matched_rule = None;
        for rule in rules {
            if rule.regex.is_match(value) {
                matched_rule = Some(rule.id.as_str());
                break;
            }
        }

        let display = redact_match(value);
        if let Some(rule_id) = matched_rule {
            covered.push((i + 1, display, rule_id.to_string()));
        } else {
            missed.push((i + 1, display, value.to_string()));
        }
    }

    eprintln!(
        "Coverage: {}/{} secrets detected by existing rules\n",
        covered.len(),
        lines.len()
    );

    for (line_num, display, rule_id) in &covered {
        eprintln!(
            "  Line {}: {}  \x1b[32m+\x1b[0m {}",
            line_num, display, rule_id
        );
    }
    for (line_num, display, _) in &missed {
        eprintln!(
            "  Line {}: {}  \x1b[31m-\x1b[0m not detected",
            line_num, display
        );
    }

    if missed.is_empty() {
        eprintln!("\nAll secrets covered!");
        return Ok(());
    }

    // Generate suggested rules
    let suggestions: Vec<SuggestedRule> = missed
        .iter()
        .enumerate()
        .map(|(i, (_, _, value))| suggest_pattern(value, i))
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

    // Interactive append
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

pub fn run(
    config: &Config,
    paths: Vec<PathBuf>,
    staged: bool,
    json: bool,
    entropy_threshold: f64,
    learn: Option<PathBuf>,
) -> Result<(), S2Error> {
    let rules = build_rules(config)?;

    // --learn mode: test coverage and suggest rules
    if let Some(ref learn_file) = learn {
        return run_learn(learn_file, &rules);
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
            eprintln!(
                "  {}:{}  {}  {}{}",
                f.file, f.line, f.rule, f.matched, confidence
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
        let rule = rules.iter().find(|r| r.id == "aws-access-key").unwrap();
        assert!(rule.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rule.regex.is_match("not a key"));
    }

    #[test]
    fn test_detects_github_token() {
        let rules = build_rules(&default_config()).unwrap();
        let rule = rules.iter().find(|r| r.id == "github-token").unwrap();
        assert!(rule
            .regex
            .is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(!rule.regex.is_match("ghp_short"));
    }

    #[test]
    fn test_detects_private_key() {
        let rules = build_rules(&default_config()).unwrap();
        let rule = rules.iter().find(|r| r.id == "private-key").unwrap();
        assert!(rule.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(rule.regex.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(!rule.regex.is_match("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_detects_stripe_key() {
        let rules = build_rules(&default_config()).unwrap();
        let rule = rules.iter().find(|r| r.id == "stripe-key").unwrap();
        assert!(rule.regex.is_match("sk_live_abcdefghijklmnop"));
        assert!(rule.regex.is_match("rk_test_1234567890abcdef"));
        assert!(!rule.regex.is_match("pk_live_public"));
    }

    #[test]
    fn test_detects_jwt() {
        let rules = build_rules(&default_config()).unwrap();
        let rule = rules.iter().find(|r| r.id == "jwt").unwrap();
        assert!(rule
            .regex
            .is_match("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
        assert!(!rule.regex.is_match("not.a.jwt"));
    }

    #[test]
    fn test_detects_generic_secret() {
        let rules = build_rules(&default_config()).unwrap();
        let rule = rules.iter().find(|r| r.id == "generic-secret").unwrap();
        assert!(rule.regex.is_match(r#"password = "supersecret123""#));
        assert!(rule.regex.is_match(r#"API_KEY: 'abcdefghijklmnop'"#));
        assert!(!rule.regex.is_match(r#"password = "short""#));
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
        // No prefix detected, full string is alphanumeric
        assert!(s.pattern.contains("[A-Z0-9]{20}"));
    }

    #[test]
    fn test_keyword_filtering() {
        let rule = ScanRule {
            id: "test".to_string(),
            description: "test".to_string(),
            regex: Regex::new(r"[a-zA-Z0-9]{24}").unwrap(),
            keyword: Some("vercel".to_string()),
        };

        // Should match — keyword present
        assert!(rule.regex.is_match("abcdefghijklmnopqrstuvwx"));
        let line = "VERCEL_TOKEN=abcdefghijklmnopqrstuvwx";
        let line_lower = line.to_lowercase();
        assert!(line_lower.contains(rule.keyword.as_ref().unwrap()));

        // Should not match — keyword absent
        let line2 = "OTHER_TOKEN=abcdefghijklmnopqrstuvwx";
        let line2_lower = line2.to_lowercase();
        assert!(!line2_lower.contains(rule.keyword.as_ref().unwrap()));
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
        let custom = rules.iter().find(|r| r.id == "test-rule").unwrap();
        assert!(custom.regex.is_match("test_abcdefghij"));
        assert!(!custom.regex.is_match("test_short"));
    }
}
