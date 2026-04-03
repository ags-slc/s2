use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use crate::error::S2Error;

struct ScanRule {
    id: &'static str,
    description: &'static str,
    regex: Regex,
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

fn build_rules() -> Vec<ScanRule> {
    let patterns: Vec<(&str, &str, &str)> = vec![
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

    patterns
        .into_iter()
        .map(|(id, desc, pat)| ScanRule {
            id,
            description: desc,
            regex: Regex::new(pat).unwrap(),
        })
        .collect()
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

    // Regex to extract quoted strings for entropy analysis
    let quoted_re = Regex::new(r#"['"]([A-Za-z0-9+/=\-_.]{20,})['"]"#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;

        // Layer 1: pattern matching
        let mut matched_by_rule = false;
        for rule in rules {
            if let Some(m) = rule.regex.find(line) {
                matched_by_rule = true;
                findings.push(Finding {
                    file: display_path.clone(),
                    line: line_num,
                    rule: rule.id.to_string(),
                    description: rule.description.to_string(),
                    matched: redact_match(m.as_str()),
                    confidence: "high".to_string(),
                });
            }
        }

        // Layer 2: entropy analysis (only if no rule matched)
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

pub fn run(
    paths: Vec<PathBuf>,
    staged: bool,
    json: bool,
    entropy_threshold: f64,
) -> Result<(), S2Error> {
    let rules = build_rules();

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
            Err(_) => continue, // skip unreadable files
        }
    }

    if json {
        for finding in &all_findings {
            println!("{}", serde_json::to_string(finding).unwrap());
        }
    } else if all_findings.is_empty() {
        eprintln!("No secrets found ({} files scanned)", files.len());
    } else {
        // Group by file for display
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

    #[test]
    fn test_detects_aws_key() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "aws-access-key").unwrap();
        assert!(finding.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!finding.regex.is_match("not a key"));
    }

    #[test]
    fn test_detects_github_token() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "github-token").unwrap();
        assert!(finding
            .regex
            .is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(!finding.regex.is_match("ghp_short"));
    }

    #[test]
    fn test_detects_private_key() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "private-key").unwrap();
        assert!(finding.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(finding.regex.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(!finding.regex.is_match("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_detects_stripe_key() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "stripe-key").unwrap();
        assert!(finding.regex.is_match("sk_live_abcdefghijklmnop"));
        assert!(finding.regex.is_match("rk_test_1234567890abcdef"));
        assert!(!finding.regex.is_match("pk_live_public"));
    }

    #[test]
    fn test_detects_jwt() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "jwt").unwrap();
        assert!(finding
            .regex
            .is_match("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
        assert!(!finding.regex.is_match("not.a.jwt"));
    }

    #[test]
    fn test_detects_generic_secret() {
        let rules = build_rules();
        let finding = rules.iter().find(|r| r.id == "generic-secret").unwrap();
        assert!(finding.regex.is_match(r#"password = "supersecret123""#));
        assert!(finding.regex.is_match(r#"API_KEY: 'abcdefghijklmnop'"#));
        assert!(!finding.regex.is_match(r#"password = "short""#));
    }

    #[test]
    fn test_shannon_entropy() {
        // Low entropy (repeated chars)
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        // Medium entropy (English-like)
        assert!(shannon_entropy("hello world") < 4.0);
        // High entropy (random-looking)
        assert!(shannon_entropy("aB3$kL9!mN2@pQ5#xR7^tY0&wZ8*") > 4.0);
    }

    #[test]
    fn test_is_binary() {
        assert!(is_binary(&[0x89, 0x50, 0x4E, 0x47, 0x00])); // PNG with null
        assert!(!is_binary(b"just plain text"));
    }

    #[test]
    fn test_redact_match() {
        assert_eq!(redact_match("AKIAIOSFODNN7EXAMPLE"), "AKIA\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}");
        assert_eq!(redact_match("short"), "short"); // too short to redact
    }
}
