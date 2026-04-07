use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::error::S2Error;

/// A parsed key-value entry from a secrets file.
pub struct ParsedEntry {
    pub key: String,
    pub value: SecretString,
    /// Set by provider resolution to the original URI string.
    pub source_uri: Option<String>,
}

/// Parse a secrets file supporting both `export KEY=val` and `KEY=val` formats.
/// Auto-detects format per line. Supports double-quoted, single-quoted, and unquoted values.
pub fn parse_file(path: &Path, content: &str) -> Result<Vec<ParsedEntry>, S2Error> {
    let mut entries = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_line(line) {
            Some(entry) => entries.push(entry),
            None => {
                return Err(S2Error::ParseError {
                    path: PathBuf::from(path),
                    line: line_num + 1,
                    message: format!("invalid format: {}", line),
                });
            }
        }
    }

    Ok(entries)
}

fn parse_line(line: &str) -> Option<ParsedEntry> {
    // Strip optional `export ` prefix
    let line = line.strip_prefix("export ").unwrap_or(line);

    // Find the `=` separator
    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim();

    // Validate key: must be non-empty, alphanumeric + underscore, or "*" (prefix import)
    if key.is_empty() || (key != "*" && !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return None;
    }

    let raw_value = &line[eq_pos + 1..];

    let value = parse_value(raw_value)?;

    Some(ParsedEntry {
        key: key.to_string(),
        value: SecretString::from(value),
        source_uri: None,
    })
}

fn parse_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();

    if trimmed.starts_with('"') {
        // Double-quoted: supports escapes
        parse_double_quoted(trimmed)
    } else if trimmed.starts_with('\'') {
        // Single-quoted: literal (no escapes)
        parse_single_quoted(trimmed)
    } else {
        // Unquoted: take everything, strip inline comments
        Some(parse_unquoted(raw))
    }
}

fn parse_double_quoted(s: &str) -> Option<String> {
    let s = &s[1..]; // skip opening quote
    let mut result = String::new();
    let mut chars = s.chars();

    loop {
        match chars.next() {
            None => return None, // unterminated
            Some('"') => break,  // closing quote
            Some('\\') => match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('$') => result.push('$'),
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => return None,
            },
            Some(c) => result.push(c),
        }
    }

    Some(result)
}

fn parse_single_quoted(s: &str) -> Option<String> {
    let s = &s[1..]; // skip opening quote
                     // Find closing single quote — no escape processing
    let end = s.find('\'')?;
    Some(s[..end].to_string())
}

fn parse_unquoted(raw: &str) -> String {
    // Strip inline comments (` #` with preceding space)
    let value = if let Some(pos) = raw.find(" #") {
        &raw[..pos]
    } else {
        raw
    };
    value.trim().to_string()
}

/// Serialize entries back to file format (for set/unset operations).
/// Uses the `KEY=value` format, quoting values that need it.
pub fn serialize_entries(entries: &[ParsedEntry]) -> String {
    use secrecy::ExposeSecret;

    let mut output = String::new();
    for entry in entries {
        let value = entry.value.expose_secret();
        if value.contains(' ')
            || value.contains('"')
            || value.contains('\'')
            || value.contains('#')
            || value.contains('\n')
            || value.contains('\t')
        {
            // Double-quote and escape
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\t', "\\t");
            output.push_str(&format!("{}=\"{}\"\n", entry.key, escaped));
        } else {
            output.push_str(&format!("{}={}\n", entry.key, value));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_simple_key_value() {
        let entries = parse_file(Path::new("test"), "FOO=bar\n").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value.expose_secret(), "bar");
    }

    #[test]
    fn test_export_prefix() {
        let entries = parse_file(Path::new("test"), "export FOO=bar\n").unwrap();
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value.expose_secret(), "bar");
    }

    #[test]
    fn test_double_quoted() {
        let entries = parse_file(Path::new("test"), "FOO=\"hello world\"\n").unwrap();
        assert_eq!(entries[0].value.expose_secret(), "hello world");
    }

    #[test]
    fn test_single_quoted() {
        let entries = parse_file(Path::new("test"), "FOO='literal $value'\n").unwrap();
        assert_eq!(entries[0].value.expose_secret(), "literal $value");
    }

    #[test]
    fn test_escape_sequences() {
        let entries = parse_file(Path::new("test"), "FOO=\"line1\\nline2\"\n").unwrap();
        assert_eq!(entries[0].value.expose_secret(), "line1\nline2");
    }

    #[test]
    fn test_comments_and_blanks() {
        let content = "# comment\n\nFOO=bar\n  # another comment\nBAZ=qux\n";
        let entries = parse_file(Path::new("test"), content).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_inline_comment() {
        let entries = parse_file(Path::new("test"), "FOO=bar # this is a comment\n").unwrap();
        assert_eq!(entries[0].value.expose_secret(), "bar");
    }

    #[test]
    fn test_mixed_formats() {
        let content = "export A=1\nB=2\nexport C=\"three\"\nD='four'\n";
        let entries = parse_file(Path::new("test"), content).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].value.expose_secret(), "1");
        assert_eq!(entries[1].value.expose_secret(), "2");
        assert_eq!(entries[2].value.expose_secret(), "three");
        assert_eq!(entries[3].value.expose_secret(), "four");
    }

    #[test]
    fn test_empty_value() {
        let entries = parse_file(Path::new("test"), "FOO=\n").unwrap();
        assert_eq!(entries[0].value.expose_secret(), "");
    }

    #[test]
    fn test_serialize_roundtrip() {
        let entries = vec![
            ParsedEntry {
                key: "SIMPLE".to_string(),
                value: SecretString::from("value".to_string()),
                source_uri: None,
            },
            ParsedEntry {
                key: "QUOTED".to_string(),
                value: SecretString::from("has spaces".to_string()),
                source_uri: None,
            },
        ];
        let serialized = serialize_entries(&entries);
        let parsed = parse_file(Path::new("test"), &serialized).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].value.expose_secret(), "value");
        assert_eq!(parsed[1].value.expose_secret(), "has spaces");
    }

    #[test]
    fn test_glob_key_for_prefix_import() {
        let entries = parse_file(Path::new("test"), "*=ssm:///prod/app/\n").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "*");
        assert_eq!(entries[0].value.expose_secret(), "ssm:///prod/app/");
    }
}
