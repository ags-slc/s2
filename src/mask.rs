//! Display-safe redaction for secret values.
//!
//! Shared by commands that surface discovered/imported secret values to the
//! terminal (`scan`, `migrate`). Keeping the masking policy in one place
//! prevents drift between callers.

/// Redact a value for terminal display.
///
/// Short values (`len <= 8`) are returned verbatim — callers typically surface
/// these only in contexts where a short match is likely a false positive and
/// the full value aids triage. Longer values show a 4-char prefix followed by
/// block-char fill, capped at 16 blocks so very long secrets don't dominate
/// the column.
pub fn redact_match(s: &str) -> String {
    let char_count = s.chars().count();
    if char_count <= 8 {
        return s.to_string();
    }
    let prefix: String = s.chars().take(4).collect();
    let suffix_len = char_count.min(40) - 4;
    format!("{}{}", prefix, "\u{2588}".repeat(suffix_len.min(16)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_match() {
        assert_eq!(
            redact_match("AKIAIOSFODNN7EXAMPLE"),
            "AKIA\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}"
        );
        assert_eq!(redact_match("short"), "short");
    }
}
