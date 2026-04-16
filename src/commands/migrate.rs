use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::PathBuf;

use secrecy::ExposeSecret;

use crate::config::{self, Config};
use crate::crypto;
use crate::error::S2Error;
use crate::keychain;
use crate::mask;
use crate::parser::{self, ParsedEntry};
use crate::permissions;

/// Tracks what happened to a single source entry, for the summary output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Added,
    Updated,
}

impl Action {
    fn glyph(self) -> &'static str {
        match self {
            Action::Added => "+",
            Action::Updated => "~",
        }
    }
}

struct MigratedKey {
    action: Action,
    key: String,
    masked_value: String,
    value_len: usize,
}

/// Collapse duplicate keys to a single entry using last-wins semantics
/// (the conventional `.env` rule: later assignments override earlier ones).
/// Preserves the position of the *first* occurrence so file ordering is stable.
fn dedupe_last_wins(entries: Vec<ParsedEntry>) -> Vec<ParsedEntry> {
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut result: Vec<ParsedEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(&idx) = index.get(&entry.key) {
            result[idx].value = entry.value;
            result[idx].source_uri = entry.source_uri;
        } else {
            index.insert(entry.key.clone(), result.len());
            result.push(entry);
        }
    }
    result
}

/// Bulk-import KEY=value entries from a plaintext `.env`-style file into a secret file.
/// Upserts existing keys, appends new ones, skips empty values and `*` glob keys, and
/// collapses duplicate keys last-wins in both source and target.
///
/// Encryption policy:
/// - **New target** → encrypted by default (matches `s2 init`). A fresh passphrase
///   is generated and stored in the keychain so the resulting file is immediately
///   usable via `s2 exec`/`s2 list`.
/// - **Existing encrypted target** → re-encrypted with the same passphrase.
/// - **Existing plaintext target** → written plaintext, but a stderr warning is
///   emitted because storing imported secrets in cleartext is almost never the
///   intent (and silently flipping to encrypted would surprise the other way).
pub fn run(config: &Config, source: PathBuf, file: Option<PathBuf>) -> Result<(), S2Error> {
    let target = config::resolve_single_file(config, &file)?;

    if !source.exists() {
        return Err(S2Error::FileNotFound(source));
    }

    // Read source as plaintext .env. We intentionally do NOT check 0600 on the
    // source — migrate is for importing external files (e.g. downloaded, copied).
    let source_raw = std::fs::read_to_string(&source)?;
    let source_entries = parser::parse_file(&source, &source_raw)?;

    if source_entries.is_empty() {
        eprintln!("No entries found in {}", source.display());
        return Ok(());
    }

    // Collapse dup keys in the source (conventional last-wins). Track how many
    // source lines were redundant so we can surface that in the summary.
    let source_raw_count = source_entries.len();
    let source_entries = dedupe_last_wins(source_entries);
    let dedup_source = source_raw_count - source_entries.len();

    // Load target (or start empty). For a new target we default-encrypt; the
    // passphrase is generated at write time because keychain::file_key relies on
    // canonicalize() which requires the file to exist on disk.
    let target_existed = target.exists();
    let (target_raw_entries, was_encrypted) = if target_existed {
        permissions::check_permissions(&target)?;
        let raw = std::fs::read(&target)?;
        if crypto::is_age_encrypted(&raw) {
            let plaintext = crypto::decrypt_file_content(&target, &raw, config.biometric)?;
            (parser::parse_file(&target, &plaintext)?, true)
        } else {
            let content = String::from_utf8(raw).map_err(|e| S2Error::ParseError {
                path: target.clone(),
                line: 0,
                message: format!("invalid UTF-8: {}", e),
            })?;
            (parser::parse_file(&target, &content)?, false)
        }
    } else {
        (Vec::new(), true)
    };
    let was_existing_plaintext = target_existed && !was_encrypted;

    // Normalize pre-existing dup keys in the target too — otherwise an upsert on
    // the first match would silently leave shadow copies behind.
    let target_raw_count = target_raw_entries.len();
    let mut target_entries = dedupe_last_wins(target_raw_entries);
    let dedup_target = target_raw_count - target_entries.len();

    // Build an O(1) index so upsert is O(n) total, not O(n*m).
    let mut target_index: HashMap<String, usize> = target_entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.key.clone(), i))
        .collect();

    let mut migrated: Vec<MigratedKey> = Vec::new();
    let mut skipped_glob = 0usize;
    let mut skipped_empty: Vec<String> = Vec::new();

    for src in source_entries {
        // `*` is s2's prefix-import sentinel and isn't a real secret — skip it.
        if src.key == "*" {
            skipped_glob += 1;
            continue;
        }

        let (value_len, masked_value) = {
            let raw = src.value.expose_secret();
            if raw.is_empty() {
                // Parallel to `s2 set` which rejects empty stdin — an empty secret is
                // meaningless. Skip but keep going so one junk line doesn't abort a
                // 50-key import.
                skipped_empty.push(src.key);
                continue;
            }
            (raw.chars().count(), mask::redact_match(raw))
        };
        let new_value = src.value;

        let action = if let Some(&idx) = target_index.get(&src.key) {
            target_entries[idx].value = new_value;
            Action::Updated
        } else {
            target_index.insert(src.key.clone(), target_entries.len());
            target_entries.push(ParsedEntry {
                key: src.key.clone(),
                value: new_value,
                source_uri: None,
            });
            Action::Added
        };

        migrated.push(MigratedKey {
            action,
            key: src.key,
            masked_value,
            value_len,
        });
    }

    let content = parser::serialize_entries(&target_entries);
    if was_encrypted {
        // New targets need a fresh passphrase; existing encrypted targets reuse
        // the one already in the keychain. Store-after-write for the new case
        // mirrors `s2 init` so canonicalize() inside file_key sees a real path.
        let passphrase = if target_existed {
            let file_key = keychain::file_key(&target);
            keychain::get_passphrase(&file_key, config.biometric)?
        } else {
            crypto::generate_passphrase()
        };
        let encrypted = crypto::encrypt_with_passphrase(content.as_bytes(), &passphrase)?;
        std::fs::write(&target, &encrypted)?;
        if !target_existed {
            let file_key = keychain::file_key(&target);
            keychain::store_passphrase(&file_key, &passphrase, config.biometric)?;
        }
    } else {
        std::fs::write(&target, content)?;
    }
    permissions::set_secure_permissions(&target)?;

    print_summary(
        &source,
        &target,
        &migrated,
        skipped_glob,
        &skipped_empty,
        dedup_source,
        dedup_target,
    );

    if !target_existed {
        eprintln!(
            "encrypted {} (passphrase stored in credential store)",
            target.display()
        );
    } else if was_existing_plaintext && !migrated.is_empty() {
        eprintln!();
        eprintln!(
            "warning: {} is plaintext; {} secret(s) stored in cleartext.",
            target.display(),
            migrated.len()
        );
        eprintln!(
            "         run `s2 encrypt {}` to encrypt in place.",
            target.display()
        );
    }

    Ok(())
}

fn print_summary(
    source: &std::path::Path,
    target: &std::path::Path,
    migrated: &[MigratedKey],
    skipped_glob: usize,
    skipped_empty: &[String],
    dedup_source: usize,
    dedup_target: usize,
) {
    let added = migrated
        .iter()
        .filter(|m| m.action == Action::Added)
        .count();
    let updated = migrated
        .iter()
        .filter(|m| m.action == Action::Updated)
        .count();
    let skipped = skipped_glob + skipped_empty.len();

    // When stderr isn't a TTY (piped, redirected, CI), fall back to a single-line
    // terse summary that matches the existing `set`/`unset` output style — no block
    // chars, no alignment, grep-friendly.
    if !std::io::stderr().is_terminal() {
        let mut parts = vec![format!("{} added", added), format!("{} updated", updated)];
        if skipped > 0 {
            parts.push(format!("{} skipped", skipped));
        }
        if dedup_source + dedup_target > 0 {
            parts.push(format!("{} collapsed", dedup_source + dedup_target));
        }
        eprintln!(
            "Migrated {} -> {}: {}",
            source.display(),
            target.display(),
            parts.join(", ")
        );
        return;
    }

    eprintln!("Migrated {} → {}", source.display(), target.display());

    // Metrics block — only non-zero rows so the summary stays dense.
    eprintln!();
    eprintln!("  added      {}", added);
    eprintln!("  updated    {}", updated);
    if skipped > 0 {
        let mut reasons: Vec<String> = Vec::new();
        if !skipped_empty.is_empty() {
            reasons.push(format!("{} empty", skipped_empty.len()));
        }
        if skipped_glob > 0 {
            reasons.push(format!("{} glob `*`", skipped_glob));
        }
        eprintln!("  skipped    {}  ({})", skipped, reasons.join(", "));
    }
    if dedup_source > 0 || dedup_target > 0 {
        let mut parts: Vec<String> = Vec::new();
        if dedup_source > 0 {
            parts.push(format!("{} source", dedup_source));
        }
        if dedup_target > 0 {
            parts.push(format!("{} target", dedup_target));
        }
        eprintln!(
            "  collapsed  {}  ({})",
            dedup_source + dedup_target,
            parts.join(", ")
        );
    }

    if !migrated.is_empty() {
        let key_width = migrated.iter().map(|m| m.key.len()).max().unwrap_or(0);
        let mask_width = migrated
            .iter()
            .map(|m| m.masked_value.chars().count())
            .max()
            .unwrap_or(0);
        eprintln!();
        eprintln!("Keys:");
        for m in migrated {
            eprintln!(
                "  {} {:<key_w$}  {:<mask_w$}  ({} ch)",
                m.action.glyph(),
                m.key,
                m.masked_value,
                m.value_len,
                key_w = key_width,
                mask_w = mask_width,
            );
        }
    }

    if !skipped_empty.is_empty() {
        eprintln!();
        eprintln!("Skipped (empty value):");
        for key in skipped_empty {
            eprintln!("  - {}", key);
        }
    }
}
