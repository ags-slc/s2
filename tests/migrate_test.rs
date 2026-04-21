use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;

// NOTE: assert_cmd pipes stderr, so `s2 migrate` takes the non-TTY "terse" output
// path. These tests assert the one-line summary contract. The TTY pretty-print
// path is verified by `mask::redact_match` unit tests in src/mask.rs and
// manual inspection.

#[test]
fn test_migrate_imports_env_file_into_empty_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(
        &source,
        "# comment line\nFOO=bar\nexport BAZ=\"qux with space\"\n\n# another\nEMPTY=\n",
    )
    .unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"))
        .stderr(predicate::str::contains("0 updated"))
        .stderr(predicate::str::contains("1 skipped"));

    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", target.to_str().unwrap(), "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO=bar"))
        .stdout(predicate::str::contains("BAZ=qux with space"));
}

#[test]
fn test_migrate_updates_existing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "FOO=new_value\nNEW_KEY=brand_new\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["set", "FOO", "-f", target.to_str().unwrap()])
        .write_stdin("old_value")
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("1 updated"));

    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", target.to_str().unwrap(), "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FOO=new_value"))
        .stdout(predicate::str::contains("NEW_KEY=brand_new"));
}

#[test]
fn test_migrate_missing_source_fails() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("secrets.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            dir.path().join("does-not-exist.env").to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("file not found"));
}

#[test]
fn test_migrate_source_dup_keys_last_wins() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "KEY=first\nOTHER=x\nKEY=second\nKEY=third\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"))
        .stderr(predicate::str::contains("0 updated"))
        .stderr(predicate::str::contains("2 collapsed"));

    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", target.to_str().unwrap(), "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY=third"))
        .stdout(predicate::str::contains("OTHER=x"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert_eq!(written.lines().filter(|l| l.starts_with("KEY=")).count(), 1);
}

#[test]
fn test_migrate_normalizes_target_dup_keys() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&target, "DUP=old1\nSAFE=untouched\nDUP=old2\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::write(&source, "DUP=new\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 added"))
        .stderr(predicate::str::contains("1 updated"))
        .stderr(predicate::str::contains("1 collapsed"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert_eq!(written.lines().filter(|l| l.starts_with("DUP=")).count(), 1);
    assert!(written.contains("DUP=new"));
    assert!(written.contains("SAFE=untouched"));
}

#[test]
fn test_migrate_skips_glob_key() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "REAL_KEY=real_value\n*=ssm:///prod/app/\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("1 skipped"));
}

#[test]
fn test_migrate_skips_empty_values() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "OK=value\nEMPTY1=\nEMPTY2=\"\"\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("2 skipped"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(!written.contains("EMPTY1"));
    assert!(!written.contains("EMPTY2"));
    assert!(written.contains("OK="));
}

#[test]
fn test_migrate_encrypts_new_target_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "API_KEY=hunter2\n").unwrap();

    // Note: target does NOT exist — no `s2 init` first. Default policy must
    // encrypt rather than silently writing plaintext to disk.
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("encrypted"))
        .stderr(predicate::str::contains(
            "passphrase stored in credential store",
        ));

    let content = std::fs::read_to_string(&target).unwrap();
    assert!(
        content.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "expected encrypted target, got: {}",
        content
    );
    assert!(!content.contains("hunter2"), "secret leaked in ciphertext");

    // Round-trip via keychain-stored passphrase.
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "exec",
            "-f",
            target.to_str().unwrap(),
            "--",
            "printenv",
            "API_KEY",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2"));
}

#[test]
fn test_migrate_warns_on_existing_plaintext_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "FOO=bar\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning"))
        .stderr(predicate::str::contains("plaintext"))
        .stderr(predicate::str::contains("s2 encrypt"));

    // Format unchanged — we warn but don't silently flip.
    let content = std::fs::read_to_string(&target).unwrap();
    assert!(!content.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(content.contains("FOO=bar"));
}

#[test]
fn test_migrate_multiline_value() {
    // Certificates, PEM-encoded keys, and other multi-line secrets are the
    // canonical reason someone would stash a value in a `.env`. The quoted
    // multi-line form must survive migrate → write → decrypt → exec intact.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n-----END PRIVATE KEY-----";
    let source_content = format!("PRIVATE_KEY=\"{}\"\nOTHER=plain\n", pem);
    std::fs::write(&source, &source_content).unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"));

    // Value survives the round-trip: `exec env` prints it back with the same
    // embedded newlines.
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "exec",
            "-f",
            target.to_str().unwrap(),
            "--",
            "printenv",
            "PRIVATE_KEY",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(pem));
}

#[test]
fn test_migrate_non_tty_output_does_not_leak_values() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("import.env");
    let target = dir.path().join("secrets.env");

    std::fs::write(&source, "API_TOKEN=FAKE_SECRET_VALUE_FOR_TEST_ONLY\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    // Non-TTY summary must never contain the secret value itself.
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("FAKE_SECRET_VALUE_FOR_TEST_ONLY").not());
}

// -------------------- --ssm mode --------------------

#[test]
fn test_migrate_ssm_rewrites_values_as_uris() {
    // Core contract: source values are discarded, each key becomes
    // `ssm:///<prefix>/<KEY>` verbatim. The on-disk file is a reference file.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(
        &source,
        "DATABASE_URL=postgres://u:p@h/db\nAPI_KEY=sk_live_XXXXXX\n",
    )
    .unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/myapp",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 added"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        written.contains("DATABASE_URL=ssm:///prod/myapp/DATABASE_URL"),
        "expected SSM reference for DATABASE_URL, got:\n{}",
        written
    );
    assert!(
        written.contains("API_KEY=ssm:///prod/myapp/API_KEY"),
        "expected SSM reference for API_KEY, got:\n{}",
        written
    );
    // Real values must NOT appear in the target — that's the whole point.
    assert!(
        !written.contains("postgres://u:p@h/db"),
        "source value leaked into target file"
    );
    assert!(
        !written.contains("sk_live_XXXXXX"),
        "source value leaked into target file"
    );
}

#[test]
fn test_migrate_ssm_normalizes_prefix() {
    // Trailing slashes, leading slashes, and whitespace all collapse to a
    // single canonical form so users can't accidentally produce `ssm:////foo`
    // or `ssm://foo//KEY`.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "KEY=whatever\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    // Trailing slash on prefix must not produce a double slash.
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app/",
        ])
        .assert()
        .success();

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        written.contains("KEY=ssm:///prod/app/KEY"),
        "trailing-slash prefix should normalize, got:\n{}",
        written
    );
    assert!(!written.contains("ssm:///prod/app//KEY"));

    // Prefix without a leading slash gets one added.
    let target2 = dir.path().join("refs2.env");
    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target2.to_str().unwrap()])
        .assert()
        .success();
    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target2.to_str().unwrap(),
            "--ssm",
            "prod/app",
        ])
        .assert()
        .success();
    let written2 = std::fs::read_to_string(&target2).unwrap();
    assert!(
        written2.contains("KEY=ssm:///prod/app/KEY"),
        "bare prefix should get leading slash added, got:\n{}",
        written2
    );
}

#[test]
fn test_migrate_ssm_rejects_empty_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "KEY=v\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--ssm prefix"));
}

#[test]
fn test_migrate_ssm_still_skips_glob_and_empty() {
    // --ssm doesn't change the skip rules for `*` (it's still not a real key)
    // or empty values (no input = no rewrite target).
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "REAL=value\n*=ssm:///prod/other/\nEMPTY=\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("2 skipped"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("REAL=ssm:///prod/app/REAL"));
    assert!(!written.contains("*="));
    assert!(!written.contains("EMPTY="));
}

#[test]
fn test_migrate_ssm_no_plaintext_warning() {
    // The cleartext warning is about secrets leaking onto disk. In SSM mode
    // the on-disk values are URIs — no secret is stored — so the warning would
    // be actively misleading and must be suppressed.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "KEY=secret-value\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("plaintext").not())
        .stderr(predicate::str::contains("cleartext").not())
        .stderr(predicate::str::contains("s2 encrypt").not());
}

#[test]
fn test_migrate_ssm_does_not_leak_source_values() {
    // The original plaintext value must never appear in stderr or the target —
    // the whole point of --ssm is to *stop* handling the real values locally.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "TOKEN=FAKE_LEAK_CANARY_ABC123\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("FAKE_LEAK_CANARY_ABC123").not());

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(
        !written.contains("FAKE_LEAK_CANARY_ABC123"),
        "source value leaked into target"
    );
}

#[test]
fn test_migrate_ssm_upserts_existing_keys() {
    // When the target already has a KEY (perhaps with a real value or an old
    // URI), --ssm should overwrite it with the new URI.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "KEY=anything\nNEWKEY=anything\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();
    Command::cargo_bin("s2")
        .unwrap()
        .args(["set", "KEY", "-f", target.to_str().unwrap()])
        .write_stdin("stale-literal-value")
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 added"))
        .stderr(predicate::str::contains("1 updated"));

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("KEY=ssm:///prod/app/KEY"));
    assert!(written.contains("NEWKEY=ssm:///prod/app/NEWKEY"));
    assert!(!written.contains("stale-literal-value"));
}

#[test]
fn test_migrate_ssm_into_new_encrypted_target() {
    // --ssm still honours the "new target is encrypted by default" contract.
    // The resulting file should be an age blob whose decrypted body contains
    // the SSM URIs — consistent with how migrate always initialises new files.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "FOO=v\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/app",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("encrypted"));

    let raw = std::fs::read_to_string(&target).unwrap();
    assert!(raw.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    // Decrypt the file in place, then read it back and verify the URI made it
    // through the encryption round-trip — avoids calling `list`, which would
    // try to resolve the URI against real AWS SSM.
    let decrypt_result = Command::cargo_bin("s2")
        .unwrap()
        .args(["decrypt", target.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(decrypt_result.status.success());
    let plaintext = std::fs::read_to_string(&target).unwrap();
    assert!(
        plaintext.contains("FOO=ssm:///prod/app/FOO"),
        "expected URI after decrypt round-trip, got:\n{}",
        plaintext
    );
}

#[test]
fn test_migrate_ssm_uri_is_parseable_reference() {
    // The URI we emit must match the format the SSM provider already accepts
    // (`ssm:///path` with triple-slash = no authority). Smoke-test by reading
    // the file back and checking the exact shape — regressions in format
    // would silently break every migrated file.
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("legacy.env");
    let target = dir.path().join("refs.env");

    std::fs::write(&source, "DB_PASSWORD=x\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", "--no-encrypt", target.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("s2")
        .unwrap()
        .args([
            "migrate",
            source.to_str().unwrap(),
            "-f",
            target.to_str().unwrap(),
            "--ssm",
            "/prod/apps/myapp/secrets",
        ])
        .assert()
        .success();

    let written = std::fs::read_to_string(&target).unwrap();
    // Exact shape — triple slash (empty authority), prefix, then key appended verbatim.
    assert!(
        written.contains("DB_PASSWORD=ssm:///prod/apps/myapp/secrets/DB_PASSWORD"),
        "URI format drift detected, got:\n{}",
        written
    );
}
