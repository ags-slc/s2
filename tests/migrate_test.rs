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
