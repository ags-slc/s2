use std::os::unix::fs::MetadataExt;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_init_creates_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Created"));

    assert!(path.exists());
    let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn test_init_refuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing.env");
    std::fs::write(&path, "").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_set_and_unset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");

    // Init
    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", path.to_str().unwrap()])
        .assert()
        .success();

    // Set a value via stdin
    Command::cargo_bin("s2")
        .unwrap()
        .args(["set", "MY_KEY", "-f", path.to_str().unwrap()])
        .write_stdin("my-value")
        .assert()
        .success()
        .stderr(predicate::str::contains("Added: MY_KEY"));

    // Verify it's in the file (check command)
    Command::cargo_bin("s2")
        .unwrap()
        .args(["check", "MY_KEY", "-f", path.to_str().unwrap()])
        .assert()
        .success();

    // Verify exec injects it
    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", path.to_str().unwrap(), "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MY_KEY=my-value"));

    // Unset
    Command::cargo_bin("s2")
        .unwrap()
        .args(["unset", "MY_KEY", "-f", path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Removed: MY_KEY"));

    // Verify it's gone
    Command::cargo_bin("s2")
        .unwrap()
        .args(["check", "MY_KEY", "-f", path.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_set_updates_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");

    Command::cargo_bin("s2")
        .unwrap()
        .args(["init", path.to_str().unwrap()])
        .assert()
        .success();

    // Set initial value
    Command::cargo_bin("s2")
        .unwrap()
        .args(["set", "MY_KEY", "-f", path.to_str().unwrap()])
        .write_stdin("first")
        .assert()
        .success();

    // Update value
    Command::cargo_bin("s2")
        .unwrap()
        .args(["set", "MY_KEY", "-f", path.to_str().unwrap()])
        .write_stdin("second")
        .assert()
        .success()
        .stderr(predicate::str::contains("Updated: MY_KEY"));

    // Verify updated value
    Command::cargo_bin("s2")
        .unwrap()
        .args(["exec", "-f", path.to_str().unwrap(), "--", "env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MY_KEY=second"));
}
