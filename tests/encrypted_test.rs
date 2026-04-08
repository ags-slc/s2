use assert_cmd::Command;
use predicates::prelude::*;

fn s2() -> Command {
    Command::cargo_bin("s2").unwrap()
}

// --- Encrypted init roundtrip ---

#[test]
fn test_init_encrypted_then_list() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    // File should be age-encrypted
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    // list should work (decrypts in-memory)
    s2().args(["list", "-f", p]).assert().success();
}

#[test]
fn test_init_encrypted_set_then_exec() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    // Set a value (transparent decrypt → modify → re-encrypt)
    s2().args(["set", "DB_PASS", "-f", p])
        .write_stdin("hunter2")
        .assert()
        .success();

    // File should still be encrypted
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!content.contains("hunter2")); // value must not appear in ciphertext

    // exec should inject the secret
    s2().args(["exec", "-f", p, "--", "printenv", "DB_PASS"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2"));
}

#[test]
fn test_init_encrypted_set_then_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    s2().args(["set", "API_KEY", "-f", p])
        .write_stdin("sk-test-123")
        .assert()
        .success();

    // check should find the key
    s2().args(["check", "API_KEY", "-f", p])
        .assert()
        .success();

    // check should fail for missing key
    s2().args(["check", "MISSING_KEY", "-f", p])
        .assert()
        .failure();
}

#[test]
fn test_init_encrypted_set_then_unset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    s2().args(["set", "TEMP_KEY", "-f", p])
        .write_stdin("temp-value")
        .assert()
        .success();

    s2().args(["check", "TEMP_KEY", "-f", p])
        .assert()
        .success();

    s2().args(["unset", "TEMP_KEY", "-f", p])
        .assert()
        .success();

    s2().args(["check", "TEMP_KEY", "-f", p])
        .assert()
        .failure();
}

// --- Encrypt / Decrypt commands ---

#[test]
fn test_encrypt_then_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.env");
    let p = path.to_str().unwrap();

    // Create a plaintext file
    s2().args(["init", "--no-encrypt", p]).assert().success();
    s2().args(["set", "SECRET", "-f", p])
        .write_stdin("plaintext-value")
        .assert()
        .success();

    // Verify it's plaintext
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("SECRET=plaintext-value"));

    // Encrypt it
    s2().args(["encrypt", p])
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    // File should now be ciphertext
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(!content.contains("plaintext-value"));

    // exec should still work (decrypts transparently)
    s2().args(["exec", "-f", p, "--", "printenv", "SECRET"])
        .assert()
        .success()
        .stdout(predicate::str::contains("plaintext-value"));

    // Decrypt it back
    s2().args(["decrypt", p])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));

    // File should be plaintext again
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("SECRET=plaintext-value"));
}

// --- Redact with encrypted files ---

#[test]
fn test_redact_with_encrypted_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    s2().args(["set", "TOKEN", "-f", p])
        .write_stdin("super-secret-token")
        .assert()
        .success();

    // Redact should replace the value
    s2().args(["redact", "-f", p])
        .write_stdin("The token is super-secret-token in the logs")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED]"))
        .stdout(predicate::str::contains("super-secret-token").not());
}

// --- Multiple values in encrypted file ---

#[test]
fn test_encrypted_multiple_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    s2().args(["set", "KEY_A", "-f", p])
        .write_stdin("value-a")
        .assert()
        .success();

    s2().args(["set", "KEY_B", "-f", p])
        .write_stdin("value-b")
        .assert()
        .success();

    s2().args(["set", "KEY_C", "-f", p])
        .write_stdin("value-c")
        .assert()
        .success();

    // All three keys should be present
    s2().args(["exec", "-f", p, "--", "printenv", "KEY_A"])
        .assert()
        .success()
        .stdout(predicate::str::contains("value-a"));

    s2().args(["exec", "-f", p, "--", "printenv", "KEY_C"])
        .assert()
        .success()
        .stdout(predicate::str::contains("value-c"));

    // List should show all three
    s2().args(["list", "-f", p])
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY_A"))
        .stdout(predicate::str::contains("KEY_B"))
        .stdout(predicate::str::contains("KEY_C"));
}

// --- Update value in encrypted file ---

#[test]
fn test_encrypted_update_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();

    s2().args(["set", "MY_KEY", "-f", p])
        .write_stdin("original")
        .assert()
        .success();

    s2().args(["set", "MY_KEY", "-f", p])
        .write_stdin("updated")
        .assert()
        .success()
        .stderr(predicate::str::contains("Updated"));

    s2().args(["exec", "-f", p, "--", "printenv", "MY_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("updated"));
}
