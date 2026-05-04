use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_scan_dev_stdin() {
    Command::cargo_bin("s2")
        .unwrap()
        .args(["scan", "/dev/stdin"])
        .write_stdin("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("aws-access-key"));
}

#[test]
fn test_scan_shows_hash_in_output() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    std::fs::write(&env_file, "DB_PASSWORD=xK9mL2nP4qR7tY0w\n").unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", env_file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("[0-9a-f]{16}").unwrap());
}

#[test]
fn test_scan_allow_creates_allowlist() {
    let dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", "--allow", "a1b2c3d4e5f6a7b8"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added"));

    let content = std::fs::read_to_string(dir.path().join(".s2allowlist")).unwrap();
    assert!(content.contains("a1b2c3d4e5f6a7b8"));
}

#[test]
fn test_scan_allow_respects_allowlist_flag_path() {
    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("nested").join("my-allow.txt");

    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "scan",
            "--allowlist",
            custom.to_str().unwrap(),
            "--allow",
            "a1b2c3d4e5f6a7b8",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added"));

    let content = std::fs::read_to_string(&custom).unwrap();
    assert!(content.contains("a1b2c3d4e5f6a7b8"));
    assert!(custom.exists());
}

#[test]
fn test_scan_allow_rejects_short_hash() {
    let dir = tempfile::tempdir().unwrap();

    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", "--allow", "abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("too short"));
}

#[test]
fn test_scan_allowed_finding_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join(".env");
    std::fs::write(&env_file, "DB_PASSWORD=xK9mL2nP4qR7tY0w\n").unwrap();

    // First scan to get the hash
    let output = Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", env_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    // Extract the 16-char hex hash from output
    let hash: String = stderr
        .chars()
        .collect::<Vec<_>>()
        .windows(16)
        .find(|w| w.iter().all(|c| c.is_ascii_hexdigit()))
        .unwrap()
        .iter()
        .collect();

    // Allow it
    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", "--allow", &hash])
        .assert()
        .success();

    // Scan again — should exit 0
    Command::cargo_bin("s2")
        .unwrap()
        .current_dir(dir.path())
        .args(["scan", env_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("allowed"));
}
