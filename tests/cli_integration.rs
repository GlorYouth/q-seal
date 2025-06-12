use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_help() {
    let mut cmd = Command::cargo_bin("q-seal").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn version_flag() {
    let mut cmd = Command::cargo_bin("q-seal").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn traditional_subcommand_help() {
    let mut cmd = Command::cargo_bin("q-seal").unwrap();
    cmd.args(&["traditional", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt").and(predicate::str::contains("decrypt")));
}

#[test]
fn post_quantum_subcommand_help() {
    let mut cmd = Command::cargo_bin("q-seal").unwrap();
    cmd.args(&["post-quantum", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt").and(predicate::str::contains("decrypt")));
}

#[test]
fn traditional_encrypt_smoke() {
    // Smoke test for encrypt CLI with no-file and no-password
    let mut cmd = Command::cargo_bin("q-seal").unwrap();
    cmd.args(&["traditional", "encrypt", "--text", "hello", "--no-file", "--no-password"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("私钥")
            .and(predicate::str::contains("加密后的数据"))
        );
} 