// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// bippy CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn no_args_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("bippy"));

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Missing required argument"));
}

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("bippy"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE number"));
}

#[test]
fn missing_sha_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("bippy"));

    cmd.arg("--cve")
        .arg("CVE-2024-12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Missing required argument"));
}

#[test]
fn invalid_sha_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("bippy"));

    cmd.args(["--cve", "CVE-2024-12345", "--sha", "invalidsha",
              "--json", "/tmp/bippy_test_out.json",
              "--user", "test@test.com", "--name", "Test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("SHAs could be resolved"));
}

#[test]
fn missing_output_format_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("bippy"));

    cmd.args(["--cve", "CVE-2024-12345", "--sha", "abc123"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("one of json or mbox must be specified"));
}
