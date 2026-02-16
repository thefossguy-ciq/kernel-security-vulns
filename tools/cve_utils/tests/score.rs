// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// score CLI tests

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn help_flag_shows_usage() {
    let mut cmd = Command::new(cargo::cargo_bin!("score"));

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Score reviewer accuracy"));
}

#[test]
fn nonexistent_review_dir_shows_error() {
    let mut cmd = Command::new(cargo::cargo_bin!("score"));

    cmd.arg("--review-dir")
        .arg("/nonexistent_dir_for_test")
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn default_run_shows_report() {
    let mut cmd = Command::new(cargo::cargo_bin!("score"));

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Reviewer Accuracy Report"));
}
