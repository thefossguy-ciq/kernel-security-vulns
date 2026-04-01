// SPDX-License-Identifier: GPL-2.0-only
//
// Vector string parsing and formatting tests.
// Tests the cvss binary via CLI for vector parsing behavior.

use assert_cmd::Command;
use predicates::prelude::*;

fn cvss_cmd() -> Command {
    Command::cargo_bin("cvss").unwrap()
}

// Valid vectors that should all parse and produce scores
const VALID_VECTORS: &[(&str, f64)] = &[
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.6),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
];

#[test]
fn all_valid_vectors_produce_correct_scores() {
    for (vector, expected_score) in VALID_VECTORS {
        let output = cvss_cmd()
            .args(["--vector-only", vector])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "failed for {vector}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        let score_str = format!("{:.1}", expected_score);
        assert!(
            stdout.contains(&score_str),
            "expected score {score_str} in output for {vector}, got: {stdout}"
        );
    }
}

// Invalid vectors
const INVALID_VECTORS: &[&str] = &[
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // wrong version
    "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // wrong version
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV
    "CVSS:3.1/AV:N/AC:L",                              // too few metrics
    "not a vector",                                     // garbage
    "",                                                 // empty
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/X:Y", // extra metric
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",       // 7 metrics
    "CVSS:3.1/AV:N/AV:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   // duplicate
];

#[test]
fn invalid_vectors_fail() {
    for vector in INVALID_VECTORS {
        let result = cvss_cmd()
            .args(["--vector-only", vector])
            .assert()
            .failure();

        // Should produce error output
        result.stderr(predicate::str::is_empty().not());
    }
}

#[test]
fn vector_roundtrip_in_output() {
    // The output should contain the canonical vector string
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ));
}
