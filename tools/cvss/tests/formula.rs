// SPDX-License-Identifier: GPL-2.0-only
//
// Integration tests: verify CVSS formula produces correct scores via CLI.

use assert_cmd::Command;

fn cvss_cmd() -> Command {
    Command::cargo_bin("cvss").unwrap()
}

/// Known vectors verified against NIST CVSS v3.1 calculator.
const KNOWN_VECTORS: &[(&str, &str, &str)] = &[
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8", "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "10.0", "CRITICAL"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.8", "HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "5.5", "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1", "MEDIUM"),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "4.6", "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "8.1", "HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "7.8", "HIGH"),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "8.8", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "8.8", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "7.2", "HIGH"),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "7.0", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "7.5", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "7.5", "HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "8.8", "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0", "NONE"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "5.3", "MEDIUM"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", "3.5", "LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "8.8", "HIGH"),
];

#[test]
fn all_known_vectors_via_cli() {
    for (vector, expected_score, expected_severity) in KNOWN_VECTORS {
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
        assert!(
            stdout.contains(expected_score),
            "expected score {expected_score} for {vector}, got: {stdout}"
        );
        assert!(
            stdout.contains(expected_severity),
            "expected severity {expected_severity} for {vector}, got: {stdout}"
        );
    }
}

#[test]
fn zero_impact_via_cli() {
    cvss_cmd()
        .args(["--vector-only", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"])
        .assert()
        .success()
        .stdout(predicates::prelude::predicate::str::contains("0.0"))
        .stdout(predicates::prelude::predicate::str::contains("NONE"));
}
