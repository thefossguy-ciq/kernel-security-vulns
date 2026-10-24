// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// bippy - generate the CVE record (.json) and announcement mail (.mbox) for
//         a kernel CVE.  All of the real work happens in
//         cve_utils::bippy_core, this is just the command line front end
//         for it.

use clap::Parser;
use cve_utils::bippy_core::{self, GenerateRequest};
use cve_utils::git_config;
use log::{debug, error};
use std::env;

mod cli;

use cli::Args;

/// Initialize and configure the logging system
fn initialize_logging(verbose: bool) -> log::LevelFilter {
    let logging_level = if verbose {
        log::LevelFilter::max()
    } else {
        log::LevelFilter::Error
    };

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    logging_level
}

/// Log command line arguments if in verbose mode
fn log_command_args() {
    if std::env::args().len() > 0 {
        debug!("Raw command line arguments:");
        for (i, arg) in std::env::args().enumerate() {
            debug!("  Arg[{i}]: '{arg}'");
        }
    }
}

/// Type alias for argument validation return value
type ArgsResult = (String, String, String, Vec<String>, Vec<String>);

/// Validate command line arguments and environment variables
fn validate_args_and_env(args: &Args) -> ArgsResult {
    // We should not have ANY trailing arguments, so if we do, print them out and abort
    if !args.remaining_parameters.is_empty() {
        error!("Trailing arguments detected:");
        for (i, arg) in args.remaining_parameters.iter().enumerate() {
            error!("  trailing_arg[{i}]: '{arg}'");
        }
        std::process::exit(1);
    }

    // Check for required arguments
    if args.cve.is_none() {
        error!("Missing required argument: cve");
        std::process::exit(1);
    }

    if args.sha.is_empty() {
        error!("Missing required argument: sha");
        std::process::exit(1);
    }

    if args.json.is_none() && args.mbox.is_none() {
        error!("Missing required argument: one of json or mbox must be specified");
        std::process::exit(1);
    }

    // Check for CVE_USER environment variable if user is not specified
    let user_email = args.user.as_ref().map_or_else(
        || {
            env::var("CVE_USER").unwrap_or_else(|_| {
                error!("Missing required argument: user (-u/--user) and CVE_USER environment variable is not set");
                std::process::exit(1);
            })
        },
        std::clone::Clone::clone
    );

    // Check for CVEKERNELTREE environment variable
    if env::var("CVEKERNELTREE").is_err() {
        error!("CVEKERNELTREE environment variable is not set");
        error!("It needs to be set to the stable repo directory");
        std::process::exit(1);
    }

    // Extract values from args
    let cve_number = args.cve.as_ref().unwrap().clone();
    let git_shas: Vec<String> = args
        .sha
        .iter()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .collect();
    if git_shas.is_empty() {
        error!("Missing required argument: sha");
        std::process::exit(1);
    }

    // Use all provided vulnerable SHAs (if any)
    let vulnerable_shas: Vec<String> = args
        .vulnerable
        .iter()
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .collect();

    // Dig into git if the user name is not set
    let user_name = args
        .name
        .clone()
        .unwrap_or_else(|| git_config::get_git_config("user.name").unwrap_or_default());

    // Debug output if verbose is enabled
    debug!("CVE_NUMBER={cve_number}");
    debug!("GIT_SHAS={git_shas:?}");
    debug!("JSON_FILE={:?}", args.json);
    debug!("MBOX_FILE={:?}", args.mbox);
    debug!("REFERENCE_FILE={:?}", args.reference);
    debug!("GIT_VULNERABLE={vulnerable_shas:?}");

    (cve_number, user_name, user_email, git_shas, vulnerable_shas)
}

/// Main function
fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging system
    initialize_logging(args.verbose);

    // Log command line arguments in verbose mode
    log_command_args();

    // Validate arguments and environment variables
    let (cve_number, user_name, user_email, git_shas, vulnerable_shas) =
        validate_args_and_env(&args);

    // Generate the CVE record and announcement mail
    let record = match bippy_core::generate(&GenerateRequest {
        cve_number: &cve_number,
        fixing_shas: &git_shas,
        vulnerable_shas: &vulnerable_shas,
        reference_file: args.reference.as_deref(),
        message_file: args.message.as_deref(),
        cvss_file: args.cvss.as_deref(),
        user_name: &user_name,
        user_email: &user_email,
    }) {
        Ok(record) => record,
        Err(err) => {
            error!("{err:#}");
            std::process::exit(1);
        }
    };

    // Write the requested output files.  A failed write is logged but does
    // not fail the run, keeping the historic behavior.
    if let Some(path) = args.mbox.as_deref() {
        if let Err(err) = std::fs::write(path, &record.mbox) {
            error!(
                "Warning: Failed to write mbox file to {}: {err}",
                path.display()
            );
        } else {
            debug!("Wrote mbox file to {path}", path = path.display());
        }
    }

    if let Some(path) = args.json.as_deref() {
        if let Err(err) = std::fs::write(path, &record.json) {
            error!(
                "Warning: Failed to write JSON file to {}: {err}",
                path.display()
            );
        } else {
            debug!("Wrote JSON file to {path}", path = path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    // CVSS weights and scores are exact, spec-defined values. Comparing them
    // with an epsilon would let a wrong score pass.
    #![allow(clippy::float_cmp, reason = "spec-defined values compare exactly")]
    use cve_utils::bippy_core;
    use cve_utils::bippy_core::file::{read_message_file, read_tags_file, read_uuid};
    use cve_utils::bippy_core::{parse_cvss_file, process_commit_text, strip_commit_text};
    use cve_utils::dyad::DyadEntry;
    use cve_utils::version_utils::{version_is_mainline, version_is_queue, version_is_rc};
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_version_is_rc() {
        assert!(version_is_rc("5.16-rc1"));
        assert!(version_is_rc("6.1-rc2"));
        assert!(!version_is_rc("5.15.1"));
        assert!(!version_is_rc("6.0"));
    }

    #[test]
    fn test_version_is_queue() {
        assert!(version_is_queue("5.15-queue"));
        assert!(!version_is_queue("5.15.1"));
        assert!(!version_is_queue("6.0"));
    }

    #[test]
    fn test_version_is_mainline() {
        assert!(version_is_mainline("2.6.39"));
        assert!(version_is_mainline("5.16-rc1"));
        assert!(version_is_mainline("6.0"));
        assert!(!version_is_mainline("5.15-queue"));
        assert!(!version_is_mainline("5.15.1"));
    }

    #[test]
    fn test_strip_commit_text() {
        let tags = vec![
            "Signed-off-by".to_string(),
            "Acked-by".to_string(),
            "Reviewed-by".to_string(),
        ];

        let commit_text = "Subject: Fix a bug\n\nThis commit fixes a bug in the kernel.\n\nSigned-off-by: Bob <bob@example.com>\nAcked-by: Alice <alice@example.com>\n";

        let expected = "In the Linux kernel, the following vulnerability has been resolved:\n\nSubject: Fix a bug\n\nThis commit fixes a bug in the kernel.\n";

        let result = strip_commit_text(commit_text, &tags);
        assert_eq!(result, expected);

        // Test with empty tags
        let empty_tags: Vec<String> = Vec::new();
        let result = strip_commit_text(commit_text, &empty_tags);
        assert_eq!(result, "In the Linux kernel, the following vulnerability has been resolved:\n\nSubject: Fix a bug\n\nThis commit fixes a bug in the kernel.\n\nSigned-off-by: Bob <bob@example.com>\nAcked-by: Alice <alice@example.com>\n");

        // Test with multi-paragraph commit
        let multi_para_commit = "Subject: Complex fix\n\nParagraph 1 with details.\n\nParagraph 2 with more details.\n\nSigned-off-by: Bob <bob@example.com>\n";
        let expected_multi = "In the Linux kernel, the following vulnerability has been resolved:\n\nSubject: Complex fix\n\nParagraph 1 with details.\n\nParagraph 2 with more details.\n";
        let result = strip_commit_text(multi_para_commit, &tags);
        assert_eq!(result, expected_multi);
    }

    #[test]
    fn test_message_file_functionality() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let script_dir = temp_dir.path();

        // Create a test .message file
        let test_sha = "abc123def456";
        let message_file_path = script_dir.join(format!("{test_sha}.message"));
        let custom_message = "This is a custom CVE description from a .message file\n\nIt should be used instead of the git commit message.";
        fs::write(&message_file_path, custom_message).unwrap();

        // Test that read_message_file finds and reads the file
        let result = read_message_file(&message_file_path).unwrap();
        assert_eq!(result, Some(custom_message.to_string()));

        // Test process_commit_text with message file
        let commit_text = "Original commit message that should be ignored";
        let processed = process_commit_text(script_dir, commit_text, Some(&message_file_path));
        assert!(processed.starts_with("In the Linux kernel, the following vulnerability has been resolved:"));
        assert!(processed.contains("This is a custom CVE description"));
        assert!(!processed.contains("Original commit message"));

        // Test process_commit_text without message file
        fs::write(script_dir.join("tags"), "Signed-off-by\n").unwrap();
        let processed_no_message = process_commit_text(script_dir, commit_text, None);
        assert!(processed_no_message.starts_with("In the Linux kernel, the following vulnerability has been resolved:"));
        assert!(processed_no_message.contains("Original commit message"));

        // Test empty message file - should fall back to commit message
        let empty_message_path = script_dir.join("empty.message");
        fs::write(&empty_message_path, "   \n\n   \n").unwrap();
        let processed_empty = process_commit_text(script_dir, commit_text, Some(&empty_message_path));
        assert!(processed_empty.starts_with("In the Linux kernel, the following vulnerability has been resolved:"));
        assert!(processed_empty.contains("Original commit message"));
    }

    #[test]
    fn test_determine_default_status() {
        // Test with vulnerable_version = 0
        let entries =
            vec![DyadEntry::new("0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap()];
        assert_eq!(
            bippy_core::version::determine_default_status(&entries),
            "affected"
        );

        // Test with invalid git id
        /* FIXME, does not build, but you get the idea of what we should be testing...
        match DyadEntry::new("5.10:abcdef123456:5.15:11c52d250b34a0862edc29db03fbec23b30db6da") {
            Ok(d) => {
                assert_eq!(0, 0);
            }
            Err(e) => {
                assert_eq!(e, Err(InvalidDyadGitId("abcdef123456")));
            }
        } */

        // Test with mainline vulnerable version that's different from the fixed version
        let entries = vec![
            DyadEntry::new("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap(),
        ];
        assert_eq!(
            bippy_core::version::determine_default_status(&entries),
            "affected"
        );

        // Test with mainline version that's both vulnerable and fixed in the same version
        // This should be "unaffected" because no actually released version was affected
        let entries = vec![
            DyadEntry::new("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(
            bippy_core::version::determine_default_status(&entries),
            "unaffected"
        );

        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            DyadEntry::new("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap(),
            DyadEntry::new("0:0:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(
            bippy_core::version::determine_default_status(&entries),
            "affected"
        );

        // Test with multiple entries, mix of same-version fixes and different-version fixes
        let entries = vec![
            DyadEntry::new("5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a").unwrap(),
            DyadEntry::new("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(
            bippy_core::version::determine_default_status(&entries),
            "unaffected"
        );
    }

    #[test]
    fn test_generate_version_ranges() {
        // Test with a single entry for a stable kernel
        let entries = vec![
            DyadEntry::new("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap(),
        ];

        let kernel_versions =
            bippy_core::version::generate_version_ranges(&entries, "unaffected").kernel_versions;
        let git_versions = bippy_core::version::generate_git_ranges(&entries);

        // Check git versions
        assert_eq!(git_versions.len(), 1);
        assert_eq!(
            git_versions[0].version,
            "11c52d250b34a0862edc29db03fbec23b30db6da"
        );
        assert_eq!(
            git_versions[0].less_than,
            Some("2b503c8598d1b232e7fc7526bce9326d92331541".to_string())
        );
        assert_eq!(git_versions[0].status, "affected");

        // Check kernel versions - expect 2 entries based on the implementation
        assert_eq!(kernel_versions.len(), 2);
        // First entry: explicit affected version
        assert_eq!(kernel_versions[0].version, "5.15");
        assert_eq!(kernel_versions[0].status, "affected");
        // Second entry: version range
        assert_eq!(kernel_versions[1].version, "5.15");
        assert_eq!(kernel_versions[1].less_than, Some("5.16".to_string()));
        assert_eq!(kernel_versions[1].status, "affected");

        // Test with default status "affected"
        let entries = vec![
            DyadEntry::new("6.0:d640c4cb8f2f933c0ca896541f9de7fb1ae245f4:6.1:c1547f12df8b8e9ca2686accee43213ecd117efe").unwrap(),
        ];

        let kernel_versions =
            bippy_core::version::generate_version_ranges(&entries, "affected").kernel_versions;
        let git_versions = bippy_core::version::generate_git_ranges(&entries);

        // Check git versions
        assert_eq!(git_versions.len(), 1);

        // Check kernel versions (should include unaffected entries)
        assert!(kernel_versions.len() >= 2);

        // Find the affected version
        let affected = kernel_versions
            .iter()
            .find(|v| v.status == "affected")
            .unwrap();
        assert_eq!(affected.version, "6.0");

        // Find the unaffected version
        let unaffected = kernel_versions
            .iter()
            .find(|v| v.status == "unaffected" && v.version == "6.1")
            .unwrap();
        assert_eq!(unaffected.version, "6.1");

        // Test with multiple entries
        let entries = vec![
            DyadEntry::new("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap(),
            DyadEntry::new("6.0:d640c4cb8f2f933c0ca896541f9de7fb1ae245f4:6.1:c1547f12df8b8e9ca2686accee43213ecd117efe").unwrap(),
        ];

        let kernel_versions =
            bippy_core::version::generate_version_ranges(&entries, "unaffected").kernel_versions;
        let git_versions = bippy_core::version::generate_git_ranges(&entries);

        // Check git versions (should have two entries)
        assert_eq!(git_versions.len(), 2);

        // Check kernel versions (should have four entries based on implementation)
        assert_eq!(kernel_versions.len(), 4);
    }

    #[test]
    fn test_read_tags_file() {
        let dir = tempdir().unwrap();
        let tags_path = dir.path().join("tags");

        // Create a test tags file
        let tags_content = "Signed-off-by\nAcked-by\nReviewed-by\n";
        let mut file = File::create(&tags_path).unwrap();
        file.write_all(tags_content.as_bytes()).unwrap();

        // Test reading the tags file
        let tags = read_tags_file(dir.path()).unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], "Signed-off-by");
        assert_eq!(tags[1], "Acked-by");
        assert_eq!(tags[2], "Reviewed-by");

        // Test with empty file
        let empty_tags_path = dir.path().join("tags");
        std::fs::remove_file(&tags_path).unwrap();
        let mut file = File::create(&empty_tags_path).unwrap();
        file.write_all(b"").unwrap();
        let tags = read_tags_file(dir.path()).unwrap();
        assert_eq!(tags.len(), 0);

        // Test with file containing empty lines and comments
        let mixed_content = "Tag1\n\nTag2\n# This is a comment\nTag3\n";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&empty_tags_path)
            .unwrap();
        file.write_all(mixed_content.as_bytes()).unwrap();

        // Read tags file - our implementation should ignore empty lines and comments
        let tags = read_tags_file(dir.path()).unwrap();
        assert_eq!(tags.len(), 3); // Changed from 4 to 3 to match implementation
    }

    #[test]
    fn test_read_uuid() {
        let dir = tempdir().unwrap();
        let uuid_path = dir.path().join("linux.uuid");

        // Create a test UUID file
        let uuid_content = "12345678-abcd-efgh-ijkl-mnopqrstuvwx\n";
        let mut file = File::create(&uuid_path).unwrap();
        file.write_all(uuid_content.as_bytes()).unwrap();

        // Test reading the UUID file
        let uuid = read_uuid(dir.path()).unwrap();
        assert_eq!(uuid, "12345678-abcd-efgh-ijkl-mnopqrstuvwx");

        // Test with empty file
        std::fs::remove_file(&uuid_path).unwrap();
        let empty_path = dir.path().join("linux.uuid");
        let mut file = File::create(&empty_path).unwrap();
        file.write_all(b"").unwrap();
        let result = read_uuid(dir.path());
        assert!(result.is_err());
    }

    const TEST_CNA: &str = "f4215fc3-5b6b-47ff-a258-f7189bd81038";
    const TEST_VECTOR: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";

    fn test_rationale() -> String {
        [
            "AV:L - reachable only through local file I/O",
            "AC:L - fully deterministic, no race to win",
            "PR:L - an unprivileged local user suffices",
            "UI:N - no action from any other user is needed",
            "S:U - stays inside the kernel's own security authority",
            "C:N - the fault happens before any data is returned",
            "I:H - an attacker-chosen modification of protected state",
            "A:H - panics outright on panic_on_oops builds",
        ]
        .join("\n")
    }

    fn write_cvss_file(dir: &std::path::Path, content: &str) -> PathBuf {
        let path = dir.join("CVE-2026-00001.cvss");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_parse_cvss_file_without_rationale() {
        let dir = tempdir().unwrap();
        let path = write_cvss_file(dir.path(), &format!("{TEST_CNA} {TEST_VECTOR}\n"));

        let metrics = parse_cvss_file(&path).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cvss_v3_1.vector_string, TEST_VECTOR);
        assert_eq!(metrics[0].cvss_v3_1.base_score, 7.1);
        assert_eq!(metrics[0].cvss_v3_1.base_severity, "HIGH");
        assert!(metrics[0].scenarios.is_empty());
    }

    #[test]
    fn test_parse_cvss_file_with_rationale() {
        let dir = tempdir().unwrap();
        let path = write_cvss_file(
            dir.path(),
            &format!("{TEST_CNA} {TEST_VECTOR}\n\n{}\n", test_rationale()),
        );

        let metrics = parse_cvss_file(&path).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].scenarios.len(), 1);
        assert_eq!(metrics[0].scenarios[0].lang, "en");

        let value = &metrics[0].scenarios[0].value;
        assert_eq!(value.lines().count(), 8);
        assert!(value.starts_with("AV:L - reachable only through local file I/O"));
        assert!(value.ends_with("A:H - panics outright on panic_on_oops builds"));
    }

    #[test]
    fn test_parse_cvss_file_rejects_over_length_rationale() {
        let dir = tempdir().unwrap();
        let padding = "word ".repeat(1000);
        let over_long = test_rationale().replace(
            "AV:L - reachable only through local file I/O",
            &format!("AV:L - reachable only through local file I/O {padding}"),
        );
        let path = write_cvss_file(
            dir.path(),
            &format!("{TEST_CNA} {TEST_VECTOR}\n\n{over_long}\n"),
        );

        let err = parse_cvss_file(&path).unwrap_err().to_string();
        assert!(err.contains("4096"), "unexpected error: {err}");
    }

    #[test]
    fn test_parse_cvss_file_rejects_rationale_that_disagrees_with_the_vector() {
        let dir = tempdir().unwrap();
        let path = write_cvss_file(
            dir.path(),
            &format!(
                "{TEST_CNA} CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\n{}\n",
                test_rationale()
            ),
        );

        assert!(parse_cvss_file(&path).is_err());
    }

    #[test]
    fn test_parse_cvss_file_reports_unusable_files() {
        let dir = tempdir().unwrap();

        // Silently returning no metrics here would strip the score from a
        // record that already has one.
        let path = write_cvss_file(dir.path(), "not-a-cvss-file\n");
        assert!(parse_cvss_file(&path).is_err());

        let missing = dir.path().join("CVE-2026-00002.cvss");
        assert!(parse_cvss_file(&missing).is_err());
    }

    #[test]
    fn test_parse_cvss_file_handles_crlf() {
        let dir = tempdir().unwrap();
        let content = format!("{TEST_CNA} {TEST_VECTOR}\n\n{}\n", test_rationale());
        let path = write_cvss_file(dir.path(), &content.replace('\n', "\r\n"));

        let metrics = parse_cvss_file(&path).unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].scenarios.len(), 1);
        assert_eq!(metrics[0].scenarios[0].value.lines().count(), 8);
        assert!(!metrics[0].scenarios[0].value.contains('\r'));
    }

    #[test]
    fn test_cvss_metric_serializes_scenarios() {
        let dir = tempdir().unwrap();
        let path = write_cvss_file(
            dir.path(),
            &format!("{TEST_CNA} {TEST_VECTOR}\n\n{}\n", test_rationale()),
        );

        let metrics = parse_cvss_file(&path).unwrap();
        let json = serde_json::to_string_pretty(&metrics[0]).unwrap();
        assert!(json.contains("\"cvssV3_1\""), "{json}");
        assert!(json.contains("\"scenarios\""), "{json}");
        assert!(json.contains("\"lang\": \"en\""), "{json}");

        // A metric with no rationale must not grow an empty scenarios array.
        let bare = write_cvss_file(dir.path(), &format!("{TEST_CNA} {TEST_VECTOR}\n"));
        let bare_json = serde_json::to_string(&parse_cvss_file(&bare).unwrap()[0]).unwrap();
        assert!(!bare_json.contains("scenarios"), "{bare_json}");
    }

    #[test]
    fn test_get_script_version() {
        // With the new implementation, script_version is obtained directly from Cargo.toml
        // using the env!("CARGO_PKG_VERSION") macro, which is evaluated at compile time

        // We can't easily test the exact value since it depends on the Cargo.toml
        // But we can verify the format is correct (typically something like "0.1.0")

        let version = env!("CARGO_PKG_VERSION");

        // Check that it's a valid semver format
        assert!(
            version.split('.').count() >= 2,
            "Version should have at least major.minor format"
        );

        // Check that it contains only valid semver characters
        assert!(
            version.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "Version should only contain digits and dots"
        );
    }
}
