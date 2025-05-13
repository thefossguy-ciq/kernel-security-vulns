// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use clap::Parser;
use cve_utils::git_config;
use cve_utils::git_utils::{get_object_full_sha, resolve_reference};
use git2::Repository;
use log::{debug, error, warn};
use std::env;
use std::path::{Path, PathBuf};

mod commands;
mod models;
mod utils;

use commands::{generate_json_record, generate_mbox};
use models::{Args, DyadEntry};
use utils::{apply_diff_to_text, get_commit_subject, get_commit_text, read_tags_file, run_dyad, strip_commit_text};

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
    if !args.trailing_args.is_empty() {
        error!("Trailing arguments detected:");
        for (i, arg) in args.trailing_args.iter().enumerate() {
            error!("  trailing_arg[{i}]: '{arg}'");
        }
        std::process::exit(1);
    }

    // Check for required arguments
    if args.cve.is_none() || args.sha.is_empty() || (args.json.is_none() && args.mbox.is_none()) {
        error!("Missing required arguments: cve, sha, or one of json/mbox");
        std::process::exit(1);
    }

    // Check for CVE_USER environment variable if user is not specified
    let user_email = match args.user.as_ref() {
        Some(email) => email.clone(),
        None => if let Ok(val) = env::var("CVE_USER") {
            val
        } else {
            error!("Missing required argument: user (-u/--user) and CVE_USER environment variable is not set");
            std::process::exit(1);
        },
    };

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
    let user_name = args.name.clone()
        .unwrap_or_else(|| git_config::get_git_config("user.name").unwrap_or_default());

    // Debug output if verbose is enabled
    debug!("CVE_NUMBER={cve_number}");
    debug!("GIT_SHAS={git_shas:?}");
    debug!("JSON_FILE={:?}", args.json);
    debug!("MBOX_FILE={:?}", args.mbox);
    debug!("DIFF_FILE={:?}", args.diff);
    debug!("REFERENCE_FILE={:?}", args.reference);
    debug!("GIT_VULNERABLE={vulnerable_shas:?}");

    (cve_number, user_name, user_email, git_shas, vulnerable_shas)
}

/// Get repository and script directories
fn get_directories() -> Result<(String, PathBuf, String, String)> {
    // Get vulns directory using cve_utils
    let vulns_dir = cve_utils::find_vulns_dir()
        .with_context(|| "Failed to find vulns directory")?;

    // Get scripts directory
    let script_dir = vulns_dir.join("scripts");
    if !script_dir.exists() {
        return Err(anyhow::anyhow!(
            "Scripts directory not found at {}",
            script_dir.display()
        ));
    }

    // Get the script name
    let script_name = "bippy".to_string();

    // Get the script version using Cargo package version
    let script_version = env!("CARGO_PKG_VERSION").to_string();

    // Get kernel tree path from environment
    let kernel_tree = env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;

    Ok((kernel_tree, script_dir, script_name, script_version))
}

/// Get commit information from Git repository
fn get_commit_info(
    kernel_tree: &str,
    git_shas: &[String],
) -> Result<(String, String, String)> {
    // Open the kernel repository
    let repo = Repository::open(kernel_tree)
        .with_context(|| format!("Failed to open Git repository at {kernel_tree:?}"))?;

    // Resolve Git references for all main commits
    let git_refs: Vec<_> = git_shas
        .iter()
        .filter_map(|sha| match resolve_reference(&repo, sha) {
            Ok(reference) => Some(reference),
            Err(err) => {
                warn!("Warning: Could not resolve SHA reference: {err}");
                None
            }
        })
        .collect();
    if git_refs.is_empty() {
        error!("None of the provided SHAs could be resolved");
        std::process::exit(1);
    }

    // Use the first as the main one for output fields
    let main_git_ref = &git_refs[0];

    // Get SHA information for the main commit
    let git_sha_full = get_object_full_sha(&repo, main_git_ref)
        .with_context(|| "Failed to get full SHA")?;
    let commit_subject = get_commit_subject(&repo, main_git_ref)
        .with_context(|| "Failed to get commit subject")?;

    // Get the full commit message text for the main commit
    let git_ref = resolve_reference(&repo, &git_sha_full)?;
    let commit_text = get_commit_text(&repo, &git_ref)?;

    Ok((git_sha_full, commit_subject, commit_text))
}

/// Process the commit text with optional diff application
fn process_commit_text(
    script_dir: &Path,
    commit_text: &str,
    diff_path: Option<&Path>,
) -> String {
    // Read the tags file to strip from commit message
    let tags = read_tags_file(script_dir).unwrap_or_default();

    // Strip tags from commit text
    let mut processed_text = strip_commit_text(commit_text, &tags);

    // Apply diff file to the commit text if provided
    if let Some(path) = diff_path {
        match apply_diff_to_text(&processed_text, path) {
            Ok(modified_text) => {
                debug!("Applied diff from {} to the commit text", path.display());
                // The apply_diff_to_text function handles newline preservation
                processed_text = modified_text;
            }
            Err(err) => {
                error!("Warning: Failed to apply diff to commit text: {err}");
            }
        }
    }

    processed_text
}

/// Run dyad and parse its output into `DyadEntry` objects
fn run_dyad_and_parse(
    script_dir: &Path,
    git_shas: &[String],
    vulnerable_shas: &[String],
) -> Vec<DyadEntry> {
    let dyad_data = match run_dyad(script_dir, git_shas, vulnerable_shas) {
        Ok(data) => data,
        Err(err) => {
            warn!("Warning: Failed to run dyad: {err:?}");
            String::new()
        }
    };

    // Parse dyad output into DyadEntry objects
    let mut dyad_entries: Vec<DyadEntry> = Vec::new();

    // Process dyad data to create entries
    if !dyad_data.is_empty() {
        for line in dyad_data.lines() {
            // Skip comments and empty lines
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Parse the line directly as DyadEntry
            if let Ok(entry) = DyadEntry::from_str(line) {
                dyad_entries.push(entry);
            }
        }
    }

    dyad_entries
}

/// Read additional references from a file if specified
fn read_additional_references(reference_path: Option<PathBuf>) -> Vec<String> {
    if let Some(ref_path) = reference_path {
        debug!("Attempting to read references from {ref_path:?}");

        if let Ok(contents) = std::fs::read_to_string(&ref_path) {
            debug!("Successfully read reference file");
            if contents.is_empty() {
                debug!("Reference file is empty");
            } else {
                debug!("Reference file contains {} lines", contents.lines().count());
                for (i, line) in contents.lines().enumerate() {
                    if !line.trim().is_empty() {
                        debug!("  Reference[{}]: {}", i, line.trim());
                    }
                }
            }

            contents
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        } else {
            warn!("Warning: Failed to read reference file from {ref_path:?}");
            if !ref_path.exists() {
                debug!("  File does not exist");
            } else if !ref_path.is_file() {
                debug!("  Path exists but is not a regular file");
            } else {
                debug!("  File exists but could not be read (permissions issue?)");
            }
            Vec::new()
        }
    } else {
        debug!("No reference file specified");
        Vec::new()
    }
}

/// Output parameters for generating files
struct OutputParams<'a> {
    cve_number: &'a str,
    git_sha_full: &'a str,
    commit_subject: &'a str,
    user_name: &'a str,
    user_email: &'a str,
    script_name: &'a str,
    script_version: &'a str,
    commit_text: &'a str,
}

/// Generate and write output files (mbox and/or JSON)
fn generate_output_files(
    mbox_path: Option<&Path>,
    json_path: Option<&Path>,
    params: &OutputParams,
    dyad_entries: &[DyadEntry],
    additional_references: &[String],
) {
    // Generate mbox file if requested
    // This has to be done BEFORE the json file creation because sometimes we do not have a set of
    // valid vulnerable:fixed pairs that are not in a single release which means we should not be
    // creating anything at all. The mbox generation catches this type of issue and will abort
    // everything if it happens.
    if let Some(path) = mbox_path {
        // Convert to Vec for generate_mbox which expects &Vec<DyadEntry>
        let entries_vec: Vec<DyadEntry> = dyad_entries.to_vec();

        let mbox_content = generate_mbox(
            params.cve_number,
            params.git_sha_full,
            params.commit_subject,
            params.user_name,
            params.user_email,
            &entries_vec,
            params.script_name,
            params.script_version,
            additional_references,
            params.commit_text,
        );

        if let Err(err) = std::fs::write(path, mbox_content) {
            error!("Warning: Failed to write mbox file to {path:?}: {err}");
        } else {
            debug!("Wrote mbox file to {path}", path=path.display());
        }
    }

    // Generate JSON file if requested
    if let Some(path) = json_path {
        match generate_json_record(
            params.cve_number,
            params.git_sha_full,
            params.commit_subject,
            params.user_name,
            params.user_email,
            dyad_entries.to_vec(),
            params.script_name,
            params.script_version,
            additional_references,
            params.commit_text,
        ) {
            Ok(json_record) => {
                if let Err(err) = std::fs::write(path, json_record) {
                    error!("Warning: Failed to write JSON file to {path:?}: {err}");
                } else {
                    debug!("Wrote JSON file to {path}", path=path.display());
                }
            }
            Err(err) => {
                error!("Error: Failed to generate JSON record: {err}");
            }
        }
    }
}

/// Main function
fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging system
    initialize_logging(args.verbose);

    // Log command line arguments in verbose mode
    log_command_args();

    // Validate arguments and environment variables
    let (cve_number, user_name, user_email, git_shas, vulnerable_shas) = validate_args_and_env(&args);

    // Get required directories and script information
    let (kernel_tree, script_dir, script_name, script_version) = get_directories()?;

    // Get Git commit information
    let (git_sha_full, commit_subject, raw_commit_text) = get_commit_info(&kernel_tree, &git_shas)?;

    // Process commit text with optional diff application
    let commit_text = process_commit_text(&script_dir, &raw_commit_text, args.diff.as_deref());

    // Run dyad and parse its output
    let dyad_entries = run_dyad_and_parse(&script_dir, &git_shas, &vulnerable_shas);

    // Read additional references from file if specified
    let additional_references = read_additional_references(args.reference);

    // Create output parameters
    let output_params = OutputParams {
        cve_number: &cve_number,
        git_sha_full: &git_sha_full,
        commit_subject: &commit_subject,
        user_name: &user_name,
        user_email: &user_email,
        script_name: &script_name,
        script_version: &script_version,
        commit_text: &commit_text,
    };

    // Generate and write output files
    generate_output_files(
        args.mbox.as_deref(),
        args.json.as_deref(),
        &output_params,
        &dyad_entries,
        &additional_references,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cve_utils::version_utils::{version_is_mainline, version_is_queue, version_is_rc};
    use std::fs::File;
    use std::io::Write;
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
    fn test_dyad_entry_parsing() {
        let entry = DyadEntry::from_str("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap();
        assert_eq!(entry.vulnerable.version(), "5.15");
        assert_eq!(
            entry.vulnerable.git_id(),
            "11c52d250b34a0862edc29db03fbec23b30db6da"
        );
        assert_eq!(entry.fixed.version(), "5.16");
        assert_eq!(
            entry.fixed.git_id(),
            "2b503c8598d1b232e7fc7526bce9326d92331541"
        );
        assert!(entry.is_fixed());
        assert!(entry.is_cross_version());

        // Test with a vulnerability that isn't fixed
        let entry =
            DyadEntry::from_str("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:0:0").unwrap();
        assert_eq!(entry.vulnerable.version(), "5.15");
        assert_eq!(
            entry.vulnerable.git_id(),
            "11c52d250b34a0862edc29db03fbec23b30db6da"
        );
        assert!(entry.fixed.is_empty());
        assert_eq!(entry.fixed.version(), "0");
        assert_eq!(entry.fixed.git_id(), "0");
        assert!(!entry.is_fixed());

        // Test with an unknown introduction point
        let entry =
            DyadEntry::from_str("0:0:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap();
        assert!(entry.vulnerable.is_empty());
        assert_eq!(entry.vulnerable.version(), "0");
        assert_eq!(entry.vulnerable.git_id(), "0");
        assert_eq!(entry.fixed.version(), "5.16");
        assert_eq!(
            entry.fixed.git_id(),
            "2b503c8598d1b232e7fc7526bce9326d92331541"
        );
        assert!(entry.is_fixed());
        assert!(!entry.is_cross_version());
    }

    #[test]
    fn test_invalid_dyad_entry() {
        let result = DyadEntry::from_str("invalid:format");
        assert!(result.is_err());
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
    fn test_determine_default_status() {
        // Test with vulnerable_version = 0
        let entries =
            vec![DyadEntry::from_str("0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap()];
        assert_eq!(utils::version::determine_default_status(&entries), "affected");

        // Test with invalid git id
        /* FIXME, does not build, but you get the idea of what we should be testing...
        match DyadEntry::from_str("5.10:abcdef123456:5.15:11c52d250b34a0862edc29db03fbec23b30db6da") {
            Ok(d) => {
                assert_eq!(0, 0);
            }
            Err(e) => {
                assert_eq!(e, Err(InvalidDyadGitId("abcdef123456")));
            }
        } */

        // Test with mainline vulnerable version that's different from the fixed version
        let entries = vec![
            DyadEntry::from_str("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap(),
        ];
        assert_eq!(utils::version::determine_default_status(&entries), "affected");

        // Test with mainline version that's both vulnerable and fixed in the same version
        // This should be "unaffected" because no actually released version was affected
        let entries = vec![
            DyadEntry::from_str("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(utils::version::determine_default_status(&entries), "unaffected");

        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            DyadEntry::from_str("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap(),
            DyadEntry::from_str("0:0:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(utils::version::determine_default_status(&entries), "affected");

        // Test with multiple entries, mix of same-version fixes and different-version fixes
        let entries = vec![
            DyadEntry::from_str("5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a").unwrap(),
            DyadEntry::from_str("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(utils::version::determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_generate_version_ranges() {
        // Test with a single entry for a stable kernel
        let entries = vec![
            DyadEntry::from_str("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap(),
        ];

        let kernel_versions = utils::version::generate_version_ranges(&entries, "unaffected");
        let git_versions = utils::version::generate_git_ranges(&entries);

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
            DyadEntry::from_str("6.0:d640c4cb8f2f933c0ca896541f9de7fb1ae245f4:6.1:c1547f12df8b8e9ca2686accee43213ecd117efe").unwrap(),
        ];

        let kernel_versions = utils::version::generate_version_ranges(&entries, "affected");
        let git_versions = utils::version::generate_git_ranges(&entries);

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
            DyadEntry::from_str("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap(),
            DyadEntry::from_str("6.0:d640c4cb8f2f933c0ca896541f9de7fb1ae245f4:6.1:c1547f12df8b8e9ca2686accee43213ecd117efe").unwrap(),
        ];

        let kernel_versions = utils::version::generate_version_ranges(&entries, "unaffected");
        let git_versions = utils::version::generate_git_ranges(&entries);

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
        let tags = utils::file::read_tags_file(dir.path()).unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], "Signed-off-by");
        assert_eq!(tags[1], "Acked-by");
        assert_eq!(tags[2], "Reviewed-by");

        // Test with empty file
        let empty_tags_path = dir.path().join("tags");
        std::fs::remove_file(&tags_path).unwrap();
        let mut file = File::create(&empty_tags_path).unwrap();
        file.write_all(b"").unwrap();
        let tags = utils::file::read_tags_file(dir.path()).unwrap();
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
        let tags = utils::file::read_tags_file(dir.path()).unwrap();
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
        let uuid = utils::file::read_uuid(dir.path()).unwrap();
        assert_eq!(uuid, "12345678-abcd-efgh-ijkl-mnopqrstuvwx");

        // Test with empty file
        std::fs::remove_file(&uuid_path).unwrap();
        let empty_path = dir.path().join("linux.uuid");
        let mut file = File::create(&empty_path).unwrap();
        file.write_all(b"").unwrap();
        let result = utils::file::read_uuid(dir.path());
        assert!(result.is_err());
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