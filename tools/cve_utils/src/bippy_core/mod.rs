// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// bippy_core - generate the CVE record (.json) and announcement mail (.mbox)
//              for a kernel CVE from the commit(s) that fix it.  This is the
//              engine behind the 'bippy' tool, usable as a library so that
//              tools which process many CVEs (e.g. cve_update) do not have to
//              fork one bippy process per CVE.

use anyhow::{anyhow, Context, Result};
use log::{debug, error, warn};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub mod cve;
mod dyad;
pub mod file;
pub mod git;
pub mod json;
pub mod mbox;
pub mod policy;
pub mod text;
pub mod version;

pub use json::{generate_json, CveRecordParams};
pub use mbox::{generate_mbox, MboxParams};
pub use text::strip_commit_text;

use crate::cvss::rationale::Rationale;
use crate::dyad::DyadEntry;
use crate::git_utils::{get_affected_files, get_object_full_sha, resolve_reference};
use cve::{CvssMetric, CvssV31, Scenario};
use dyad::run_dyad;
use file::{read_message_file, read_tags_file};
use git::{get_commit_subject, get_commit_text};

/// The tool name recorded in the generated output (the json `x_generator`
/// engine field and the mbox From line), together with `ENGINE_VERSION`.
pub const ENGINE_NAME: &str = "bippy";

/// The engine version recorded in the generated output.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything needed to generate the record of one CVE.
pub struct GenerateRequest<'a> {
    /// CVE identifier (e.g., "CVE-2023-12345")
    pub cve_number: &'a str,
    /// Git ids of the commit(s) that fix the issue
    pub fixing_shas: &'a [String],
    /// Git ids of the commit(s) that introduced the issue, if known
    pub vulnerable_shas: &'a [String],
    /// Optional file with additional reference URLs, one per line
    pub reference_file: Option<&'a Path>,
    /// Optional file whose content replaces the commit message
    pub message_file: Option<&'a Path>,
    /// Optional file with CVSS score(s) and rationale
    pub cvss_file: Option<&'a Path>,
    /// Name of the user creating the CVE
    pub user_name: &'a str,
    /// Email of the user creating the CVE
    pub user_email: &'a str,
}

/// The generated CVE output files, as strings.
pub struct GeneratedRecord {
    /// The CVE record in CVE schema JSON format (the .json file)
    pub json: String,
    /// The announcement mail (the .mbox file)
    pub mbox: String,
}

/// Find the scripts directory of the vulns repository
fn find_script_dir() -> Result<PathBuf> {
    let vulns_dir =
        crate::common::find_vulns_dir().with_context(|| "Failed to find vulns directory")?;

    let script_dir = vulns_dir.join("scripts");
    if !script_dir.exists() {
        return Err(anyhow!(
            "Scripts directory not found at {}",
            script_dir.display()
        ));
    }

    Ok(script_dir)
}

/// The kernel tree, looked up once per process: it cannot change while a
/// tool runs, and callers that generate many CVEs should not re-validate it
/// for every record.
fn cached_kernel_tree() -> Result<&'static Path> {
    static KERNEL_TREE: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    KERNEL_TREE
        .get_or_init(|| crate::common::get_kernel_tree().map_err(|e| format!("{e:#}")))
        .as_deref()
        .map_err(|e| anyhow!("{e}"))
}

/// The scripts directory of the vulns repository, looked up once per process.
pub(crate) fn cached_script_dir() -> Result<&'static Path> {
    static SCRIPT_DIR: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    SCRIPT_DIR
        .get_or_init(|| find_script_dir().map_err(|e| format!("{e:#}")))
        .as_deref()
        .map_err(|e| anyhow!("{e}"))
}

/// The tags to strip from commit messages, loaded from scripts/tags once per
/// process: the file cannot change while a tool runs.
fn cached_tags(script_dir: &Path) -> &'static [String] {
    static TAGS: OnceLock<Vec<String>> = OnceLock::new();
    TAGS.get_or_init(|| read_tags_file(script_dir).unwrap_or_default())
}

/// Get commit information from Git repository
fn get_commit_info(
    kernel_tree: &Path,
    git_shas: &[String],
) -> Result<(String, String, String, Vec<String>)> {
    // Use the per-thread cached repository handle; opening the repository on
    // every call is wasteful for callers that generate many CVEs in a row.
    crate::git_utils::with_repository(kernel_tree, |repo| {
        // Resolve Git references for all main commits
        let git_refs: Vec<_> = git_shas
            .iter()
            .filter_map(|sha| match resolve_reference(repo, sha) {
                Ok(reference) => Some(reference),
                Err(err) => {
                    warn!("Warning: Could not resolve SHA reference: {err}");
                    None
                }
            })
            .collect();
        if git_refs.is_empty() {
            return Err(anyhow!("None of the provided SHAs could be resolved"));
        }

        // Use the first as the main one for output fields
        let main_git_ref = &git_refs[0];

        // Get SHA information for the main commit
        let git_sha_full =
            get_object_full_sha(repo, main_git_ref).with_context(|| "Failed to get full SHA")?;
        let commit_subject = get_commit_subject(repo, main_git_ref)
            .with_context(|| "Failed to get commit subject")?;

        // Get the full commit message text for the main commit
        let git_ref = resolve_reference(repo, &git_sha_full)?;
        let commit_text = get_commit_text(repo, &git_ref)?;

        // Get the affected files list
        let affected_files = get_affected_files(repo, &git_ref)?;

        Ok((git_sha_full, commit_subject, commit_text, affected_files))
    })?
}

/// Process the commit text, replacing it with the content of the message
/// file when one is given and stripping the given tags otherwise.
#[must_use]
pub fn process_commit_text(
    tags: &[String],
    commit_text: &str,
    message_file: Option<&Path>,
) -> String {
    // Check if a message file was explicitly provided
    if let Some(message_path) = message_file {
        if let Ok(Some(message_content)) = read_message_file(message_path) {
            let trimmed_content = message_content.trim();
            // Check if message file has actual content after trimming
            if trimmed_content.is_empty() {
                error!("Warning: Message file {} is empty or contains only whitespace, falling back to commit message", message_path.display());
            } else {
                debug!(
                    "Using content from .message file: {}",
                    message_path.display()
                );
                // When using a .message file, use its content as the complete description
                return format!("In the Linux kernel, the following vulnerability has been resolved:\n\n{trimmed_content}");
            }
        } else {
            error!(
                "Warning: Could not read message file: {}",
                message_path.display()
            );
        }
    }

    // Strip tags from commit text normally
    strip_commit_text(commit_text, tags)
}

/// Run dyad and parse its output into `DyadEntry` objects
fn run_dyad_and_parse(git_shas: &[String], vulnerable_shas: &[String]) -> Vec<DyadEntry> {
    let dyad_data = match run_dyad(git_shas, vulnerable_shas) {
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
            if let Ok(entry) = DyadEntry::new(line) {
                dyad_entries.push(entry);
            }
        }
    }

    dyad_entries
}

/// Read additional references from a file if specified
fn read_additional_references(reference_path: Option<&Path>) -> Vec<String> {
    reference_path.map_or_else(
        || {
            debug!("No reference file specified");
            Vec::new()
        },
        |ref_path| {
            debug!("Attempting to read references from {}", ref_path.display());

            std::fs::read_to_string(ref_path).map_or_else(
                |_| {
                    warn!(
                        "Warning: Failed to read reference file from {}",
                        ref_path.display()
                    );
                    if !ref_path.exists() {
                        debug!("  File does not exist");
                    } else if !ref_path.is_file() {
                        debug!("  Path exists but is not a regular file");
                    } else {
                        debug!("  File exists but could not be read (permissions issue?)");
                    }
                    Vec::new()
                },
                |contents| {
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
                },
            )
        },
    )
}

/// Parse a .cvss file into `CvssMetric` entries.
///
/// The file holds one or more `CNA_ID CVSS_VECTOR` lines, optionally followed
/// by a blank line and the rationale for the score. The rationale is published
/// as `metrics[].scenarios[].value`.
///
/// A file we were told to use but cannot use is an error, not a reason to
/// carry on: dropping the metrics would quietly strip the score from a record
/// that already has one.
///
/// # Errors
///
/// Returns an error if the file cannot be read or does not validate as a
/// CVSS file.
pub fn parse_cvss_file(path: &Path) -> Result<Vec<CvssMetric>> {
    let file = crate::cvss::file::CvssFile::read(path)?;
    file.validate()?;

    let scenarios: Vec<Scenario> = file
        .rationale
        .as_ref()
        .map(Rationale::to_scenario_value)
        .map(|value| {
            vec![Scenario {
                lang: "en".to_string(),
                value,
            }]
        })
        .unwrap_or_default();

    Ok(file
        .entries
        .iter()
        .map(|entry| {
            let result = entry.score();
            CvssMetric {
                cvss_v3_1: CvssV31 {
                    version: "3.1".to_string(),
                    vector_string: entry.vector_string(),
                    base_score: result.score,
                    base_severity: result.severity,
                },
                scenarios: scenarios.clone(),
            }
        })
        .collect())
}

/// Generate the CVE record and announcement mail for one CVE.
///
/// This is the whole bippy pipeline: resolve the fixing commits in the
/// kernel tree, compute the vulnerable:fixed kernel pairs with the dyad
/// engine, check the CVE issuance policy and render the .json and .mbox
/// content.  Nothing is written to disk; the caller decides what to do
/// with the generated strings.
///
/// # Errors
///
/// Returns an error if:
/// - The kernel tree, the vulns directory or the verhaal database cannot be found
/// - None of the fixing commits can be resolved in the kernel tree
/// - No released kernel was affected, so no CVE may be issued (policy)
/// - A given .cvss file cannot be parsed
pub fn generate(req: &GenerateRequest) -> Result<GeneratedRecord> {
    // Get required directories
    let kernel_tree = cached_kernel_tree()?;
    let script_dir = cached_script_dir()?;

    // Get Git commit information
    let (git_sha_full, commit_subject, raw_commit_text, affected_files) =
        get_commit_info(kernel_tree, req.fixing_shas)?;

    // Process commit text
    let commit_text = process_commit_text(cached_tags(script_dir), &raw_commit_text, req.message_file);

    // Run dyad and parse its output
    let dyad_entries = run_dyad_and_parse(req.fixing_shas, req.vulnerable_shas);

    // Check CVE issuance policy - logs error if no released version was affected
    // (see policy.rs for detailed documentation)
    if !policy::check_cve_issuance_policy(&dyad_entries, &git_sha_full) {
        return Err(anyhow!(
            "no released kernel was affected, not assigning a CVE to {git_sha_full}"
        ));
    }

    // Read additional references from file if specified
    let additional_references = read_additional_references(req.reference_file);

    // Parse CVSS file if specified
    let cvss_metrics = match req.cvss_file {
        Some(path) => parse_cvss_file(path)
            .with_context(|| format!("reading CVSS file {}", path.display()))?,
        None => Vec::new(),
    };

    let mbox = generate_mbox(&MboxParams {
        cve_number: req.cve_number,
        git_sha_full: &git_sha_full,
        commit_subject: &commit_subject,
        user_name: req.user_name,
        user_email: req.user_email,
        dyad_entries: &dyad_entries,
        script_name: ENGINE_NAME,
        script_version: ENGINE_VERSION,
        additional_references: &additional_references,
        commit_text: &commit_text,
        affected_files: &affected_files,
        cvss_metrics: &cvss_metrics,
    });

    let json = generate_json(&CveRecordParams {
        cve_number: req.cve_number,
        git_sha_full: &git_sha_full,
        commit_subject: &commit_subject,
        user_name: req.user_name,
        user_email: req.user_email,
        dyad_entries,
        script_name: ENGINE_NAME,
        script_version: ENGINE_VERSION,
        additional_references: &additional_references,
        commit_text: &commit_text,
        affected_files: &affected_files,
        cvss_metrics,
    })?;

    Ok(GeneratedRecord { json, mbox })
}
