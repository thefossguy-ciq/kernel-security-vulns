// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use clap::Parser;
use cve_utils::git_config;
use cve_utils::git_utils::{
    get_affected_files, get_object_full_sha, get_short_sha, resolve_reference,
};
use cve_utils::version_utils::{compare_kernel_versions, version_is_mainline};
use cve_utils::Kernel;
use git2::{Object, Repository};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use serde_json::ser::{PrettyFormatter, Serializer};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Error types for the bippy tool
#[derive(Error, Debug)]
enum BippyError {
    /// Error when parsing a dyad entry
    #[error("Invalid dyad entry: {0}")]
    InvalidDyadEntry(String),

    #[error("Invalid dyad git_id: {0}")]
    InvalidDyadGitId(String),

    #[error("Invalid dyad version: {0}")]
    InvalidDyadVersion(String),

    /// Error in git2 library
    #[error("Git error: {0}")]
    GitError(#[from] git2::Error),

    /// Error in io operations
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// DyadEntry represents a kernel vulnerability range entry from the dyad script
#[derive(Debug, Clone)]
struct DyadEntry {
    vulnerable: Kernel,
    fixed: Kernel,
}

impl DyadEntry {
    /// Create a new DyadEntry from a colon-separated string
    fn from_str(s: &str) -> Result<Self, BippyError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(BippyError::InvalidDyadEntry(s.to_string()));
        }

        let vulnerable_version = parts[0].to_string();
        let vulnerable_git = parts[1].to_string();
        let fixed_version = parts[2].to_string();
        let fixed_git = parts[3].to_string();

        // Create the vulnerable and fixed kernels by the git id, verifying that this is a valid
        // git id AND that the version number is what dyad gave us so that we don't go off of crazy
        // information somehow.
        let vulnerable_kernel = match Kernel::from_id(vulnerable_git.clone()) {
            Ok(v) => v,
            Err(_e) => return Err(BippyError::InvalidDyadGitId(vulnerable_git)),
        };
        if vulnerable_kernel.version() != vulnerable_version {
            return Err(BippyError::InvalidDyadVersion(vulnerable_version));
        }

        let fixed_kernel = match Kernel::from_id(fixed_git.clone()) {
            Ok(v) => v,
            Err(_e) => return Err(BippyError::InvalidDyadGitId(fixed_git)),
        };
        if fixed_kernel.version() != fixed_version {
            return Err(BippyError::InvalidDyadVersion(fixed_version));
        }

        Ok(DyadEntry {
            vulnerable: vulnerable_kernel,
            fixed: fixed_kernel,
        })
    }

    /// Check if this vulnerability has been fixed
    #[cfg(test)]
    fn is_fixed(&self) -> bool {
        !self.fixed.is_empty()
    }

    /// Check if vulnerability spans across different kernel versions
    #[cfg(test)]
    fn is_cross_version(&self) -> bool {
        !self.vulnerable.is_empty()
            && !self.fixed.is_empty()
            && self.vulnerable.version() != self.fixed.version()
    }
}

/// Strip commit text to only keep the relevant parts
/// Removes Signed-off-by and other tags from the commit message
fn strip_commit_text(text: &str, tags: &[String]) -> Result<String> {
    let mut result =
        String::from("In the Linux kernel, the following vulnerability has been resolved:\n\n");

    // Split the commit message by lines
    let lines: Vec<&str> = text.lines().collect();

    // Skip empty lines at the beginning
    let mut i = 0;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }

    // Add subject line
    if i < lines.len() {
        result.push_str(lines[i]);
        result.push_str("\n\n");
        i += 1;
    }

    // Skip empty lines after the subject
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }

    // Add the rest of the message, skipping only lines that exactly start with a tag
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip only if the line actually starts with a recognized tag
        let is_tag_line = tags.iter().any(|tag| {
            let tag_with_colon = format!("{}:", tag);
            trimmed
                .to_lowercase()
                .starts_with(&tag_with_colon.to_lowercase())
        });

        if !is_tag_line {
            result.push_str(line);
            result.push('\n');
        }

        i += 1;
    }

    // Trim trailing whitespace and ensure exactly one newline at the end
    let result = result.trim_end().to_string() + "\n";

    Ok(result)
}

/// Determine the default status for CVE entries based on the dyad entries
fn determine_default_status(entries: &[DyadEntry]) -> &'static str {
    // If any entry has vulnerable_version = 0, status should be "affected"
    if entries.iter().any(|entry| entry.vulnerable.is_empty()) {
        return "affected";
    }

    // If any entry has a mainline vulnerable version AND it's not fixed in the same version,
    // status should be "affected"
    if entries.iter().any(|entry| {
        entry.vulnerable.is_mainline() && entry.vulnerable.version() != entry.fixed.version()
    }) {
        return "affected";
    }

    // Otherwise status should be "unaffected"
    "unaffected"
}

/// Generate CPE ranges for the CVE JSON format
fn generate_cpe_ranges(entries: &[DyadEntry]) -> Vec<CpeNodes> {
    let mut cpe_nodes: Vec<CpeNodes> = vec![];
    let mut node = CpeNodes {
        operator: "OR".to_string(),
        negate: false,
        cpe_match: vec![],
    };

    for entry in entries {
        // Skip entries where the vulnerability is in the same version it was fixed
        // These versions are not actually affected in any released version so CVE.org
        // doesn't like to see them.
        if entry.vulnerable.version() == entry.fixed.version() {
            continue;
        }

        // Our CPE ranges are very simple, if we have a starting point of the vulnerability, we
        // document that, and if we have an end point, we document that.  Nothing fancy.
        let mut cpe_match: CpeMatch = CpeMatch {
            vulnerable: true,
            criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*".to_string(),
            ..Default::default()
        };

        if entry.vulnerable.version() != "0" {
            cpe_match.version_start_including = entry.vulnerable.version();
        }
        if entry.fixed.version() != "0" {
            cpe_match.version_end_excluding = entry.fixed.version();
        }
        node.cpe_match.push(cpe_match);
    }

    cpe_nodes.push(node);
    cpe_nodes
}

/// Generate git ranges for the CVE JSON format
fn generate_git_ranges(entries: &[DyadEntry]) -> Vec<VersionRange> {
    let mut git_versions = Vec::new();

    for entry in entries {
        // If the vulnerable version is 0, use the first Linux commit id as the "start of history"
        let vulnerable_git = if entry.vulnerable.is_empty() {
            // First Linux commit ID
            "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2".to_string()
        } else {
            entry.vulnerable.git_id().to_string()
        };

        let mut ver_range = VersionRange {
            version: vulnerable_git,
            status: "affected".to_string(),
            version_type: Some("git".to_string()),
            ..Default::default()
        };

        // If this entry is fixed, report where it is fixed
        if entry.fixed.git_id() != "0" {
            // This entry is a fixed one, so set the place where it is resolved
            ver_range.less_than = Some(entry.fixed.git_id().to_string());
        }

        git_versions.push(ver_range);
    }
    git_versions
}

/// Generate version ranges for the CVE JSON format
fn generate_version_ranges(entries: &[DyadEntry], default_status: &str) -> Vec<VersionRange> {
    let mut kernel_versions = Vec::new();
    let mut seen_versions = HashSet::new();
    let mut affected_mainline_versions = HashSet::new();
    let mut fixed_mainline_versions = HashSet::new();

    // Add debugging output for the dyad entries we're processing
    debug!(
        "Processing {} dyad entries with default_status={}",
        entries.len(),
        default_status
    );
    for (i, entry) in entries.iter().enumerate() {
        debug!(
            "Dyad entry {}: v:{} vg:{} f:{} fg:{}",
            i,
            entry.vulnerable.version(),
            entry.vulnerable.git_id(),
            entry.fixed.version(),
            entry.fixed.git_id()
        );
    }

    // First pass: Collect all affected and fixed mainline versions
    for entry in entries {
        // Skip entries where the vulnerability is in the same version it was fixed
        // These versions are not actually affected in any released version
        if entry.vulnerable.version() == entry.fixed.version() {
            debug!(
                "Skipping version {} as it was fixed in the same version",
                entry.vulnerable.version()
            );
            continue;
        }

        if entry.vulnerable.is_mainline() {
            affected_mainline_versions.insert(entry.vulnerable.version().clone());
            debug!("Adding affected version: {}", entry.vulnerable.version());
        }
        if entry.fixed.is_mainline() {
            fixed_mainline_versions.insert(entry.fixed.version().clone());
            debug!("Adding fixed version: {}", entry.fixed.version());
        }
    }

    // Get all versions we know about and sort them
    let mut all_versions: Vec<(String, bool)> = Vec::new(); // (version, is_affected)

    // Add all affected versions
    for v in &affected_mainline_versions {
        all_versions.push((v.clone(), true));
    }

    // Add all fixed versions
    for v in &fixed_mainline_versions {
        // Only add if not already in the list as affected
        if !affected_mainline_versions.contains(v) {
            all_versions.push((v.clone(), false));
        }
    }

    // Sort all versions using the shared compare_kernel_versions function
    all_versions.sort_by(|(a, _), (b, _)| compare_kernel_versions(a, b));

    debug!("Sorted versions (version, is_affected):");
    for (v, affected) in &all_versions {
        debug!(
            "   {} => {}",
            v,
            if *affected { "affected" } else { "unaffected" }
        );
    }

    if !all_versions.is_empty() {
        // Process each version and add to kernel_versions if not already seen
        for (version, is_affected) in all_versions.iter() {
            // Don't add individual unaffected mainline versions - they'll be added later with range information
            if !is_affected && version_is_mainline(version) {
                debug!("Skipping individual unaffected mainline version {} - will be added with range info later", version);
                continue;
            }

            let status = if *is_affected {
                "affected"
            } else {
                "unaffected"
            };

            // Skip versions that match the default status (redundant)
            // EXCEPT for affected versions, which we always include for clarity
            if status == default_status && !is_affected {
                debug!(
                    "Skipping explicit version {} (matches default status '{}')",
                    version, default_status
                );
                continue;
            }

            let ver_key = format!("kernel:{}:{}:::", status, version);
            if !seen_versions.contains(&ver_key) {
                seen_versions.insert(ver_key);
                kernel_versions.push(VersionRange {
                    version: version.clone(),
                    less_than: None,
                    less_than_or_equal: None,
                    status: status.to_string(),
                    version_type: None,
                });
                debug!("Added explicit version: {} => {}", version, status);
            }
        }

        // Now infer statuses for intermediate versions
        // This is for versions that fall between our known points
        for i in 0..all_versions.len() - 1 {
            let (current_version, current_affected) = &all_versions[i];
            let (next_version, next_affected) = &all_versions[i + 1];

            debug!(
                "Checking for intermediate versions between {} ({}) and {} ({})",
                current_version,
                if *current_affected {
                    "affected"
                } else {
                    "unaffected"
                },
                next_version,
                if *next_affected {
                    "affected"
                } else {
                    "unaffected"
                }
            );

            // Check if they're in the same major version
            let current_parts: Vec<&str> = current_version.split('.').collect();
            let next_parts: Vec<&str> = next_version.split('.').collect();

            if let (Ok(current_major), Ok(next_major), Ok(current_minor), Ok(next_minor)) = (
                current_parts.first().unwrap_or(&"0").parse::<u32>(),
                next_parts.first().unwrap_or(&"0").parse::<u32>(),
                current_parts.get(1).unwrap_or(&"0").parse::<u32>(),
                next_parts.get(1).unwrap_or(&"0").parse::<u32>(),
            ) {
                debug!(
                    "Parsed version components: {}.{} and {}.{}",
                    current_major, current_minor, next_major, next_minor
                );

                // Only process if they're in the same major version and there's a gap
                if current_major == next_major && next_minor - current_minor > 1 {
                    debug!("Found gap of {} versions", next_minor - current_minor - 1);

                    // Process each intermediate version
                    for minor in (current_minor + 1)..next_minor {
                        let intermediate_version = format!("{}.{}", current_major, minor);

                        // Determine status based on surrounding versions
                        let status = match (*current_affected, *next_affected) {
                            (true, true) => "affected",  // Both surrounding versions affected
                            (false, true) => "affected", // Current fixed, next affected - intermediate is likely affected
                            (true, false) => {
                                // Current affected, next fixed
                                // If we're processing consecutive versions, the last affected version
                                // should be the highest version that is affected, so we don't need to
                                // explicitly add intermediate versions as affected - they'll be covered by default
                                // Prevent redundant entries if default status is already "affected"
                                if default_status == "affected" {
                                    // Skip explicit entry by using default status
                                    debug!(
                                        "Setting status to default_status to skip redundant entry"
                                    );
                                    default_status
                                } else {
                                    "affected" // Only add explicit entries if default is not affected
                                }
                            }
                            (false, false) => "unaffected", // Both surrounding versions fixed
                        };

                        debug!(
                            "Inferring intermediate version {} => {}",
                            intermediate_version, status
                        );

                        // Explicitly check if the status equals the default_status string value
                        let is_default = status == default_status;
                        debug!(
                            "Status '{}' is {} to default '{}'",
                            status,
                            if is_default { "equal" } else { "not equal" },
                            default_status
                        );

                        // Only add intermediate version if its status differs from the default status
                        // This prevents adding redundant entries
                        if !is_default {
                            let ver_key = format!("kernel:{}:{}:::", status, intermediate_version);
                            if !seen_versions.contains(&ver_key) {
                                seen_versions.insert(ver_key);
                                kernel_versions.push(VersionRange {
                                    version: intermediate_version.clone(),
                                    less_than: None,
                                    less_than_or_equal: None,
                                    status: status.to_string(),
                                    version_type: None,
                                });
                                debug!(
                                    "Added intermediate version: {} => {}",
                                    intermediate_version, status
                                );
                            }
                        } else {
                            debug!("Skipping redundant intermediate version {} (matches default status '{}')",
                                      intermediate_version, default_status);
                        }
                    }
                } else {
                    debug!("No gap found or different major versions");
                }
            } else {
                debug!("Failed to parse version components");
            }
        }
    }

    for entry in entries {
        // Skip entries where the vulnerability is in the same version it was fixed
        // as CVE does NOT want us reporting that type of stuff.
        if entry.vulnerable.version() == entry.fixed.version() {
            continue;
        }

        // Handle kernel version ranges
        if default_status == "affected" {
            // Only add versions before affected as unaffected if no other versions before this are affected
            if entry.vulnerable.is_mainline() {
                let unaffected_key = format!("kernel:unaffected:0:{}:", entry.vulnerable.version());
                if !seen_versions.contains(&unaffected_key) {
                    // Check if any version before this one is already marked as affected
                    let is_safe_to_mark_unaffected = !affected_mainline_versions.iter().any(|v| {
                        // Use the shared comparison function
                        match compare_kernel_versions(v, &entry.vulnerable.version()) {
                            std::cmp::Ordering::Less => true, // This affected version is less than current version
                            _ => false,
                        }
                    });

                    if is_safe_to_mark_unaffected {
                        seen_versions.insert(unaffected_key);
                        kernel_versions.push(VersionRange {
                            version: "0".to_string(),
                            less_than: Some(entry.vulnerable.version().clone()),
                            less_than_or_equal: None,
                            status: "unaffected".to_string(),
                            version_type: Some("semver".to_string()),
                        });
                    }
                }
            }

            // Add fixed versions as unaffected
            if entry.fixed.version() != "0" {
                let fixed_version = entry.fixed.version();
                // For stable kernels, determine the wildcard pattern
                let version_parts: Vec<&str> = fixed_version.split('.').collect();
                let wildcard = if version_parts.len() >= 2 {
                    format!("{}.{}.*", version_parts[0], version_parts[1])
                } else {
                    entry.fixed.version().clone() + ".*"
                };

                // Create a unique key for this version
                let key = format!("kernel:unaffected:{}::{}", entry.fixed.version(), wildcard);

                if !seen_versions.contains(&key) {
                    seen_versions.insert(key.clone());

                    // Add fixed version as unaffected
                    if !entry.fixed.is_mainline() {
                        // For stable kernels with a patch version (e.g., 5.10.234)
                        kernel_versions.push(VersionRange {
                            version: entry.fixed.version().clone(),
                            less_than: None,
                            less_than_or_equal: Some(wildcard),
                            status: "unaffected".to_string(),
                            version_type: Some("semver".to_string()),
                        });
                    } else {
                        // For mainline versions, we need to be careful about wildcard ranges
                        // Check if there are any affected versions after this fixed version
                        let has_later_affected = affected_mainline_versions.iter().any(|v| {
                            // Use the shared comparison function
                            match compare_kernel_versions(&entry.fixed.version(), v) {
                                std::cmp::Ordering::Less => true, // Current fixed version is less than this affected version
                                _ => false,
                            }
                        });

                        // Handle RC versions as mainline versions
                        let is_rc_version = entry.fixed.is_rc_version();

                        if has_later_affected && !is_rc_version {
                            // If there's a later affected version, we need to be precise
                            // Find the next version that's affected
                            let mut next_affected_version: Option<String> = None;

                            for v in &affected_mainline_versions {
                                if compare_kernel_versions(&entry.fixed.version(), v)
                                    == std::cmp::Ordering::Less
                                {
                                    // v is later than entry.fixed.version()
                                    if let Some(ref candidate) = next_affected_version {
                                        if compare_kernel_versions(candidate, v)
                                            == std::cmp::Ordering::Greater
                                        {
                                            next_affected_version = Some(v.clone());
                                        }
                                    } else {
                                        // No candidate yet, set this as the first candidate
                                        next_affected_version = Some(v.clone());
                                    }
                                }
                            }

                            if let Some(next_version) = next_affected_version {
                                // Add a range for versions between the fixed version and the next affected version
                                kernel_versions.push(VersionRange {
                                    version: entry.fixed.version().clone(),
                                    less_than: Some(next_version),
                                    less_than_or_equal: None,
                                    status: "unaffected".to_string(),
                                    version_type: Some("semver".to_string()),
                                });
                            } else {
                                // Fallback - should not normally happen
                                kernel_versions.push(VersionRange {
                                    version: entry.fixed.version().clone(),
                                    less_than: None,
                                    less_than_or_equal: None,
                                    status: "unaffected".to_string(),
                                    version_type: Some("original_commit_for_fix".to_string()),
                                });
                            }
                        } else {
                            // No later affected versions or this is an RC version, so we can use the original_commit_for_fix entry
                            kernel_versions.push(VersionRange {
                                version: entry.fixed.version().clone(),
                                less_than: None,
                                less_than_or_equal: Some("*".to_string()),
                                status: "unaffected".to_string(),
                                version_type: Some("original_commit_for_fix".to_string()),
                            });
                        }
                    }
                }
            }
        } else {
            // For unaffected default status, add affected ranges
            if entry.vulnerable.version() != "0" && entry.fixed.version() != "0" {
                let ver_range = VersionRange {
                    version: entry.vulnerable.version().clone(),
                    less_than: Some(entry.fixed.version().clone()),
                    less_than_or_equal: None,
                    status: "affected".to_string(),
                    version_type: Some("semver".to_string()),
                };

                let key = format!(
                    "kernel:affected:{}:{}:",
                    ver_range.version,
                    ver_range.less_than.as_deref().unwrap_or("")
                );

                if !seen_versions.contains(&key) {
                    seen_versions.insert(key);
                    kernel_versions.push(ver_range);
                }
            }
        }
    }

    // Sort the version ranges to ensure consistent output
    kernel_versions.sort_by(|a, b| {
        if a.status != b.status {
            return a.status.cmp(&b.status);
        }

        // For version comparison, parse and compare numerically
        if let (Some(a_type), Some(b_type)) = (&a.version_type, &b.version_type) {
            // Put original_commit_for_fix at the end
            if a_type == "original_commit_for_fix" && b_type != "original_commit_for_fix" {
                return std::cmp::Ordering::Greater;
            }
            if a_type != "original_commit_for_fix" && b_type == "original_commit_for_fix" {
                return std::cmp::Ordering::Less;
            }
        }

        // Use the shared helper function
        compare_kernel_versions(&a.version, &b.version)
    });

    // Before returning, print out the final ranges for debugging
    debug!("Final kernel version ranges:");
    for v in &kernel_versions {
        let range_desc = match (&v.less_than, &v.less_than_or_equal) {
            (Some(lt), None) => format!(" < {}", lt),
            (None, Some(lte)) => format!(" <= {}", lte),
            (Some(lt), Some(lte)) => format!(" < {} OR <= {}", lt, lte),
            (None, None) => "".to_string(),
        };
        debug!("   {} ({}){}", v.version, v.status, range_desc);
    }

    kernel_versions
}

/// Reads the tags file from the script directory
fn read_tags_file(script_dir: &Path) -> Result<Vec<String>> {
    let tags_path = script_dir.join("tags");
    let content = std::fs::read_to_string(&tags_path)
        .with_context(|| format!("Failed to read tags file at {:?}", tags_path))?;

    Ok(content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#')) // Added filter for comments
        .collect())
}

/// Read the UUID for the Linux kernel CVE team from a file
fn read_uuid(script_dir: &Path) -> Result<String> {
    let uuid_path = script_dir.join("linux.uuid");
    let content = std::fs::read_to_string(&uuid_path)
        .with_context(|| format!("Failed to read UUID file at {:?}", uuid_path))?;

    let uuid = content.trim();
    if uuid.is_empty() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "UUID file is empty").into(),
        );
    }

    Ok(uuid.to_string())
}

/// Run the dyad script to get version range information
fn run_dyad(script_dir: &Path, git_shas: &[String], vulnerable_shas: &[String]) -> Result<String> {
    // Ensure dyad script exists
    let dyad_script = script_dir.join("dyad");
    if !dyad_script.exists() {
        return Err(anyhow::anyhow!(
            "Dyad script not found at {}",
            dyad_script.display()
        ));
    }

    // Change directory to the scripts directory
    let current_dir = std::env::current_dir()?;
    std::env::set_current_dir(script_dir)?;

    // Get kernel tree paths from environment variables
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;

    // Construct the command
    let mut command = std::process::Command::new(&dyad_script);

    // Set environment variables
    command.env("CVEKERNELTREE", &kernel_tree);

    // Add each vulnerable SHA as a separate -v argument
    for vuln_sha in vulnerable_shas {
        if !vuln_sha.trim().is_empty() {
            command.arg("-v").arg(vuln_sha);
            if let Ok(repo) = Repository::open(&kernel_tree) {
                if let Ok(obj) = resolve_reference(&repo, vuln_sha) {
                    if let Ok(short_sha) = get_short_sha(&repo, &obj) {
                        debug!("Using vulnerable SHA: {}", short_sha);
                    }
                }
            }
        }
    }

    // Add each Git SHA as a separate --sha1 argument
    for git_sha in git_shas {
        if !git_sha.trim().is_empty() {
            command.arg("--sha1").arg(git_sha);
            debug!("Using fix SHA: {}", git_sha);
        }
    }

    debug!("Running command: {:?}", command);

    // Execute the command
    let output = command
        .output()
        .with_context(|| format!("Failed to execute dyad script at {}", dyad_script.display()))?;

    // Restore original directory
    std::env::set_current_dir(current_dir)?;

    // Check for success
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut error_msg = format!("Dyad script failed with status: {}", output.status);

        if !stderr.is_empty() {
            error_msg.push_str(&format!("\nStderr: {}", stderr));
        }

        if !stdout.is_empty() {
            error_msg.push_str(&format!("\nStdout: {}", stdout));
        }

        return Err(anyhow::anyhow!("{}", error_msg));
    }

    // Return the output
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}

/// Arguments for the bippy tool
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, disable_version_flag = true, trailing_var_arg = true)]
struct Args {
    /// CVE number (e.g., "CVE-2021-1234")
    #[clap(short, long)]
    cve: Option<String>,

    /// Git SHA(s) of the commit(s)
    #[clap(short, long, num_args = 1..)]
    sha: Vec<String>,

    /// Git SHA(s) of the vulnerable commit(s) (optional, can be specified multiple times)
    #[clap(short = 'V', long, num_args = 1..)]
    vulnerable: Vec<String>,

    /// Output JSON file path
    #[clap(short, long)]
    json: Option<PathBuf>,

    /// Output mbox file path
    #[clap(short, long)]
    mbox: Option<PathBuf>,

    /// Diff file to apply to the commit text (optional)
    #[clap(short, long)]
    diff: Option<PathBuf>,

    /// Reference file path
    #[clap(short, long)]
    reference: Option<PathBuf>,

    /// User email
    #[clap(short, long)]
    user: Option<String>,

    /// User name
    #[clap(short = 'n', long)]
    name: Option<String>,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,

    /// Catch any trailing arguments
    #[clap(hide = true)]
    trailing_args: Vec<String>,
}

/// Get the commit subject for a git reference
fn get_commit_subject(_repo: &Repository, obj: &Object) -> Result<String> {
    let commit = obj
        .as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    Ok(commit.summary().unwrap_or("").to_string())
}

/// Get the full commit message text
fn get_commit_text(_repo: &Repository, obj: &Object) -> Result<String> {
    let commit = obj
        .as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    // Get the raw commit message - don't truncate
    let message = commit.message().unwrap_or("").to_string();

    Ok(message)
}

/// Apply a diff to text and return the result
fn apply_diff_to_text(text: &str, diff_file: &Path) -> Result<String> {
    // Create a temporary file
    let mut temp_file = tempfile::NamedTempFile::new()
        .with_context(|| "Failed to create temporary file for applying diff")?;

    // Write the original text to the temporary file
    std::io::Write::write_all(&mut temp_file, text.as_bytes())
        .with_context(|| "Failed to write to temporary file")?;

    // Get the path of the temporary file
    let temp_path = temp_file.path();

    // Run the patch command
    let status = std::process::Command::new("patch")
        .arg("-p1")
        .arg(temp_path)
        .arg(diff_file)
        .status()
        .with_context(|| {
            format!(
                "Failed to execute patch command with diff file {:?}",
                diff_file
            )
        })?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "Patch command failed with status: {}",
            status
        ));
    }

    // Read the modified content
    let modified_text = std::fs::read_to_string(temp_path)
        .with_context(|| "Failed to read patched temporary file")?;

    // Ensure we handle newlines consistently - trim trailing newlines and add exactly one
    let trimmed = modified_text.trim_end();

    // Return the text with exactly one newline at the end, same as the original handling
    if text.ends_with('\n') {
        Ok(format!("{}\n", trimmed))
    } else {
        Ok(trimmed.to_string())
    }
}

/// Models for the CVE JSON format

#[derive(Debug, Serialize, Deserialize)]
struct CveMetadata {
    #[serde(rename = "assignerOrgId")]
    assigner_org_id: String,
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "requesterUserId")]
    requester_user_id: String,
    serial: String,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderMetadata {
    #[serde(rename = "orgId")]
    org_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct VersionRange {
    // Version string, in a specific type, see versionType below for the valid types
    // 0 means "beginning of time"
    version: String,

    #[serde(rename = "lessThan", skip_serializing_if = "Option::is_none")]
    less_than: Option<String>,

    #[serde(rename = "lessThanOrEqual", skip_serializing_if = "Option::is_none")]
    less_than_or_equal: Option<String>,

    // valid values are "affected", "unaffected", or "unknown"
    status: String,

    // valid values are "custom", "git", "maven", "python", "rpm", or "semver"
    // We will just stick with "git" or "semver" as that's the most sane for us, even though
    // "semver" is NOT what Linux kernel release numbers represent at all.
    #[serde(rename = "versionType", skip_serializing_if = "Option::is_none")]
    version_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AffectedProduct {
    product: String,
    vendor: String,
    #[serde(rename = "defaultStatus")]
    default_status: String,
    repo: String,
    #[serde(rename = "programFiles")]
    program_files: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    versions: Vec<VersionRange>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Reference {
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Generator {
    engine: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CpeMatch {
    // boolean value, must be "true" or "false"
    vulnerable: bool,

    // critera for us is always going to be: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    criteria: String,

    #[serde(rename = "versionStartIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    version_start_including: String,

    #[serde(rename = "versionEndExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    version_end_excluding: String,

    // Odds are we will not use the following fields, but they are here
    // just to round out the documentation of the schema
    #[serde(rename = "matchCriteriaId")]
    #[serde(skip_serializing_if = "String::is_empty")]
    match_criteria_id: String,

    #[serde(rename = "versionStartExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    version_start_excluding: String,

    #[serde(rename = "versionEndIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    version_end_including: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CpeNodes {
    // must be "OR" or "AND"
    operator: String,
    // boolean value, must be "true" or "false"
    negate: bool,
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CpeApplicability {
    nodes: Vec<CpeNodes>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CnaData {
    #[serde(rename = "providerMetadata")]
    provider_metadata: ProviderMetadata,
    descriptions: Vec<Description>,
    affected: Vec<AffectedProduct>,
    #[serde(rename = "cpeApplicability")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cpe_applicability: Vec<CpeApplicability>,
    references: Vec<Reference>,
    title: String,
    #[serde(rename = "x_generator")]
    x_generator: Generator,
}

#[derive(Debug, Serialize, Deserialize)]
struct Containers {
    cna: CnaData,
}

#[derive(Debug, Serialize, Deserialize)]
struct CveRecord {
    containers: Containers,
    #[serde(rename = "cveMetadata")]
    cve_metadata: CveMetadata,
    #[serde(rename = "dataType")]
    data_type: String,
    #[serde(rename = "dataVersion")]
    data_version: String,
}

/// Generate a JSON record for the CVE
#[allow(clippy::too_many_arguments)]
fn generate_json_record(
    cve_number: &str,
    git_sha_full: &str,
    _git_sha_short: &str,
    commit_subject: &str,
    _user_name: &str,
    user_email: &str,
    mut dyad_entries: Vec<DyadEntry>,
    script_name: &str,
    script_version: &str,
    additional_references: &[String],
    commit_text: &str,
) -> Result<String> {
    // Get vulns directory using cve_utils
    let vulns_dir =
        cve_utils::find_vulns_dir().with_context(|| "Failed to find vulns directory")?;

    // Get the script directory from vulns directory
    let script_dir = vulns_dir.join("scripts");
    if !script_dir.exists() {
        return Err(anyhow::anyhow!(
            "Scripts directory not found at {}",
            script_dir.display()
        ));
    }

    // Read the UUID from the linux.uuid file
    let uuid = match read_uuid(&script_dir) {
        Ok(id) => id,
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to read UUID: {}", e));
        }
    };

    // Get the kernel tree path from environment
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;
    let repo = Repository::open(&kernel_tree)?;
    let git_ref = resolve_reference(&repo, git_sha_full)?;

    // Get affected files
    let affected_files = get_affected_files(&repo, &git_ref)?;

    // If no entries were created, use the fix commit as a fallback
    if dyad_entries.is_empty() {
        // Create a dummy entry using the fix commit
        if let Ok(entry) = DyadEntry::from_str(&format!("0:0:0:{}", git_sha_full)) {
            dyad_entries.push(entry);
        }
    }

    // Determine default status
    let default_status = determine_default_status(&dyad_entries);

    // Generate version ranges
    let kernel_versions = generate_version_ranges(&dyad_entries, default_status);
    let kernel_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: default_status.to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files.clone(),
        versions: kernel_versions,
    };

    // Generate git ranges
    let git_versions = generate_git_ranges(&dyad_entries);
    let git_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: "unaffected".to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files,
        versions: git_versions,
    };

    // Generate CPE ranges
    let cpe_nodes = generate_cpe_ranges(&dyad_entries);

    // Create references
    let mut references = Vec::new();
    let mut seen_refs: HashSet<String> = HashSet::new();

    // Add references for all entries
    for entry in dyad_entries {
        // Add fixed commit reference if available
        if !entry.fixed.is_empty() {
            let url = format!("https://git.kernel.org/stable/c/{}", entry.fixed.git_id());
            if !seen_refs.contains(&url) {
                seen_refs.insert(url.clone());
                references.push(Reference { url });
            }
        }
    }

    // Add any additional references from the reference file
    for url in additional_references {
        if !seen_refs.contains(url) {
            seen_refs.insert(url.clone());
            references.push(Reference { url: url.clone() });
        }
    }

    // If no references were found, add the main fix commit
    if references.is_empty() {
        let main_fix_url = format!("https://git.kernel.org/stable/c/{}", git_sha_full);
        references.push(Reference { url: main_fix_url });
    }

    // Use the provided commit_text, which might have been modified by the diff
    let description = commit_text;

    // Truncate description to 3982 characters (CVE backend limit) if needed
    let max_length = 3982; // CVE backend limit
    let truncated_description = if description.len() <= max_length {
        // If already under the limit, just ensure no trailing newline
        description.trim_end().to_string()
    } else {
        // Get the truncated text limited to max_length
        let truncated = &description[..max_length];

        // Special case: if only over by a trailing newline, just trim it
        if description.len() == max_length + 1 && description.ends_with('\n') {
            truncated.to_string()
        } else {
            // Add truncation marker, with proper newline handling
            let separator = if truncated.ends_with('\n') { "" } else { "\n" };
            format!("{}{}---truncated---", truncated, separator)
        }
    };

    // Create the structured CVE record using our defined types
    let cve_record = CveRecord {
        containers: Containers {
            cna: CnaData {
                provider_metadata: ProviderMetadata {
                    org_id: uuid.clone(),
                },
                descriptions: vec![Description {
                    lang: "en".to_string(),
                    value: truncated_description,
                }],
                affected: vec![git_product, kernel_product],
                //cpe_applicability: vec![], // FIXME
                cpe_applicability: vec![CpeApplicability { nodes: cpe_nodes }],
                references,
                title: commit_subject.to_string(),
                x_generator: Generator {
                    engine: format!("{}-{}", script_name, script_version),
                },
            },
        },
        cve_metadata: CveMetadata {
            assigner_org_id: uuid,
            cve_id: cve_number.to_string(),
            requester_user_id: user_email.to_string(),
            serial: "1".to_string(),
            state: "PUBLISHED".to_string(),
        },
        data_type: "CVE_RECORD".to_string(),
        data_version: "5.0".to_string(),
    };

    // Use a custom formatter with 3-space indentation
    let formatter = PrettyFormatter::with_indent(b"   ");
    let mut output = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut output, formatter);
    cve_record
        .serialize(&mut serializer)
        .map_err(|e| anyhow::anyhow!("Error serializing JSON: {}", e))?;

    let json_string = String::from_utf8(output)
        .map_err(|e| anyhow::anyhow!("Error converting JSON to string: {}", e))?;

    // Ensure the JSON output ends with a newline
    if !json_string.ends_with('\n') {
        Ok(json_string + "\n")
    } else {
        Ok(json_string)
    }
}

/// Generate an mbox file for the CVE
#[allow(clippy::too_many_arguments)]
fn generate_mbox(
    cve_number: &str,
    git_sha_full: &str,
    git_sha_short: &str,
    commit_subject: &str,
    user_name: &str,
    user_email: &str,
    dyad_entries: &Vec<DyadEntry>,
    script_name: &str,
    script_version: &str,
    additional_references: &[String],
    commit_text: &str,
) -> String {
    // For the From line we need the script name and version
    let from_line = format!(
        "From {}-{} Mon Sep 17 00:00:00 2001",
        script_name, script_version
    );

    // Parse dyad output to generate vulnerability information
    let mut vuln_array_mbox = Vec::new();
    let kernel_tree = match std::env::var("CVEKERNELTREE") {
        Ok(path) => path,
        Err(_) => {
            error!("CVEKERNELTREE environment variable is not set");
            return format!(
                "{}\n\
                From: {} <{}>\n\
                To: <linux-cve-announce@vger.kernel.org>\n\
                Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
                Subject: {}: {}\n\
                \n\
                Error: CVEKERNELTREE environment variable is not set",
                from_line, user_name, user_email, cve_number, commit_subject
            );
        }
    };

    let repo = match Repository::open(&kernel_tree) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to open kernel repo at {}: {}", kernel_tree, e);
            return format!(
                "{}\n\
                From: {} <{}>\n\
                To: <linux-cve-announce@vger.kernel.org>\n\
                Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
                Subject: {}: {}\n\
                \n\
                Error: Failed to open kernel repository",
                from_line, user_name, user_email, cve_number, commit_subject
            );
        }
    };

    // Parse the dyad output
    for entry in dyad_entries {
        // Handle unfixed vulnerabilities
        if entry.fixed.is_empty() {
            // Issue is not fixed, so say that:
            vuln_array_mbox.push(format!(
                "Issue introduced in {} with commit {}",
                entry.vulnerable.version(),
                entry.vulnerable.git_id()
            ));
            continue;
        }

        // Skip entries where the vulnerability is in the same version it was fixed
        if entry.vulnerable.version() == entry.fixed.version() {
            continue;
        }

        // Handle different types of entries
        if entry.vulnerable.is_empty() {
            // We do not know when it showed up, so just say it is fixed
            vuln_array_mbox.push(format!(
                "Fixed in {} with commit {}",
                entry.fixed.version(),
                entry.fixed.git_id()
            ));
        } else {
            // Report when it was introduced and when it was fixed
            vuln_array_mbox.push(format!(
                "Issue introduced in {} with commit {} and fixed in {} with commit {}",
                entry.vulnerable.version(),
                entry.vulnerable.git_id(),
                entry.fixed.version(),
                entry.fixed.git_id()
            ));
        }
    }

    // If no vulnerabilities were found, add a default entry
    if vuln_array_mbox.is_empty() {
        vuln_array_mbox.push(format!(
            "Issue fixed in mainline with commit {}",
            git_sha_short
        ));
    }

    // Get affected files from the commit
    let affected_files = match resolve_reference(&repo, git_sha_full) {
        Ok(obj) => get_affected_files(&repo, &obj).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // First add all fix commit URLs from dyad entries (except the main fix)
    let mut version_url_pairs = Vec::new();
    for entry in dyad_entries {
        if !entry.fixed.is_empty() && entry.fixed.git_id() != git_sha_full {
            let fix_url = format!("https://git.kernel.org/stable/c/{}", entry.fixed.git_id());
            if !version_url_pairs.iter().any(|(_, url)| url == &fix_url) {
                version_url_pairs.push((entry.fixed.version().clone(), fix_url));
            }
        }
    }

    // Sort the URLs by kernel version
    version_url_pairs.sort_by(|(ver_a, _), (ver_b, _)| {
        // Use the shared compare_kernel_versions function
        compare_kernel_versions(ver_a, ver_b)
    });

    // Build the URL array from the sorted pairs
    let mut url_array = version_url_pairs
        .into_iter()
        .map(|(_, url)| url)
        .collect::<Vec<_>>();

    // Add the main fix commit URL at the end
    url_array.push(format!("https://git.kernel.org/stable/c/{}", git_sha_full));

    // Add any additional references from the reference file
    for url in additional_references {
        if !url_array.contains(url) {
            url_array.push(url.clone());
        }
    }

    // Format the vulnerability summary section
    let mut vuln_section = String::new();
    for line in vuln_array_mbox {
        vuln_section.push_str(&format!("\t{}\n", line));
    }

    // Format the affected files section
    let mut files_section = String::new();
    for file in affected_files {
        files_section.push_str(&format!("\t{}\n", file));
    }

    // Format the mitigation section with URLs
    let mut url_section = String::new();
    for url in url_array {
        url_section.push_str(&format!("\t{}\n", url));
    }

    // Use the provided commit_text, which might have been modified by the diff
    let commit_message = commit_text;

    // The full formatted mbox content
    let result = format!(
        "{}\n\
         From: {} <{}>\n\
         To: <linux-cve-announce@vger.kernel.org>\n\
         Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
         Subject: {}: {}\n\
         \n\
         Description\n\
         ===========\n\
         \n\
         {}\n\
         \n\
         The Linux kernel CVE team has assigned {} to this issue.\n\
         \n\
         \n\
         Affected and fixed versions\n\
         ===========================\n\
         \n\
         {}\n\
         Please see https://www.kernel.org for a full list of currently supported\n\
         kernel versions by the kernel community.\n\
         \n\
         Unaffected versions might change over time as fixes are backported to\n\
         older supported kernel versions.  The official CVE entry at\n\
         \thttps://cve.org/CVERecord/?id={}\n\
         will be updated if fixes are backported, please check that for the most\n\
         up to date information about this issue.\n\
         \n\
         \n\
         Affected files\n\
         ==============\n\
         \n\
         The file(s) affected by this issue are:\n\
         {}\n\
         \n\
         Mitigation\n\
         ==========\n\
         \n\
         The Linux kernel CVE team recommends that you update to the latest\n\
         stable kernel version for this, and many other bugfixes.  Individual\n\
         changes are never tested alone, but rather are part of a larger kernel\n\
         release.  Cherry-picking individual commits is not recommended or\n\
         supported by the Linux kernel community at all.  If however, updating to\n\
         the latest release is impossible, the individual changes to resolve this\n\
         issue can be found at these commits:\n\
         {}",
        from_line,
        user_name,
        user_email,
        cve_number,
        commit_subject,
        commit_message.trim_end(), // Trim any trailing newlines
        cve_number,
        vuln_section,
        cve_number,
        files_section,
        url_section
    );

    // Ensure the result ends with a newline
    if !result.ends_with('\n') {
        result + "\n"
    } else {
        result
    }
}

/// Main function
fn main() -> Result<()> {
    let mut logging_level: log::LevelFilter = log::LevelFilter::Error;

    // Parse command line arguments
    let args = Args::parse();

    // Set the logging level based on the command line option and turn on the logger
    if args.verbose {
        logging_level = log::LevelFilter::max();
    }
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    // Debug all raw command line arguments if verbose is enabled
    if std::env::args().len() > 0 {
        debug!("Raw command line arguments:");
        for (i, arg) in std::env::args().enumerate() {
            debug!("  Arg[{}]: '{}'", i, arg);
        }
    }

    // Debug trailing args in verbose mode
    if !args.trailing_args.is_empty() {
        debug!("Trailing arguments detected:");
        for (i, arg) in args.trailing_args.iter().enumerate() {
            debug!("  trailing_arg[{}]: '{}'", i, arg);
        }
    }

    // Check if one of the trailing args might be a reference file path
    let reference_from_trailing = args
        .trailing_args
        .iter()
        .find(|arg| arg.contains(".reference"))
        .map(|s| s.to_string());

    // Also look for reference file in any position in the command line
    let reference_from_raw_args = find_reference_in_args();

    if reference_from_trailing.is_some() {
        debug!(
            "Found potential reference file in trailing args: '{}'",
            reference_from_trailing.as_ref().unwrap()
        );
    }

    if reference_from_raw_args.is_some() {
        debug!(
            "Found potential reference file in raw args: '{}'",
            reference_from_raw_args.as_ref().unwrap()
        );
    }

    // Check for required arguments
    if args.cve.is_none() || args.sha.is_empty() || (args.json.is_none() && args.mbox.is_none()) {
        error!("Missing required arguments: cve, sha, or one of json/mbox");
        std::process::exit(1);
    }

    // Check for CVE_USER environment variable if user is not specified
    let user_email = match args.user {
        Some(ref email) => email.clone(),
        None => match env::var("CVE_USER") {
            Ok(val) => val,
            Err(_) => {
                error!("Missing required argument: user (-u/--user) and CVE_USER environment variable is not set");
                std::process::exit(1);
            }
        },
    };

    // Check for CVEKERNELTREE environment variable
    if env::var("CVEKERNELTREE").is_err() {
        error!("CVEKERNELTREE environment variable is not set");
        error!("It needs to be set to the stable repo directory");
        std::process::exit(1);
    }

    // Extract values from args
    let cve_number = args.cve.as_ref().unwrap();
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
    let user_name = match args.name {
        Some(ref name) => name.clone(),
        None => match git_config::get_git_config("user.name") {
            Ok(val) => val,
            Err(_) => "".to_string(),
        },
    };

    // Debug output if verbose is enabled
    debug!("CVE_NUMBER={}", cve_number);
    debug!("GIT_SHAS={:?}", git_shas);
    debug!("JSON_FILE={:?}", args.json);
    debug!("MBOX_FILE={:?}", args.mbox);
    debug!("DIFF_FILE={:?}", args.diff);
    debug!("REFERENCE_FILE={:?}", args.reference);
    debug!("REF_FROM_TRAILING={:?}", reference_from_trailing);
    debug!("REF_FROM_RAW_ARGS={:?}", reference_from_raw_args);
    debug!("GIT_VULNERABLE={:?}", vulnerable_shas);

    // Get vulns directory using cve_utils
    let vulns_dir =
        cve_utils::find_vulns_dir().with_context(|| "Failed to find vulns directory")?;

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

    // Open the kernel repository
    let repo = Repository::open(&kernel_tree)
        .with_context(|| format!("Failed to open Git repository at {:?}", kernel_tree))?;

    // Resolve Git references for all main commits
    let git_refs: Vec<_> = git_shas
        .iter()
        .filter_map(|sha| match resolve_reference(&repo, sha) {
            Ok(reference) => Some(reference),
            Err(err) => {
                warn!("Warning: Could not resolve SHA reference: {}", err);
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
    let git_sha_full =
        get_object_full_sha(&repo, main_git_ref).with_context(|| "Failed to get full SHA")?;
    let git_sha_short =
        get_short_sha(&repo, main_git_ref).with_context(|| "Failed to get short SHA")?;
    let commit_subject =
        get_commit_subject(&repo, main_git_ref).with_context(|| "Failed to get commit subject")?;

    // Get the full commit message text for the main commit
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;
    let repo = Repository::open(&kernel_tree)?;
    let git_ref = resolve_reference(&repo, &git_sha_full)?;
    let mut commit_text = get_commit_text(&repo, &git_ref)?;

    // Read the tags file to strip from commit message
    let vulns_dir =
        cve_utils::find_vulns_dir().with_context(|| "Failed to find vulns directory")?;
    let script_dir = vulns_dir.join("scripts");
    let tags = read_tags_file(&script_dir).unwrap_or_default();

    // Strip tags from commit text
    commit_text = strip_commit_text(&commit_text, &tags).unwrap_or_else(|_| {
        format!(
            "In the Linux kernel, the following vulnerability has been resolved:\n\n{}",
            commit_text
        )
    });

    // Apply diff file to the commit text if provided
    if let Some(diff_path) = args.diff.as_ref() {
        match apply_diff_to_text(&commit_text, diff_path) {
            Ok(modified_text) => {
                debug!(
                    "Applied diff from {} to the commit text",
                    diff_path.display()
                );
                // The apply_diff_to_text function handles newline preservation
                commit_text = modified_text;
            }
            Err(err) => {
                error!("Warning: Failed to apply diff to commit text: {}", err);
            }
        }
    }

    // Run dyad with all main SHAs and all vulnerable SHAs
    let dyad_data = match run_dyad(&script_dir, &git_shas, &vulnerable_shas) {
        Ok(data) => data,
        Err(err) => {
            warn!("Warning: Failed to run dyad: {:?}", err);
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

    // First check for the reference file explicitly specified with --reference
    let mut reference_path: Option<PathBuf> = args.reference.clone();

    // If not found, look in trailing arguments
    if reference_path.is_none() && reference_from_trailing.is_some() {
        // Extract just the path part from the argument
        let arg = reference_from_trailing.unwrap();
        let path = extract_path_from_arg(&arg);
        debug!("Extracted path from trailing arg: '{}'", path);
        reference_path = Some(PathBuf::from(path));
    }

    // If still not found, look in raw command line arguments
    if reference_path.is_none() && reference_from_raw_args.is_some() {
        reference_path = Some(PathBuf::from(reference_from_raw_args.unwrap()));
    }

    let additional_references: Vec<String> = if let Some(ref_path) = reference_path {
        debug!("Attempting to read references from {:?}", ref_path);

        if let Ok(contents) = std::fs::read_to_string(&ref_path) {
            debug!("Successfully read reference file");
            if !contents.is_empty() {
                debug!("Reference file contains {} lines", contents.lines().count());
                for (i, line) in contents.lines().enumerate() {
                    if !line.trim().is_empty() {
                        debug!("  Reference[{}]: {}", i, line.trim());
                    }
                }
            } else {
                debug!("Reference file is empty");
            }

            contents
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        } else {
            warn!("Warning: Failed to read reference file from {:?}", ref_path);
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
    };

    // Generate JSON file if requested
    if let Some(json_path) = args.json.as_ref() {
        match generate_json_record(
            cve_number,
            &git_sha_full,
            &git_sha_short,
            &commit_subject,
            &user_name,
            &user_email,
            dyad_entries.clone(),
            &script_name,
            &script_version,
            &additional_references,
            &commit_text,
        ) {
            Ok(json_record) => {
                if let Err(err) = std::fs::write(json_path, json_record) {
                    error!(
                        "Warning: Failed to write JSON file to {:?}: {}",
                        json_path, err
                    );
                } else {
                    debug!("Wrote JSON file to {}", json_path.display());
                }
            }
            Err(err) => {
                error!("Error: Failed to generate JSON record: {}", err);
            }
        }
    }

    // Generate mbox file if requested
    if let Some(mbox_path) = args.mbox.as_ref() {
        let mbox_content = generate_mbox(
            cve_number,
            &git_sha_full,
            &git_sha_short,
            &commit_subject,
            &user_name,
            &user_email,
            &dyad_entries,
            &script_name,
            &script_version,
            &additional_references,
            &commit_text,
        );

        if let Err(err) = std::fs::write(mbox_path, mbox_content) {
            error!(
                "Warning: Failed to write mbox file to {:?}: {}",
                mbox_path, err
            );
        } else {
            debug!("Wrote mbox file to {}", mbox_path.display());
        }
    }

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

        let result = strip_commit_text(commit_text, &tags).unwrap();
        assert_eq!(result, expected);

        // Test with empty tags
        let empty_tags: Vec<String> = Vec::new();
        let result = strip_commit_text(commit_text, &empty_tags).unwrap();
        assert_eq!(result, "In the Linux kernel, the following vulnerability has been resolved:\n\nSubject: Fix a bug\n\nThis commit fixes a bug in the kernel.\n\nSigned-off-by: Bob <bob@example.com>\nAcked-by: Alice <alice@example.com>\n");

        // Test with multi-paragraph commit
        let multi_para_commit = "Subject: Complex fix\n\nParagraph 1 with details.\n\nParagraph 2 with more details.\n\nSigned-off-by: Bob <bob@example.com>\n";
        let expected_multi = "In the Linux kernel, the following vulnerability has been resolved:\n\nSubject: Complex fix\n\nParagraph 1 with details.\n\nParagraph 2 with more details.\n";
        let result = strip_commit_text(multi_para_commit, &tags).unwrap();
        assert_eq!(result, expected_multi);
    }

    #[test]
    fn test_determine_default_status() {
        // Test with vulnerable_version = 0
        let entries =
            vec![DyadEntry::from_str("0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap()];
        assert_eq!(determine_default_status(&entries), "affected");

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
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with mainline version that's both vulnerable and fixed in the same version
        // This should be "unaffected" because no actually released version was affected
        let entries = vec![
            DyadEntry::from_str("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");

        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            DyadEntry::from_str("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da").unwrap(),
            DyadEntry::from_str("0:0:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with multiple entries, mix of same-version fixes and different-version fixes
        let entries = vec![
            DyadEntry::from_str("5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a").unwrap(),
            DyadEntry::from_str("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_generate_version_ranges() {
        // Test with a single entry for a stable kernel
        let entries = vec![
            DyadEntry::from_str("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap(),
        ];

        let kernel_versions = generate_version_ranges(&entries, "unaffected");
        let git_versions = generate_git_ranges(&entries);

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

        let kernel_versions = generate_version_ranges(&entries, "affected");
        let git_versions = generate_git_ranges(&entries);

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

        let kernel_versions = generate_version_ranges(&entries, "unaffected");
        let git_versions = generate_git_ranges(&entries);

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
            version.chars().all(|c| c.is_digit(10) || c == '.'),
            "Version should only contain digits and dots"
        );
    }
}

// Helper function to extract file path from an argument string
fn extract_path_from_arg(arg: &str) -> String {
    if arg.starts_with("--reference=") {
        // Extract the part after --reference=
        arg.trim_start_matches("--reference=").to_string()
    } else if arg.contains('=') {
        // Extract the part after the =
        let parts: Vec<&str> = arg.split('=').collect();
        if parts.len() >= 2 {
            parts[1].to_string()
        } else {
            arg.to_string()
        }
    } else {
        arg.to_string()
    }
}

// Helper function to find a reference file path in command line arguments
fn find_reference_in_args() -> Option<String> {
    for arg in std::env::args() {
        // Look for argument of the form '--reference=path/to/file.reference'
        if arg.starts_with("--reference=") && arg.contains(".reference") {
            return Some(extract_path_from_arg(&arg));
        }
        // Look for argument of the form 'something=path/to/file.reference'
        else if arg.contains("=") && arg.contains(".reference") {
            let parts: Vec<&str> = arg.split('=').collect();
            if parts.len() == 2 && parts[1].contains(".reference") {
                return Some(parts[1].to_string());
            }
        }
        // Look for standalone '.reference' arguments
        else if arg.contains(".reference") {
            return Some(arg);
        }
    }
    None
}
