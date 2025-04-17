// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use std::path::{Path, PathBuf};
use git2::{Repository, Object};
use clap::Parser;
use anyhow::{Context, Result};
use thiserror::Error;
use std::env;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use cve_utils::version_utils::version_is_mainline;
use cve_utils::git_utils::{resolve_reference, get_object_full_sha, get_short_sha, get_affected_files};
use cve_utils::git_config;
use serde_json::ser::{PrettyFormatter, Serializer};

/// Error types for the bippy tool
#[derive(Error, Debug)]
enum BippyError {
    /// Error when parsing a dyad entry
    #[error("Invalid dyad entry: {0}")]
    InvalidDyadEntry(String),

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
    vulnerable_version: String,
    vulnerable_git: String,
    fixed_version: String,
    fixed_git: String,
}

impl DyadEntry {
    /// Create a new DyadEntry from a colon-separated string
    fn from_str(s: &str) -> Result<Self, BippyError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(BippyError::InvalidDyadEntry(s.to_string()));
        }

        Ok(DyadEntry {
            vulnerable_version: parts[0].to_string(),
            vulnerable_git: parts[1].to_string(),
            fixed_version: parts[2].to_string(),
            fixed_git: parts[3].to_string(),
        })
    }

    /// Getter for the vulnerable_git field
    fn vulnerable_git(&self) -> &str {
        &self.vulnerable_git
    }

    /// Getter for the fixed_git field
    fn fixed_git(&self) -> &str {
        &self.fixed_git
    }

    /// Check if this vulnerability has been fixed
    #[cfg(test)]
    fn is_fixed(&self) -> bool {
        self.fixed_version != "0" && self.fixed_git() != "0"
    }

    /// Check if vulnerability spans across different kernel versions
    #[cfg(test)]
    fn is_cross_version(&self) -> bool {
        self.vulnerable_version != "0" && self.fixed_version != "0" &&
        self.vulnerable_version != self.fixed_version
    }
}

/// Strip commit text to only keep the relevant parts
/// Removes Signed-off-by and other tags from the commit message
fn strip_commit_text(text: &str, tags: &[String]) -> Result<String> {
    let mut result = String::from("In the Linux kernel, the following vulnerability has been resolved:\n\n");

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
            trimmed.to_lowercase().starts_with(&tag_with_colon.to_lowercase())
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
    if entries.iter().any(|entry| entry.vulnerable_version == "0") {
        return "affected";
    }

    // If any entry has a mainline vulnerable version AND it's not fixed in the same version,
    // status should be "affected"
    if entries.iter().any(|entry|
        version_is_mainline(&entry.vulnerable_version) &&
        entry.vulnerable_version != entry.fixed_version
    ) {
        return "affected";
    }

    // Otherwise status should be "unaffected"
    "unaffected"
}

/// Generate version ranges for the CVE JSON format
fn generate_version_ranges(entries: &[DyadEntry], default_status: &str) -> (Vec<VersionRange>, Vec<VersionRange>) {
    let mut kernel_versions = Vec::new();
    let mut git_versions = Vec::new();
    let mut seen_versions = HashSet::new();

    for entry in entries {
        // Handle git version ranges
        if entry.fixed_git() != "0" {
            // For git version ranges, determine the vulnerable git ID
            // If vulnerable_version is 0, use the first Linux commit ID
            let vulnerable_git = if entry.vulnerable_version == "0" || entry.vulnerable_git() == "0" {
                "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2".to_string() // First Linux commit ID
            } else {
                entry.vulnerable_git().to_string()
            };

            // Create a version range for Git
            let ver_range = VersionRange {
                version: vulnerable_git,
                less_than: Some(entry.fixed_git().to_string()),
                less_than_or_equal: None,
                status: "affected".to_string(),
                version_type: Some("git".to_string()),
            };

            // Create a unique key that represents the entire range
            let key = format!("git:{}:{}:{}",
                ver_range.version,
                ver_range.less_than.as_deref().unwrap_or(""),
                ver_range.less_than_or_equal.as_deref().unwrap_or(""));

            // Only add if we haven't seen this exact range before
            if !seen_versions.contains(&key) {
                seen_versions.insert(key);
                git_versions.push(ver_range);
            }
        }

        // Skip entries where the vulnerability is in the same version it was fixed
        if entry.vulnerable_version == entry.fixed_version {
            continue;
        }

        // Handle kernel version ranges
        if default_status == "affected" {
            if entry.vulnerable_version != "0" && version_is_mainline(&entry.vulnerable_version) {
                let ver_key = format!("kernel:affected:{}:::", entry.vulnerable_version);
                if !seen_versions.contains(&ver_key) {
                    seen_versions.insert(ver_key);

                    // Add the mainline affected version
                    kernel_versions.push(VersionRange {
                        version: entry.vulnerable_version.clone(),
                        less_than: None,
                        less_than_or_equal: None,
                        status: "affected".to_string(),
                        version_type: None,
                    });

                    // Add versions before affected as unaffected
                    let unaffected_key = format!("kernel:unaffected:0:{}:", entry.vulnerable_version);
                    if !seen_versions.contains(&unaffected_key) {
                        seen_versions.insert(unaffected_key);
                        kernel_versions.push(VersionRange {
                            version: "0".to_string(),
                            less_than: Some(entry.vulnerable_version.clone()),
                            less_than_or_equal: None,
                            status: "unaffected".to_string(),
                            version_type: Some("semver".to_string()),
                        });
                    }
                }
            }

            // Add fixed versions as unaffected
            if entry.fixed_version != "0" {
                // For stable kernels, determine the wildcard pattern
                let version_parts: Vec<&str> = entry.fixed_version.split('.').collect();
                let wildcard = if version_parts.len() >= 2 {
                    format!("{}.{}.*", version_parts[0], version_parts[1])
                } else {
                    entry.fixed_version.clone() + ".*"
                };

                // Create a unique key for this version
                let key = format!("kernel:unaffected:{}::{}",
                    entry.fixed_version,
                    wildcard);

                if !seen_versions.contains(&key) {
                    seen_versions.insert(key.clone());

                    // Add fixed version as unaffected
                    if !version_is_mainline(&entry.fixed_version) {
                        // For stable kernels with a patch version (e.g., 5.10.234)
                        kernel_versions.push(VersionRange {
                            version: entry.fixed_version.clone(),
                            less_than: None,
                            less_than_or_equal: Some(wildcard),
                            status: "unaffected".to_string(),
                            version_type: Some("semver".to_string()),
                        });
                    } else {
                        // For mainline versions
                        kernel_versions.push(VersionRange {
                            version: entry.fixed_version.clone(),
                            less_than: None,
                            less_than_or_equal: Some("*".to_string()),
                            status: "unaffected".to_string(),
                            version_type: Some("original_commit_for_fix".to_string()),
                        });
                    }
                }
            }
        } else {
            // For unaffected default status, add affected ranges
            if entry.vulnerable_version != "0" && entry.fixed_version != "0" {
                let ver_range = VersionRange {
                    version: entry.vulnerable_version.clone(),
                    less_than: Some(entry.fixed_version.clone()),
                    less_than_or_equal: None,
                    status: "affected".to_string(),
                    version_type: Some("semver".to_string()),
                };

                let key = format!("kernel:affected:{}:{}:",
                    ver_range.version,
                    ver_range.less_than.as_deref().unwrap_or(""));

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

        // Compare versions numerically
        // First try to parse as kernel versions (x.y.z)
        let a_parts: Vec<&str> = a.version.split('.').collect();
        let b_parts: Vec<&str> = b.version.split('.').collect();

        // Compare major versions first
        if let (Ok(a_major), Ok(b_major)) = (a_parts.first().unwrap_or(&"0").parse::<u32>(),
                                            b_parts.first().unwrap_or(&"0").parse::<u32>()) {
            if a_major != b_major {
                return a_major.cmp(&b_major);
            }

            // Compare minor versions next
            if let (Ok(a_minor), Ok(b_minor)) = (a_parts.get(1).unwrap_or(&"0").parse::<u32>(),
                                                b_parts.get(1).unwrap_or(&"0").parse::<u32>()) {
                if a_minor != b_minor {
                    return a_minor.cmp(&b_minor);
                }

                // Compare patch level if present
                if let (Ok(a_patch), Ok(b_patch)) = (a_parts.get(2).unwrap_or(&"0").parse::<u32>(),
                                                    b_parts.get(2).unwrap_or(&"0").parse::<u32>()) {
                    return a_patch.cmp(&b_patch);
                }
            }
        }

        // Fallback to string comparison if parsing failed
        a.version.cmp(&b.version)
    });

    // Remove Git versions sorting to preserve the original order from dyad (matching bash script behavior)
    // git_versions.sort_by(|a, b| {
    //     if a.status != b.status {
    //         return a.status.cmp(&b.status);
    //     }
    //     a.version.cmp(&b.version)
    // });

    (kernel_versions, git_versions)
}

/// Reads the tags file from the script directory
fn read_tags_file(script_dir: &Path) -> Result<Vec<String>> {
    let tags_path = script_dir.join("tags");
    let content = std::fs::read_to_string(&tags_path)
        .with_context(|| format!("Failed to read tags file at {:?}", tags_path))?;

    Ok(content.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))  // Added filter for comments
        .collect())
}

/// Read the UUID for the Linux kernel CVE team from a file
fn read_uuid(script_dir: &Path) -> Result<String> {
    let uuid_path = script_dir.join("linux.uuid");
    let content = std::fs::read_to_string(&uuid_path)
        .with_context(|| format!("Failed to read UUID file at {:?}", uuid_path))?;

    let uuid = content.trim();
    if uuid.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UUID file is empty"
        ).into());
    }

    Ok(uuid.to_string())
}

/// Run the dyad script to get version range information
fn run_dyad(script_dir: &Path, git_sha: &str, vulnerable_sha: Option<&str>, verbose: bool) -> Result<String> {
    // Ensure dyad script exists
    let dyad_script = script_dir.join("dyad");
    if !dyad_script.exists() {
        return Err(anyhow::anyhow!("Dyad script not found at {}", dyad_script.display()));
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

    // Add vulnerable SHA if provided
    if let Some(vuln_sha) = vulnerable_sha {
        if !vuln_sha.is_empty() {
            // Split the vulnerable SHA string and add each as a separate -v argument
            for single_sha in vuln_sha.split_whitespace() {
                command.arg("-v").arg(single_sha);

                // Only print vulnerable SHA information if verbose is enabled
                if verbose {
                    if let Ok(repo) = Repository::open(&kernel_tree) {
                        if let Ok(obj) = resolve_reference(&repo, single_sha) {
                            if let Ok(short_sha) = get_short_sha(&repo, &obj) {
                                println!("Using vulnerable SHA: {}", short_sha);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add the Git SHA
    command.arg(git_sha);

    // Only print the command when verbose mode is enabled
    if verbose {
        println!("Running command: {:?}", command);
    }

    // Execute the command
    let output = command.output()
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

    /// Git SHA of the commit
    #[clap(short, long)]
    sha: Option<String>,

    /// Git SHA of the vulnerable commit (optional)
    #[clap(short = 'V', long)]
    vulnerable: Option<String>,

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
    let commit = obj.as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    Ok(commit.summary().unwrap_or("").to_string())
}

/// Get the full commit message text
fn get_commit_text(_repo: &Repository, obj: &Object) -> Result<String> {
    let commit = obj.as_commit()
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
        .with_context(|| format!("Failed to execute patch command with diff file {:?}", diff_file))?;

    if !status.success() {
        return Err(anyhow::anyhow!("Patch command failed with status: {}", status));
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

#[derive(Debug, Serialize, Deserialize)]
struct VersionRange {
    version: String,
    #[serde(rename = "lessThan", skip_serializing_if = "Option::is_none")]
    less_than: Option<String>,
    #[serde(rename = "lessThanOrEqual", skip_serializing_if = "Option::is_none")]
    less_than_or_equal: Option<String>,
    status: String,
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

#[derive(Debug, Serialize, Deserialize)]
struct CpeMatch {
    vulnerable: String,
    // critera is always going to be: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    criteria: String,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: String,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CpeNodes {
    operator: String,
    negate: String,
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
    dyad_data: &str,
    script_name: &str,
    script_version: &str,
    additional_references: &[String],
    commit_text: &str,
) -> Result<String> {
    // Get vulns directory using cve_utils
    let vulns_dir = cve_utils::find_vulns_dir()
        .with_context(|| "Failed to find vulns directory")?;

    // Get the script directory from vulns directory
    let script_dir = vulns_dir.join("scripts");
    if !script_dir.exists() {
        return Err(anyhow::anyhow!("Scripts directory not found at {}", script_dir.display()));
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

    // Parse dyad output into DyadEntry objects
    let mut dyad_entries = Vec::new();

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
    let (kernel_versions, git_versions) = generate_version_ranges(&dyad_entries, default_status);

    // Create affected products
    let git_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: "unaffected".to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files.clone(),
        versions: git_versions,
    };

    let kernel_product = AffectedProduct {
        product: "Linux".to_string(),
        vendor: "Linux".to_string(),
        default_status: default_status.to_string(),
        repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git".to_string(),
        program_files: affected_files,
        versions: kernel_versions,
    };

    // Create references
    let mut references = Vec::new();
    let mut seen_refs: HashSet<String> = HashSet::new();

    // Add references for all entries
    for entry in &dyad_entries {
        // Add fixed commit reference if available
        if entry.fixed_git() != "0" {
            let url = format!("https://git.kernel.org/stable/c/{}", entry.fixed_git());
            if !seen_refs.contains(&url) {
                seen_refs.insert(url.clone());
                references.push(Reference {
                    url,
                });
            }
        }
    }

    // Add any additional references from the reference file
    for url in additional_references {
        if !seen_refs.contains(url) {
            seen_refs.insert(url.clone());
            references.push(Reference {
                url: url.clone(),
            });
        }
    }

    // If no references were found, add the main fix commit
    if references.is_empty() {
        let main_fix_url = format!("https://git.kernel.org/stable/c/{}", git_sha_full);
        references.push(Reference {
            url: main_fix_url,
        });
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
                cpe_applicability: vec![],  // FIXME
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
    cve_record.serialize(&mut serializer)
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
    dyad_data: &str,
    script_name: &str,
    script_version: &str,
    additional_references: &[String],
    commit_text: &str,
) -> String {
    // For the From line we need the script name and version
    let from_line = format!("From {}-{} Mon Sep 17 00:00:00 2001", script_name, script_version);

    // Parse dyad output to generate vulnerability information
    let mut vuln_array_mbox = Vec::new();
    let kernel_tree = match std::env::var("CVEKERNELTREE") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("CVEKERNELTREE environment variable is not set");
            return format!(
                "{}\n\
                From: {} <{}>\n\
                To: <linux-cve-announce@vger.kernel.org>\n\
                Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
                Subject: {}: {}\n\
                \n\
                Error: CVEKERNELTREE environment variable is not set",
                from_line,
                user_name, user_email,
                cve_number, commit_subject
            );
        }
    };

    let repo = match Repository::open(&kernel_tree) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to open kernel repo at {}: {}", kernel_tree, e);
            return format!(
                "{}\n\
                From: {} <{}>\n\
                To: <linux-cve-announce@vger.kernel.org>\n\
                Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>\n\
                Subject: {}: {}\n\
                \n\
                Error: Failed to open kernel repository",
                from_line,
                user_name, user_email,
                cve_number, commit_subject
            );
        }
    };

    // Parse the dyad output
    for line in dyad_data.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        // Try to parse the line as a DyadEntry
        if let Ok(entry) = DyadEntry::from_str(line) {
            // Handle unfixed vulnerabilities
            if entry.fixed_version == "0" {
                // Issue is not fixed, so say that:
                vuln_array_mbox.push(format!(
                    "Issue introduced in {} with commit {}",
                    entry.vulnerable_version,
                    entry.vulnerable_git()
                ));
                continue;
            }

            // Skip entries where the vulnerability is in the same version it was fixed
            if entry.vulnerable_version == entry.fixed_version {
                continue;
            }

            // Handle different types of entries
            if entry.vulnerable_version == "0" {
                // We do not know when it showed up, so just say it is fixed
                vuln_array_mbox.push(format!(
                    "Fixed in {} with commit {}",
                    entry.fixed_version,
                    entry.fixed_git()
                ));
            } else {
                // Report when it was introduced and when it was fixed
                vuln_array_mbox.push(format!(
                    "Issue introduced in {} with commit {} and fixed in {} with commit {}",
                    entry.vulnerable_version,
                    entry.vulnerable_git(),
                    entry.fixed_version,
                    entry.fixed_git()
                ));
            }
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
    for line in dyad_data.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if let Ok(entry) = DyadEntry::from_str(line) {
            if entry.fixed_version != "0" && entry.fixed_git() != "0" && entry.fixed_git() != git_sha_full {
                let fix_url = format!("https://git.kernel.org/stable/c/{}", entry.fixed_git());
                if !version_url_pairs.iter().any(|(_, url)| url == &fix_url) {
                    version_url_pairs.push((entry.fixed_version.clone(), fix_url));
                }
            }
        }
    }

    // Sort the URLs by kernel version
    version_url_pairs.sort_by(|(ver_a, _), (ver_b, _)| {
        // Compare versions numerically
        let a_parts: Vec<&str> = ver_a.split('.').collect();
        let b_parts: Vec<&str> = ver_b.split('.').collect();

        // Compare major versions first
        if let (Ok(a_major), Ok(b_major)) = (a_parts.first().unwrap_or(&"0").parse::<u32>(),
                                            b_parts.first().unwrap_or(&"0").parse::<u32>()) {
            if a_major != b_major {
                return a_major.cmp(&b_major);
            }

            // Compare minor versions next
            if let (Ok(a_minor), Ok(b_minor)) = (a_parts.get(1).unwrap_or(&"0").parse::<u32>(),
                                                b_parts.get(1).unwrap_or(&"0").parse::<u32>()) {
                if a_minor != b_minor {
                    return a_minor.cmp(&b_minor);
                }

                // Compare patch level if present
                if let (Ok(a_patch), Ok(b_patch)) = (a_parts.get(2).unwrap_or(&"0").parse::<u32>(),
                                                    b_parts.get(2).unwrap_or(&"0").parse::<u32>()) {
                    return a_patch.cmp(&b_patch);
                }
            }
        }

        // Fallback to string comparison if parsing failed
        ver_a.cmp(ver_b)
    });

    // Build the URL array from the sorted pairs
    let mut url_array = version_url_pairs.into_iter().map(|(_, url)| url).collect::<Vec<_>>();

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
        user_name, user_email,
        cve_number, commit_subject,
        commit_message.trim_end(),  // Trim any trailing newlines
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
    // Parse command line arguments
    let args = Args::parse();

    // Debug all raw command line arguments if verbose is enabled
    if args.verbose && std::env::args().len() > 0 {
        eprintln!("Raw command line arguments:");
        for (i, arg) in std::env::args().enumerate() {
            eprintln!("  Arg[{}]: '{}'", i, arg);
        }
    }

    // Debug trailing args in verbose mode
    if args.verbose && !args.trailing_args.is_empty() {
        eprintln!("Trailing arguments detected:");
        for (i, arg) in args.trailing_args.iter().enumerate() {
            eprintln!("  trailing_arg[{}]: '{}'", i, arg);
        }
    }

    // Check if one of the trailing args might be a reference file path
    let reference_from_trailing = args.trailing_args.iter()
        .find(|arg| arg.contains(".reference"))
        .map(|s| s.to_string());

    // Also look for reference file in any position in the command line
    let reference_from_raw_args = find_reference_in_args();

    if args.verbose && reference_from_trailing.is_some() {
        eprintln!("Found potential reference file in trailing args: '{}'",
            reference_from_trailing.as_ref().unwrap());
    }

    if args.verbose && reference_from_raw_args.is_some() {
        eprintln!("Found potential reference file in raw args: '{}'",
            reference_from_raw_args.as_ref().unwrap());
    }

    // Check for required arguments
    if args.cve.is_none() || args.sha.is_none() || (args.json.is_none() && args.mbox.is_none()) {
        eprintln!("Missing required arguments: cve, sha, or one of json/mbox");
        std::process::exit(1);
    }

    // Check for CVE_USER environment variable if user is not specified
    let user_email = match args.user {
        Some(ref email) => email.clone(),
        None => {
            match env::var("CVE_USER") {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Missing required argument: user (-u/--user) and CVE_USER environment variable is not set");
                    std::process::exit(1);
                }
            }
        }
    };

    // Check for CVEKERNELTREE environment variable
    if env::var("CVEKERNELTREE").is_err() {
        eprintln!("CVEKERNELTREE environment variable is not set");
        eprintln!("It needs to be set to the stable repo directory");
        std::process::exit(1);
    }

    // Extract values from args
    let cve_number = args.cve.as_ref().unwrap();
    let git_sha = args.sha.as_ref().unwrap();

    // Treat empty string vulnerable values as None
    let vulnerable_sha = match args.vulnerable.as_deref() {
        Some("") => None,
        other => other,
    };

    // Dig into git if the user name is not set
    let user_name = match args.name {
        Some(ref name) => name.clone(),
        None => {
            match git_config::get_git_config("user.name") {
                Ok(val) => val,
                Err(_) => "".to_string(),
            }
        }
    };

    // Debug output if verbose is enabled
    if args.verbose {
        println!("CVE_NUMBER={}", cve_number);
        println!("GIT_SHA={}", git_sha);
        println!("JSON_FILE={:?}", args.json);
        println!("MBOX_FILE={:?}", args.mbox);
        println!("DIFF_FILE={:?}", args.diff);
        println!("REFERENCE_FILE={:?}", args.reference);
        println!("REF_FROM_TRAILING={:?}", reference_from_trailing);
        println!("REF_FROM_RAW_ARGS={:?}", reference_from_raw_args);
        println!("GIT_VULNERABLE={:?}", vulnerable_sha);
    }

    // Get vulns directory using cve_utils
    let vulns_dir = cve_utils::find_vulns_dir()
        .with_context(|| "Failed to find vulns directory")?;

    // Get scripts directory
    let script_dir = vulns_dir.join("scripts");
    if !script_dir.exists() {
        return Err(anyhow::anyhow!("Scripts directory not found at {}", script_dir.display()));
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

    // Resolve Git references
    let git_ref = resolve_reference(&repo, git_sha.as_str())
        .with_context(|| format!("Failed to resolve Git reference: {}", git_sha))?;

    // Get vulnerable SHA reference if provided
    let _vulnerable_ref = match vulnerable_sha {
        Some(sha) => {
            match resolve_reference(&repo, sha) {
                Ok(reference) => Some(reference),
                Err(err) => {
                    eprintln!("Warning: Could not resolve vulnerable SHA reference: {}", err);
                    None
                }
            }
        },
        None => None,
    };

    // Get SHA information
    let git_sha_full = get_object_full_sha(&repo, &git_ref)
        .with_context(|| "Failed to get full SHA")?;
    let git_sha_short = get_short_sha(&repo, &git_ref)
        .with_context(|| "Failed to get short SHA")?;
    let commit_subject = get_commit_subject(&repo, &git_ref)
        .with_context(|| "Failed to get commit subject")?;

    // Get the full commit message text
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;
    let repo = Repository::open(&kernel_tree)?;
    let git_ref = resolve_reference(&repo, &git_sha_full)?;
    let mut commit_text = get_commit_text(&repo, &git_ref)?;

    // Read the tags file to strip from commit message
    let vulns_dir = cve_utils::find_vulns_dir()
        .with_context(|| "Failed to find vulns directory")?;
    let script_dir = vulns_dir.join("scripts");
    let tags = read_tags_file(&script_dir).unwrap_or_default();

    // Strip tags from commit text
    commit_text = strip_commit_text(&commit_text, &tags)
        .unwrap_or_else(|_| format!("In the Linux kernel, the following vulnerability has been resolved:\n\n{}", commit_text));

    // Apply diff file to the commit text if provided
    if let Some(diff_path) = args.diff.as_ref() {
        match apply_diff_to_text(&commit_text, diff_path) {
            Ok(modified_text) => {
                if args.verbose {
                    println!("Applied diff from {} to the commit text", diff_path.display());
                }
                // The apply_diff_to_text function handles newline preservation
                commit_text = modified_text;
            },
            Err(err) => {
                eprintln!("Warning: Failed to apply diff to commit text: {}", err);
            }
        }
    }

    // Run dyad with the given SHA
    let dyad_data = match run_dyad(&script_dir, &git_sha_full, vulnerable_sha, args.verbose) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Warning: Failed to run dyad: {:?}", err);
            String::new()
        }
    };

    // First check for the reference file explicitly specified with --reference
    let mut reference_path: Option<PathBuf> = args.reference.clone();

    // If not found, look in trailing arguments
    if reference_path.is_none() && reference_from_trailing.is_some() {
        // Extract just the path part from the argument
        let arg = reference_from_trailing.unwrap();
        let path = extract_path_from_arg(&arg);
        if args.verbose {
            println!("Extracted path from trailing arg: '{}'", path);
        }
        reference_path = Some(PathBuf::from(path));
    }

    // If still not found, look in raw command line arguments
    if reference_path.is_none() && reference_from_raw_args.is_some() {
        reference_path = Some(PathBuf::from(reference_from_raw_args.unwrap()));
    }

    let additional_references: Vec<String> = if let Some(ref_path) = reference_path {
        if args.verbose {
            println!("Attempting to read references from {:?}", ref_path);
        }

        if let Ok(contents) = std::fs::read_to_string(&ref_path) {
            if args.verbose {
                println!("Successfully read reference file");
                if !contents.is_empty() {
                    println!("Reference file contains {} lines", contents.lines().count());
                    for (i, line) in contents.lines().enumerate() {
                        if !line.trim().is_empty() {
                            println!("  Reference[{}]: {}", i, line.trim());
                        }
                    }
                } else {
                    println!("Reference file is empty");
                }
            }

            contents.lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect()
        } else {
            eprintln!("Warning: Failed to read reference file from {:?}", ref_path);
            if args.verbose {
                if !ref_path.exists() {
                    eprintln!("  File does not exist");
                } else if !ref_path.is_file() {
                    eprintln!("  Path exists but is not a regular file");
                } else {
                    eprintln!("  File exists but could not be read (permissions issue?)");
                }
            }
            Vec::new()
        }
    } else {
        if args.verbose {
            println!("No reference file specified");
        }
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
            &dyad_data,
            &script_name,
            &script_version,
            &additional_references,
            &commit_text,
        ) {
            Ok(json_record) => {
                if let Err(err) = std::fs::write(json_path, json_record) {
                    eprintln!("Warning: Failed to write JSON file to {:?}: {}", json_path, err);
                } else if args.verbose {
                    println!("Wrote JSON file to {}", json_path.display());
                }
            },
            Err(err) => {
                eprintln!("Error: Failed to generate JSON record: {}", err);
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
            &dyad_data,
            &script_name,
            &script_version,
            &additional_references,
            &commit_text,
        );

        if let Err(err) = std::fs::write(mbox_path, mbox_content) {
            eprintln!("Warning: Failed to write mbox file to {:?}: {}", mbox_path, err);
        } else if args.verbose {
            println!("Wrote mbox file to {}", mbox_path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cve_utils::version_utils::{version_is_rc, version_is_queue};
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
        let entry = DyadEntry::from_str("5.15:abcdef123456:5.16:789abcdef012").unwrap();
        assert_eq!(entry.vulnerable_version, "5.15");
        assert_eq!(entry.vulnerable_git(), "abcdef123456");
        assert_eq!(entry.fixed_version, "5.16");
        assert_eq!(entry.fixed_git(), "789abcdef012");
        assert!(entry.is_fixed());
        assert!(entry.is_cross_version());

        // Test with a vulnerability that isn't fixed
        let entry = DyadEntry::from_str("5.15:abcdef123456:0:0").unwrap();
        assert_eq!(entry.vulnerable_version, "5.15");
        assert_eq!(entry.vulnerable_git(), "abcdef123456");
        assert_eq!(entry.fixed_version, "0");
        assert_eq!(entry.fixed_git(), "0");
        assert!(!entry.is_fixed());

        // Test with an unknown introduction point
        let entry = DyadEntry::from_str("0:0:5.16:789abcdef012").unwrap();
        assert_eq!(entry.vulnerable_version, "0");
        assert_eq!(entry.vulnerable_git(), "0");
        assert_eq!(entry.fixed_version, "5.16");
        assert_eq!(entry.fixed_git(), "789abcdef012");
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
        let entries = vec![
            DyadEntry::from_str("0:abcdef123456:5.15:fedcba654321").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with mainline vulnerable version that's different from the fixed version
        let entries = vec![
            DyadEntry::from_str("5.10:abcdef123456:5.15:fedcba654321").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with mainline version that's both vulnerable and fixed in the same version
        // This should be "unaffected" because no actually released version was affected
        let entries = vec![
            DyadEntry::from_str("6.0:abcdef123456:6.0:fedcba654321").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");

        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            DyadEntry::from_str("5.10:abcdef123456:5.15:fedcba654321").unwrap(),
            DyadEntry::from_str("0:123456abcdef:6.0:654321fedcba").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with multiple entries, mix of same-version fixes and different-version fixes
        let entries = vec![
            DyadEntry::from_str("5.15.1:abcdef123456:5.15.2:fedcba654321").unwrap(),
            DyadEntry::from_str("6.0:123456abcdef:6.0:654321fedcba").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_generate_version_ranges() {
        // Test with a single entry for a stable kernel
        let entries = vec![
            DyadEntry::from_str("5.15:abcdef123456:5.16:fedcba654321").unwrap(),
        ];

        let (kernel_versions, git_versions) = generate_version_ranges(&entries, "unaffected");

        // Check git versions
        assert_eq!(git_versions.len(), 1);
        assert_eq!(git_versions[0].version, "abcdef123456");
        assert_eq!(git_versions[0].less_than, Some("fedcba654321".to_string()));
        assert_eq!(git_versions[0].status, "affected");

        // Check kernel versions
        assert_eq!(kernel_versions.len(), 1);
        assert_eq!(kernel_versions[0].version, "5.15");
        assert_eq!(kernel_versions[0].less_than, Some("5.16".to_string()));
        assert_eq!(kernel_versions[0].status, "affected");

        // Test with default status "affected"
        let entries = vec![
            DyadEntry::from_str("6.0:abcdef123456:6.1:fedcba654321").unwrap(),
        ];

        let (kernel_versions, git_versions) = generate_version_ranges(&entries, "affected");

        // Check git versions
        assert_eq!(git_versions.len(), 1);

        // Check kernel versions (should include unaffected entries)
        assert!(kernel_versions.len() >= 2);

        // Find the affected version
        let affected = kernel_versions.iter().find(|v| v.status == "affected").unwrap();
        assert_eq!(affected.version, "6.0");

        // Find the unaffected version
        let unaffected = kernel_versions.iter().find(|v| v.status == "unaffected" && v.version == "6.1").unwrap();
        assert_eq!(unaffected.version, "6.1");

        // Test with multiple entries
        let entries = vec![
            DyadEntry::from_str("5.15:abcdef123456:5.16:fedcba654321").unwrap(),
            DyadEntry::from_str("6.0:123456abcdef:6.1:654321fedcba").unwrap(),
        ];

        let (kernel_versions, git_versions) = generate_version_ranges(&entries, "unaffected");

        // Check git versions (should have two entries)
        assert_eq!(git_versions.len(), 2);

        // Check kernel versions (should have two entries)
        assert_eq!(kernel_versions.len(), 2);
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
        assert_eq!(tags.len(), 3);  // Changed from 4 to 3 to match implementation
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
        assert!(version.split('.').count() >= 2, "Version should have at least major.minor format");

        // Check that it contains only valid semver characters
        assert!(version.chars().all(|c| c.is_digit(10) || c == '.'),
                "Version should only contain digits and dots");
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
