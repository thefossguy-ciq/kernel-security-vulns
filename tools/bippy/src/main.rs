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
use cve_utils;
use cve_utils::version_utils::version_is_mainline;
use cve_utils::git_utils::{resolve_reference, get_object_full_sha, get_short_sha, get_affected_files};
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

    // Add the rest of the message until we reach a tag
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Stop when we reach a tag line
        if tags.iter().any(|tag| trimmed.to_lowercase().starts_with(&tag.to_lowercase())) {
            break;
        }

        // Add the line to the result
        result.push_str(line);
        result.push('\n');
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

    // If any entry has a mainline vulnerable version, status should be "affected"
    if entries.iter().any(|entry| version_is_mainline(&entry.vulnerable_version)) {
        return "affected";
    }

    // Otherwise status should be "unaffected"
    "unaffected"
}

/// Generate version ranges for the CVE JSON format
fn generate_version_ranges(entries: &[DyadEntry], default_status: &str) -> (Vec<VersionRange>, Vec<VersionRange>) {
    let mut kernel_versions = Vec::new();
    let mut git_versions = Vec::new();

    // Use HashSets to track unique entries based on their full content
    let mut seen_versions = HashSet::new();

    // Process entries from dyad output
    for entry in entries {
        // Handle git version ranges
        if entry.vulnerable_version != "0" && entry.vulnerable_git() != "0" {
            // Create a version range for Git
            let ver_range = VersionRange {
                version: entry.vulnerable_git().to_string(),
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
            if !seen_versions.contains(&key) && entry.fixed_git() != "0" {
                seen_versions.insert(key);
                git_versions.push(ver_range);
            }
        }

        // Handle kernel version ranges
        if default_status == "affected" {
            // If this is the first time we're seeing a vulnerable version, add it as affected
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
        a.version.cmp(&b.version)
    });

    git_versions.sort_by(|a, b| {
        if a.status != b.status {
            return a.status.cmp(&b.status);
        }
        a.version.cmp(&b.version)
    });

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
fn run_dyad(script_dir: &Path, git_sha: &str, vulnerable_sha: Option<&str>) -> Result<String> {
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
    let commit_tree = std::env::var("CVECOMMITTREE")
        .with_context(|| "CVECOMMITTREE environment variable is not set")?;

    // Construct the command
    let mut command = std::process::Command::new(&dyad_script);

    // Set environment variables
    command.env("CVEKERNELTREE", &kernel_tree)
           .env("CVECOMMITTREE", &commit_tree);

    // Add vulnerable SHA if provided
    if let Some(vuln_sha) = vulnerable_sha {
        if !vuln_sha.is_empty() {
            command.arg("-v").arg(vuln_sha);

            if let Ok(repo) = Repository::open(&kernel_tree) {
                if let Ok(obj) = resolve_reference(&repo, vuln_sha) {
                    if let Ok(short_sha) = get_short_sha(&repo, &obj) {
                        println!("Using vulnerable SHA: {}", short_sha);
                    }
                }
            }
        }
    }

    // Add the Git SHA
    command.arg(git_sha);

    println!("Running command: {:?}", command);

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

    /// Output diff file path
    #[clap(short, long)]
    diff: Option<PathBuf>,

    /// Reference file path
    #[clap(short, long)]
    reference: Option<PathBuf>,

    /// Reference value
    #[clap(short = 'R', long)]
    reference_value: Option<String>,

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
fn apply_diff_to_text<'a>(repo: &'a Repository, obj: &Object<'a>, _affected_files: &[String]) -> Result<String> {
    let commit = obj.as_commit()
        .ok_or_else(|| anyhow::anyhow!("Object is not a commit"))?;

    // Get parent commit
    let parent = match commit.parent(0) {
        Ok(parent) => parent,
        Err(_) => {
            // First commit has no parent
            return Ok(String::new());
        }
    };

    // Get the diff between parent and commit
    let parent_tree = parent.tree()?;
    let commit_tree = commit.tree()?;

    let diff = repo.diff_tree_to_tree(Some(&parent_tree), Some(&commit_tree), None)?;

    let mut diff_text = String::new();
    diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
        diff_text.push_str(&String::from_utf8_lossy(line.content()));
        true
    })?;

    Ok(diff_text)
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
struct CnaData {
    #[serde(rename = "providerMetadata")]
    provider_metadata: ProviderMetadata,
    descriptions: Vec<Description>,
    affected: Vec<AffectedProduct>,
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

    // Get the full commit text
    let kernel_tree = std::env::var("CVEKERNELTREE")
        .with_context(|| "CVEKERNELTREE environment variable is not set")?;
    let repo = Repository::open(&kernel_tree)?;
    let git_ref = resolve_reference(&repo, git_sha_full)?;
    let commit_text = get_commit_text(&repo, &git_ref)?;

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

        // Add vulnerable commit reference if available
        if entry.vulnerable_git() != "0" {
            let url = format!("https://git.kernel.org/stable/c/{}", entry.vulnerable_git());
            if !seen_refs.contains(&url) {
                seen_refs.insert(url.clone());
                references.push(Reference {
                    url,
                });
            }
        }
    }

    // If no references were found, add the main fix commit
    if references.is_empty() {
        let main_fix_url = format!("https://git.kernel.org/stable/c/{}", git_sha_full);
        references.push(Reference {
            url: main_fix_url,
        });
    }

    // Strip tags from commit text
    let vulns_dir = match cve_utils::find_vulns_dir() {
        Ok(dir) => dir,
        Err(_) => PathBuf::new(),
    };

    let script_dir = vulns_dir.join("scripts");
    let tags = read_tags_file(&script_dir).unwrap_or_default();

    // Get the full commit message, skipping tags at the end
    let full_message = match strip_commit_text(&commit_text, &tags) {
        Ok(desc) => desc,
        Err(_) => {
            // If stripping fails, use the raw commit text with a fallback prefix
            format!("In the Linux kernel, the following vulnerability has been resolved:\n\n{}", commit_text)
        }
    };

    // Use the full message without specific commit ID hardcoding
    let description = full_message;

    // No need to truncate, we want the full message

    // Create the structured CVE record using our defined types
    let cve_record = CveRecord {
        containers: Containers {
            cna: CnaData {
                provider_metadata: ProviderMetadata {
                    org_id: uuid.clone(),
                },
                descriptions: vec![Description {
                    lang: "en".to_string(),
                    value: description,
                }],
                affected: vec![git_product, kernel_product],
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

    Ok(json_string)
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
            if entry.vulnerable_version != "0" && entry.fixed_version != "0" {
                // Use full commit hashes instead of short versions
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

    // Get URLs for mitigation section
    let mut url_array = Vec::new();
    // Add the main fix commit URL
    url_array.push(format!("https://git.kernel.org/stable/c/{}", git_sha_full));

    // Add all fix commit URLs from dyad entries
    for line in dyad_data.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if let Ok(entry) = DyadEntry::from_str(line) {
            if entry.fixed_version != "0" && entry.fixed_git() != "0" {
                let fix_url = format!("https://git.kernel.org/stable/c/{}", entry.fixed_git());
                if !url_array.contains(&fix_url) {
                    url_array.push(fix_url);
                }
            }
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

    // Get the commit message
    let commit_message = match resolve_reference(&repo, git_sha_full) {
        Ok(obj) => match get_commit_text(&repo, &obj) {
            Ok(text) => {
                // Get the tags to strip
                let vulns_dir = match cve_utils::find_vulns_dir() {
                    Ok(dir) => dir,
                    Err(_) => PathBuf::new(),
                };

                let script_dir = vulns_dir.join("scripts");
                let tags = read_tags_file(&script_dir).unwrap_or_default();
                let message = strip_commit_text(&text, &tags).unwrap_or(text);

                // Remove any extra blank lines between the description and the CVE assignment line
                message.replace("\n\n\nThe Linux kernel", "\nThe Linux kernel")
            },
            Err(_) => String::from("No commit message available")
        },
        Err(_) => String::from("No commit message available")
    };

    // The full formatted mbox content
    format!(
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
        commit_message,
        cve_number,
        vuln_section,
        cve_number,
        files_section,
        url_section
    )
}

/// Main function
fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

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

    // Check for CVECOMMITTREE environment variable
    if env::var("CVECOMMITTREE").is_err() {
        eprintln!("CVECOMMITTREE environment variable is not set");
        eprintln!("It needs to be set to the Stable commit tree");
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

    let user_name = args.name.as_deref().unwrap_or("");

    // Debug output if verbose is enabled
    if args.verbose {
        println!("CVE_NUMBER={}", cve_number);
        println!("GIT_SHA={}", git_sha);
        println!("JSON_FILE={:?}", args.json);
        println!("MBOX_FILE={:?}", args.mbox);
        println!("DIFF_FILE={:?}", args.diff);
        println!("REFERENCE_FILE={:?}", args.reference);
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

    // Get additional commit information if requested
    let _commit_text = match args.diff.as_ref() {
        Some(_) => get_commit_text(&repo, &git_ref)
            .with_context(|| "Failed to get commit text")?,
        None => String::new(),
    };

    // Get affected files if diff file is requested
    let affected_files = match args.diff.as_ref() {
        Some(_) => get_affected_files(&repo, &git_ref)
            .with_context(|| "Failed to get affected files")?,
        None => Vec::new(),
    };

    // Run dyad with the given SHA
    let dyad_data = match run_dyad(&script_dir, &git_sha_full, vulnerable_sha) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Warning: Failed to run dyad: {:?}", err);
            String::new()
        }
    };

    // Write diff file if requested
    if let Some(diff_path) = args.diff.as_ref() {
        match apply_diff_to_text(&repo, &git_ref, &affected_files) {
            Ok(diff_text) => {
                if let Err(err) = std::fs::write(diff_path, diff_text) {
                    eprintln!("Warning: Failed to write diff file to {:?}: {}", diff_path, err);
                } else if args.verbose {
                    println!("Wrote diff file to {}", diff_path.display());
                }
            },
            Err(err) => {
                eprintln!("Warning: Failed to generate diff text: {}", err);
            }
        }
    }

    // Write reference file if requested
    if let Some(ref_path) = args.reference.as_ref() {
        if let Some(ref_value) = args.reference_value.as_ref() {
            if let Err(err) = std::fs::write(ref_path, ref_value) {
                eprintln!("Warning: Failed to write reference file to {:?}: {}", ref_path, err);
            } else if args.verbose {
                println!("Wrote reference file to {}", ref_path.display());
            }
        } else {
            eprintln!("Warning: reference file specified but no reference value provided");
        }
    }

    // Generate JSON file if requested
    if let Some(json_path) = args.json.as_ref() {
        match generate_json_record(
            cve_number,
            &git_sha_full,
            &git_sha_short,
            &commit_subject,
            user_name,
            &user_email,
            &dyad_data,
            &script_name,
            &script_version,
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
            user_name,
            &user_email,
            &dyad_data,
            &script_name,
            &script_version,
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

        // Test with mainline vulnerable version
        let entries = vec![
            DyadEntry::from_str("5.10:abcdef123456:5.15:fedcba654321").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with mainline version (mainline should be "affected")
        let entries = vec![
            DyadEntry::from_str("6.0:abcdef123456:6.1:fedcba654321").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            DyadEntry::from_str("5.10:abcdef123456:5.15:fedcba654321").unwrap(),
            DyadEntry::from_str("0:123456abcdef:6.0:654321fedcba").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with multiple entries, one with mainline vulnerable version
        let entries = vec![
            DyadEntry::from_str("5.15.1:abcdef123456:5.15.2:fedcba654321").unwrap(),
            DyadEntry::from_str("6.0:123456abcdef:6.1:654321fedcba").unwrap(),
        ];
        assert_eq!(determine_default_status(&entries), "affected");
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
