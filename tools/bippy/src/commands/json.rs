// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use cve_utils::git_utils::{get_affected_files, resolve_reference};
use git2::Repository;
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use std::collections::HashSet;

use crate::models::{CnaData, Containers, CpeApplicability, CveMetadata, CveRecord, DyadEntry, Generator, ProviderMetadata, Reference, Description, AffectedProduct};
use crate::utils::{generate_cpe_ranges, generate_git_ranges, generate_version_ranges, determine_default_status, read_uuid};

/// Generate a JSON record for the CVE
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn generate_json_record(
    cve_number: &str,
    git_sha_full: &str,
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
        if let Ok(entry) = DyadEntry::from_str(&format!("0:0:0:{git_sha_full}")) {
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
        let main_fix_url = format!("https://git.kernel.org/stable/c/{git_sha_full}");
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
            format!("{truncated}{separator}---truncated---")
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
                    engine: format!("{script_name}-{script_version}"),
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
        .map_err(|e| anyhow::anyhow!("Error serializing JSON: {e}"))?;

    let json_string = String::from_utf8(output)
        .map_err(|e| anyhow::anyhow!("Error converting JSON to string: {e}"))?;

    // Ensure the JSON output ends with a newline
    if json_string.ends_with('\n') {
        Ok(json_string)
    } else {
        Ok(json_string + "\n")
    }
}