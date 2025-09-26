// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use crate::models::dyad::DyadEntry;
use crate::models::{CpeMatch, CpeNodes, VersionRange};
use cve_utils::version_utils::compare_kernel_versions;
use cve_utils::version_utils::version_is_mainline;
use log::debug;
use std::collections::HashSet;

/// Determine the default status for CVE entries based on the dyad entries
pub fn determine_default_status(entries: &[DyadEntry]) -> &'static str {
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
pub fn generate_cpe_ranges(entries: &[DyadEntry]) -> Vec<CpeNodes> {
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
        if entry.is_same_version() {
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
pub fn generate_git_ranges(entries: &[DyadEntry]) -> Vec<VersionRange> {
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
pub fn generate_version_ranges(entries: &[DyadEntry], default_status: &str) -> Vec<VersionRange> {
    let mut kernel_versions = Vec::new();
    let mut seen_versions = HashSet::new();

    // Collect all affected and fixed versions
    let (affected_mainline_versions, fixed_mainline_versions) = collect_version_data(entries);

    // Debug output
    debug!(
        "Processing {} dyad entries with default_status={}",
        entries.len(),
        default_status
    );
    log_entry_details(entries);

    // Get sorted versions
    let all_versions =
        build_sorted_version_list(&affected_mainline_versions, &fixed_mainline_versions);

    if !all_versions.is_empty() {
        // Process each version and add to kernel_versions
        process_explicit_versions(
            &all_versions,
            &mut seen_versions,
            &mut kernel_versions,
            default_status,
        );

        // Process intermediate versions
        process_intermediate_versions(
            &all_versions,
            &mut seen_versions,
            &mut kernel_versions,
            default_status,
        );
    }

    // Process ranges for affected or unaffected versions
    process_version_ranges(
        entries,
        default_status,
        &affected_mainline_versions,
        &mut seen_versions,
        &mut kernel_versions,
    );

    // Sort the version ranges
    sort_version_ranges(&mut kernel_versions);

    // Debug output
    log_final_ranges(&kernel_versions);

    kernel_versions
}

/// Collect and log details of dyad entries
fn log_entry_details(entries: &[DyadEntry]) {
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
}

/// Collect affected and fixed mainline versions from dyad entries
fn collect_version_data(entries: &[DyadEntry]) -> (HashSet<String>, HashSet<String>) {
    let mut affected_mainline_versions = HashSet::new();
    let mut fixed_mainline_versions = HashSet::new();

    for entry in entries {
        // Skip entries where the vulnerability is in the same version it was fixed
        if entry.is_same_version() {
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

    (affected_mainline_versions, fixed_mainline_versions)
}

/// Build a sorted list of all versions with their affected status
fn build_sorted_version_list(
    affected_mainline_versions: &HashSet<String>,
    fixed_mainline_versions: &HashSet<String>,
) -> Vec<(String, bool)> {
    let mut all_versions: Vec<(String, bool)> = Vec::new(); // (version, is_affected)

    // Add all affected versions
    for v in affected_mainline_versions {
        all_versions.push((v.clone(), true));
    }

    // Add all fixed versions
    for v in fixed_mainline_versions {
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

    all_versions
}

/// Process explicit versions from the sorted list
fn process_explicit_versions(
    all_versions: &[(String, bool)],
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
    default_status: &str,
) {
    for (version, is_affected) in all_versions {
        // Don't add individual unaffected mainline versions - they'll be added later with range information
        if !is_affected && version_is_mainline(version) {
            debug!("Skipping individual unaffected mainline version {version} - will be added with range info later");
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
                "Skipping explicit version {version} (matches default status '{default_status}')"
            );
            continue;
        }

        let ver_key = format!("kernel:{status}:{version}:::");
        if seen_versions.insert(ver_key) {
            kernel_versions.push(VersionRange {
                version: version.clone(),
                less_than: None,
                less_than_or_equal: None,
                status: status.to_string(),
                version_type: None,
            });
            debug!("Added explicit version: {version} => {status}");
        }
    }
}

/// Process intermediate versions between known points
fn process_intermediate_versions(
    all_versions: &[(String, bool)],
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
    default_status: &str,
) {
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
                "Parsed version components: {current_major}.{current_minor} and {next_major}.{next_minor}"
            );

            // Only process if they're in the same major version and there's a gap
            if current_major == next_major && next_minor - current_minor > 1 {
                let config = GapProcessingConfig {
                    current_major,
                    current_minor,
                    next_minor,
                    current_affected: *current_affected,
                    next_affected: *next_affected,
                    default_status,
                };

                process_version_gap(&config, seen_versions, kernel_versions);
            } else {
                debug!("No gap found or different major versions");
            }
        } else {
            debug!("Failed to parse version components");
        }
    }
}

/// Configuration for gap processing
struct GapProcessingConfig<'a> {
    current_major: u32,
    current_minor: u32,
    next_minor: u32,
    current_affected: bool,
    next_affected: bool,
    default_status: &'a str,
}

/// Process versions in a gap between known points
fn process_version_gap(
    config: &GapProcessingConfig,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    let gap_size = config.next_minor - config.current_minor - 1;
    debug!("Found gap of {gap_size} versions");

    // Process each intermediate version
    for minor in (config.current_minor + 1)..config.next_minor {
        let intermediate_version = format!("{}.{}", config.current_major, minor);

        // Determine status based on surrounding versions
        let status = match (config.current_affected, config.next_affected) {
            (true | false, true) => "affected", // Both surrounding versions affected or current fixed, next affected
            (true, false) => {
                // Current affected, next fixed
                // If we're processing consecutive versions, the last affected version
                // should be the highest version that is affected, so we don't need to
                // explicitly add intermediate versions as affected - they'll be covered by default
                // Prevent redundant entries if default status is already "affected"
                if config.default_status == "affected" {
                    // Skip explicit entry by using default status
                    debug!("Setting status to default_status to skip redundant entry");
                    config.default_status
                } else {
                    "affected" // Only add explicit entries if default is not affected
                }
            }
            (false, false) => "unaffected", // Both surrounding versions fixed
        };

        debug!("Inferring intermediate version {intermediate_version} => {status}");

        // Explicitly check if the status equals the default_status string value
        let is_default = status == config.default_status;
        debug!(
            "Status '{}' is {} to default '{}'",
            status,
            if is_default { "equal" } else { "not equal" },
            config.default_status
        );

        // Only add intermediate version if its status differs from the default status
        // This prevents adding redundant entries
        if is_default {
            debug!("Skipping redundant intermediate version {intermediate_version} (matches default status '{}')", config.default_status);
        } else {
            add_version_if_new(intermediate_version, status, seen_versions, kernel_versions);
        }
    }
}

/// Add a version to `kernel_versions` if it's not already seen
fn add_version_if_new(
    version: String,
    status: &str,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    let ver_key = format!("kernel:{status}:{version}:::");
    if seen_versions.insert(ver_key) {
        let version_clone = version.clone();
        kernel_versions.push(VersionRange {
            version,
            less_than: None,
            less_than_or_equal: None,
            status: status.to_string(),
            version_type: None,
        });
        debug!("Added intermediate version: {version_clone} => {status}");
    }
}

/// Process version ranges for affected or unaffected versions
fn process_version_ranges(
    entries: &[DyadEntry],
    default_status: &str,
    affected_mainline_versions: &HashSet<String>,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    for entry in entries {
        // Skip entries where the vulnerability is in the same version it was fixed
        if entry.vulnerable.version() == entry.fixed.version() {
            continue;
        }

        if default_status == "affected" {
            process_unaffected_ranges(
                entry,
                affected_mainline_versions,
                seen_versions,
                kernel_versions,
            );
        } else {
            process_affected_ranges(entry, seen_versions, kernel_versions);
        }
    }
}

/// Process unaffected ranges when default status is "affected"
fn process_unaffected_ranges(
    entry: &DyadEntry,
    affected_mainline_versions: &HashSet<String>,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    // Only add versions before affected as unaffected if no other versions before this are affected
    if entry.vulnerable.is_mainline() {
        add_pre_affected_unaffected_range(
            entry,
            affected_mainline_versions,
            seen_versions,
            kernel_versions,
        );
    }

    // Add fixed versions as unaffected
    if entry.fixed.version() != "0" {
        add_fixed_unaffected_range(
            entry,
            affected_mainline_versions,
            seen_versions,
            kernel_versions,
        );
    }
}

/// Add unaffected range for versions before the first affected version
fn add_pre_affected_unaffected_range(
    entry: &DyadEntry,
    affected_mainline_versions: &HashSet<String>,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    let unaffected_key = format!("kernel:unaffected:0:{}:", entry.vulnerable.version());
    // First check if we need to process this unaffected range
    if seen_versions.contains(&unaffected_key) {
        return;
    }

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
            less_than: Some(entry.vulnerable.version()),
            less_than_or_equal: None,
            status: "unaffected".to_string(),
            version_type: Some("semver".to_string()),
        });
    }
}

/// Add unaffected range for versions after the fix
fn add_fixed_unaffected_range(
    entry: &DyadEntry,
    affected_mainline_versions: &HashSet<String>,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    let fixed_version = entry.fixed.version();
    // For stable kernels, determine the wildcard pattern
    let version_parts: Vec<&str> = fixed_version.split('.').collect();
    let wildcard = if version_parts.len() >= 2 {
        format!("{}.{}.*", version_parts[0], version_parts[1])
    } else {
        format!("{}.*", entry.fixed.version())
    };

    // Create a unique key for this version
    let key = format!("kernel:unaffected:{}::{}", entry.fixed.version(), wildcard);

    if seen_versions.insert(key) {
        // Add fixed version as unaffected
        if entry.fixed.is_mainline() {
            add_mainline_fixed_unaffected_range(entry, affected_mainline_versions, kernel_versions);
        } else {
            // For stable kernels with a patch version (e.g., 5.10.234)
            kernel_versions.push(VersionRange {
                version: entry.fixed.version(),
                less_than: None,
                less_than_or_equal: Some(wildcard),
                status: "unaffected".to_string(),
                version_type: Some("semver".to_string()),
            });
        }
    }
}

/// Add unaffected range for mainline versions after the fix
fn add_mainline_fixed_unaffected_range(
    entry: &DyadEntry,
    affected_mainline_versions: &HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
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
        let next_affected_version = find_next_affected_version(entry, affected_mainline_versions);

        if let Some(next_version) = next_affected_version {
            // Add a range for versions between the fixed version and the next affected version
            kernel_versions.push(VersionRange {
                version: entry.fixed.version(),
                less_than: Some(next_version),
                less_than_or_equal: None,
                status: "unaffected".to_string(),
                version_type: Some("semver".to_string()),
            });
        } else {
            // Fallback - should not normally happen
            kernel_versions.push(VersionRange {
                version: entry.fixed.version(),
                less_than: None,
                less_than_or_equal: None,
                status: "unaffected".to_string(),
                version_type: Some("original_commit_for_fix".to_string()),
            });
        }
    } else {
        // No later affected versions or this is an RC version, so we can use the original_commit_for_fix entry
        kernel_versions.push(VersionRange {
            version: entry.fixed.version(),
            less_than: None,
            less_than_or_equal: Some("*".to_string()),
            status: "unaffected".to_string(),
            version_type: Some("original_commit_for_fix".to_string()),
        });
    }
}

/// Find the next affected version after a fixed version
fn find_next_affected_version(
    entry: &DyadEntry,
    affected_mainline_versions: &HashSet<String>,
) -> Option<String> {
    let mut next_affected_version: Option<String> = None;

    for v in affected_mainline_versions {
        if compare_kernel_versions(&entry.fixed.version(), v) == std::cmp::Ordering::Less {
            // v is later than entry.fixed.version()
            if let Some(ref candidate) = next_affected_version {
                if compare_kernel_versions(candidate, v) == std::cmp::Ordering::Greater {
                    next_affected_version = Some(v.clone());
                }
            } else {
                // No candidate yet, set this as the first candidate
                next_affected_version = Some(v.clone());
            }
        }
    }

    next_affected_version
}

/// Process affected ranges when default status is "unaffected"
fn process_affected_ranges(
    entry: &DyadEntry,
    seen_versions: &mut HashSet<String>,
    kernel_versions: &mut Vec<VersionRange>,
) {
    if entry.vulnerable.version() != "0" && entry.fixed.version() != "0" {
        let ver_range = VersionRange {
            version: entry.vulnerable.version(),
            less_than: Some(entry.fixed.version()),
            less_than_or_equal: None,
            status: "affected".to_string(),
            version_type: Some("semver".to_string()),
        };

        let key = format!(
            "kernel:affected:{}:{}:",
            ver_range.version,
            ver_range.less_than.as_deref().unwrap_or("")
        );

        if seen_versions.insert(key) {
            kernel_versions.push(ver_range);
        }
    }
}

/// Sort the version ranges to ensure consistent output
fn sort_version_ranges(kernel_versions: &mut [VersionRange]) {
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
}

/// Log the final version ranges for debugging
fn log_final_ranges(kernel_versions: &[VersionRange]) {
    debug!("Final kernel version ranges:");
    for v in kernel_versions {
        let range_desc = match (&v.less_than, &v.less_than_or_equal) {
            (Some(lt), None) => format!(" < {lt}"),
            (None, Some(lte)) => format!(" <= {lte}"),
            (Some(lt), Some(lte)) => format!(" < {lt} OR <= {lte}"),
            (None, None) => String::new(),
        };
        debug!("   {0} ({1}){2}", v.version, v.status, range_desc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::dyad::DyadEntry;

    // Helper function to create a DyadEntry from string representation
    fn dyad_entry(s: &str) -> DyadEntry {
        DyadEntry::from_str(s).unwrap()
    }

    #[test]
    fn test_determine_default_status_with_unknown_vulnerable() {
        // When vulnerable_version = 0, status should be "affected"
        let entries = vec![dyad_entry(
            "0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da",
        )];
        assert_eq!(determine_default_status(&entries), "affected");
    }

    #[test]
    fn test_determine_default_status_with_unfixed_vulnerabilities() {
        // When there are unfixed vulnerabilities, status should be "affected"
        let entries = vec![dyad_entry(
            "5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:0:0",
        )];
        assert_eq!(determine_default_status(&entries), "affected");
    }

    #[test]
    fn test_determine_default_status_with_mainline_cross_version_vulnerability() {
        // When there's a mainline vulnerable version that's different from the fixed version,
        // status should be "affected"
        let entries = vec![
            dyad_entry("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da"),
        ];
        assert_eq!(determine_default_status(&entries), "affected");
    }

    #[test]
    fn test_determine_default_status_with_same_version_fix() {
        // When a vulnerability is both introduced and fixed in the same version,
        // status should be "unaffected" because no actually released version was affected
        let entries = vec![
            dyad_entry("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33"),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_determine_default_status_with_stable_version_fix() {
        // When only stable versions are affected and fixed, status should be "unaffected"
        let entries = vec![
            dyad_entry("5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a"),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_determine_default_status_with_mixed_entries() {
        // Test with multiple entries, one with vulnerable_version = 0
        let entries = vec![
            dyad_entry("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da"),
            dyad_entry("0:0:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33"),
        ];
        assert_eq!(determine_default_status(&entries), "affected");

        // Test with multiple entries, mix of same-version fixes and different-version fixes
        let entries = vec![
            dyad_entry("5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a"),
            dyad_entry("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33"),
        ];
        assert_eq!(determine_default_status(&entries), "unaffected");

        // Mainline vulnerability that's not fixed should make the default status "affected"
        let entries = vec![
            // Just use this entry which we know works and has a mainline vulnerability
            dyad_entry("5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da"),
        ];
        assert_eq!(determine_default_status(&entries), "affected");
    }

    #[test]
    fn test_generate_cpe_ranges_with_cross_version_vulnerability() {
        // Test with a single entry for a cross-version vulnerability
        let entries = vec![
            dyad_entry("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541"),
        ];

        let cpe_nodes = generate_cpe_ranges(&entries);

        // Should have one OR node with one CPE match
        assert_eq!(cpe_nodes.len(), 1);
        assert_eq!(cpe_nodes[0].operator, "OR");
        assert!(!cpe_nodes[0].negate);
        assert_eq!(cpe_nodes[0].cpe_match.len(), 1);

        // Check CPE match details
        let cpe_match = &cpe_nodes[0].cpe_match[0];
        assert!(cpe_match.vulnerable);
        assert_eq!(
            cpe_match.criteria,
            "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        );
        assert_eq!(cpe_match.version_start_including, "5.15");
        assert_eq!(cpe_match.version_end_excluding, "5.16");
    }

    #[test]
    fn test_generate_cpe_ranges_with_unknown_vulnerable() {
        // Test with an unknown vulnerability introduction point
        let entries = vec![dyad_entry(
            "0:0:5.16:2b503c8598d1b232e7fc7526bce9326d92331541",
        )];

        let cpe_nodes = generate_cpe_ranges(&entries);

        // Should have one OR node with one CPE match
        assert_eq!(cpe_nodes.len(), 1);
        assert_eq!(cpe_nodes[0].cpe_match.len(), 1);

        // Check CPE match details - no version_start_including, only version_end_excluding
        let cpe_match = &cpe_nodes[0].cpe_match[0];
        assert_eq!(cpe_match.version_start_including, "");
        assert_eq!(cpe_match.version_end_excluding, "5.16");
    }

    #[test]
    fn test_generate_cpe_ranges_with_unfixed_vulnerability() {
        // Test with an unfixed vulnerability
        let entries = vec![dyad_entry(
            "5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:0:0",
        )];

        let cpe_nodes = generate_cpe_ranges(&entries);

        // Should have one OR node with one CPE match
        assert_eq!(cpe_nodes.len(), 1);
        assert_eq!(cpe_nodes[0].cpe_match.len(), 1);

        // Check CPE match details - only version_start_including, no version_end_excluding
        let cpe_match = &cpe_nodes[0].cpe_match[0];
        assert_eq!(cpe_match.version_start_including, "5.11");
        assert_eq!(cpe_match.version_end_excluding, "");
    }

    #[test]
    fn test_generate_cpe_ranges_with_same_version_vulnerability() {
        // Test with a vulnerability that's fixed in the same version
        let entries = vec![
            dyad_entry("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33"),
        ];

        let cpe_nodes = generate_cpe_ranges(&entries);

        // Should have one OR node with no CPE matches (skipped due to same version)
        assert_eq!(cpe_nodes.len(), 1);
        assert_eq!(cpe_nodes[0].cpe_match.len(), 0);
    }

    #[test]
    fn test_generate_git_ranges_basic() {
        // Test with a single entry
        let entries = vec![
            dyad_entry("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541"),
        ];

        let git_versions = generate_git_ranges(&entries);

        // Should have one git version entry
        assert_eq!(git_versions.len(), 1);

        // Check git version details
        let git_version = &git_versions[0];
        assert_eq!(
            git_version.version,
            "11c52d250b34a0862edc29db03fbec23b30db6da"
        );
        assert_eq!(git_version.status, "affected");
        assert_eq!(git_version.version_type, Some("git".to_string()));
        assert_eq!(
            git_version.less_than,
            Some("2b503c8598d1b232e7fc7526bce9326d92331541".to_string())
        );
        assert_eq!(git_version.less_than_or_equal, None);
    }

    #[test]
    fn test_generate_git_ranges_with_unknown_vulnerable() {
        // Test with an unknown vulnerability introduction point
        let entries = vec![dyad_entry(
            "0:0:5.16:2b503c8598d1b232e7fc7526bce9326d92331541",
        )];

        let git_versions = generate_git_ranges(&entries);

        // Should have one git version entry starting from the first Linux commit ID
        assert_eq!(git_versions.len(), 1);
        assert_eq!(
            git_versions[0].version,
            "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
        );
        assert_eq!(
            git_versions[0].less_than,
            Some("2b503c8598d1b232e7fc7526bce9326d92331541".to_string())
        );
    }

    #[test]
    fn test_generate_git_ranges_with_unfixed_vulnerability() {
        // Test with an unfixed vulnerability
        let entries = vec![dyad_entry(
            "5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:0:0",
        )];

        let git_versions = generate_git_ranges(&entries);

        // Should have one git version entry with no "less_than" field
        assert_eq!(git_versions.len(), 1);
        assert_eq!(
            git_versions[0].version,
            "e478d6029dca9d8462f426aee0d32896ef64f10f"
        );
        assert_eq!(git_versions[0].less_than, None);
    }

    #[test]
    fn test_version_ranges_functionality() {
        // Test the basic functionality of generate_version_ranges
        // Note: This function is complex and depends heavily on external functions,
        // so we're only testing core aspects rather than full functionality

        // Test with a single entry and default status "unaffected"
        let entries = vec![
            dyad_entry("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541"),
        ];

        let kernel_versions = generate_version_ranges(&entries, "unaffected");

        // Verify we get at least some entries back
        assert!(!kernel_versions.is_empty());

        // Verify we have some affected entries
        let affected_entries: Vec<&VersionRange> = kernel_versions
            .iter()
            .filter(|v| v.status == "affected")
            .collect();

        assert!(!affected_entries.is_empty());
    }
}
