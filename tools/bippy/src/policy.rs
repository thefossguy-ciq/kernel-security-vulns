// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// Policy decisions for CVE issuance and version range generation.
//
// This module centralizes all policy decisions in bippy to make them easy to
// understand, audit, and modify. All decisions about what constitutes a valid
// CVE, which versions are affected, and how to represent version ranges are
// defined here.

use cve_utils::dyad::DyadEntry;

// =============================================================================
// CONSTANTS
// =============================================================================

/// The first Linux kernel commit - used as "beginning of time" for version ranges
/// when we don't know when a vulnerability was introduced.
pub const FIRST_LINUX_COMMIT: &str = "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2";

/// Maximum length for CVE descriptions (CVE backend limit)
pub const MAX_DESCRIPTION_LENGTH: usize = 3982;

// =============================================================================
// POLICY: Same-Version Pairs
// =============================================================================
//
// A "same-version pair" is when a vulnerability is both introduced and fixed
// in the same kernel release version (e.g., both in 6.1).
//
// Policy: Same-version pairs should NOT result in CVE issuance because no
// actually released kernel version was ever vulnerable. The vulnerability
// existed only during the development cycle, not in any tagged release.
//
// This policy comes from CVE.org requirements: a CVE should only be issued
// when an actual release is vulnerable.

/// Check if a dyad entry represents a same-version pair (introduced and fixed
/// in the same release version).
///
/// Same-version pairs are excluded from CVE issuance because no released
/// kernel version was actually vulnerable.
#[inline]
pub fn is_same_version_pair(entry: &DyadEntry) -> bool {
    entry.vulnerable.version() == entry.fixed.version()
}

/// Check if a dyad entry should be included in CVE output.
///
/// An entry is included if it represents an actual vulnerability window
/// (i.e., not a same-version pair).
#[inline]
pub fn entry_should_be_included(entry: &DyadEntry) -> bool {
    !is_same_version_pair(entry)
}

// =============================================================================
// POLICY: CVE Issuance Decision
// =============================================================================
//
// Policy: A CVE should only be issued if at least one dyad entry represents
// a real vulnerability window - meaning the vulnerability was introduced in
// one version and fixed in a different version.
//
// If all entries are same-version pairs, no CVE should be issued.

/// Determine if a CVE should be issued for the given dyad entries.
///
/// Returns `true` if at least one entry represents a real vulnerability
/// window (not a same-version pair).
///
/// Returns `false` if all entries are same-version pairs, meaning no
/// released kernel version was ever vulnerable.
pub fn should_issue_cve(entries: &[DyadEntry]) -> bool {
    entries.iter().any(entry_should_be_included)
}

/// Check CVE issuance policy and log error if it fails.
///
/// This function checks whether a CVE should be issued. If the policy check
/// fails, it logs an error message explaining why and returns `false`.
/// The caller is responsible for exiting or handling the failure.
///
/// # Arguments
/// * `entries` - The dyad entries to check
/// * `git_sha` - The git SHA to include in the error message (for context)
///
/// # Returns
/// `true` if a CVE should be issued, `false` if policy rejects it (error already logged)
pub fn check_cve_issuance_policy(entries: &[DyadEntry], git_sha: &str) -> bool {
    if should_issue_cve(entries) {
        return true;
    }

    log::error!(
        "Despite having some vulnerable:fixed kernels, none were in an actual release, \
         so aborting and not assigning a CVE to {git_sha}"
    );
    false
}

/// Panic message for internal assertion failures when no includable entries exist.
///
/// This should never happen if `check_cve_issuance_policy` was called earlier,
/// but provides a clear message if the assertion fails.
pub fn no_includable_entries_error() -> &'static str {
    "No vulnerable:fixed kernel versions to include in CVE output. \
     This is an internal error - should have been caught by check_cve_issuance_policy()"
}

// =============================================================================
// POLICY: Default Status Determination
// =============================================================================
//
// The "default status" in a CVE record determines how unlisted versions are
// treated. This is a key policy decision that affects how the CVE is
// interpreted by consumers.
//
// Policy:
//   - "affected": Use when the vulnerability affects a wide range of versions,
//     especially when we don't know when it was introduced (vulnerable_version = 0),
//     or when mainline versions are affected.
//   - "unaffected": Use when the vulnerability is limited to specific stable
//     branches and doesn't affect mainline, or when it's fixed in the same
//     version it was introduced.

/// Determine the default status for CVE version ranges.
///
/// Returns "affected" when:
/// - Any entry has an unknown vulnerable version (version = 0)
/// - Any entry has a mainline vulnerable version that differs from the fix version
///
/// Returns "unaffected" when:
/// - All entries are same-version pairs, OR
/// - All affected versions are stable-only (not mainline)
pub fn determine_default_status(entries: &[DyadEntry]) -> &'static str {
    // If any entry has unknown vulnerable version, default to "affected"
    // because we don't know how far back the vulnerability goes
    if entries.iter().any(|entry| entry.vulnerable.is_empty()) {
        return "affected";
    }

    // If any entry has a mainline vulnerable version that's different from
    // the fixed version, the vulnerability spans releases, so default to "affected"
    if entries
        .iter()
        .any(|entry| entry.vulnerable.is_mainline() && entry_should_be_included(entry))
    {
        return "affected";
    }

    // Otherwise, the vulnerability is limited in scope, default to "unaffected"
    "unaffected"
}

// =============================================================================
// POLICY: Unknown Vulnerability Introduction
// =============================================================================
//
// When we don't know when a vulnerability was introduced (vulnerable_version = 0),
// we need to decide what to use as the "start" of the vulnerability window.
//
// Policy: Use the first Linux kernel commit as the start point. This is a
// conservative approach that assumes the vulnerability could have existed
// from the beginning of Linux history.

/// Get the git commit ID to use when the vulnerability introduction point is unknown.
///
/// Returns the first Linux kernel commit ID, representing "beginning of time".
#[inline]
pub fn get_unknown_vulnerable_commit() -> &'static str {
    FIRST_LINUX_COMMIT
}

// =============================================================================
// POLICY: Description Truncation
// =============================================================================
//
// CVE.org has a maximum description length limit. We need to truncate
// descriptions that exceed this limit.
//
// Policy: Truncate at the maximum length and add a "---truncated---" marker
// to indicate the description was cut off.

/// Truncate a description to fit within CVE backend limits.
///
/// If the description exceeds `MAX_DESCRIPTION_LENGTH` characters, it is
/// truncated and a "---truncated---" marker is added.
pub fn truncate_description(description: &str) -> String {
    // If already under the limit, just ensure no trailing newline
    if description.len() <= MAX_DESCRIPTION_LENGTH {
        return description.trim_end().to_string();
    }

    // Get the truncated text limited to max length
    let truncated = &description[..MAX_DESCRIPTION_LENGTH];

    // Special case: if only over by a trailing newline, just trim it
    if description.len() == MAX_DESCRIPTION_LENGTH + 1 && description.ends_with('\n') {
        truncated.to_string()
    } else {
        // Add truncation marker, with proper newline handling
        let separator = if truncated.ends_with('\n') { "" } else { "\n" };
        format!("{truncated}{separator}---truncated---")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cve_utils::dyad::DyadEntry;

    fn dyad_entry(s: &str) -> DyadEntry {
        DyadEntry::new(s).unwrap()
    }

    #[test]
    fn test_is_same_version_pair() {
        // Same version - should be true
        let entry = dyad_entry(
            "6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33",
        );
        assert!(is_same_version_pair(&entry));

        // Different versions - should be false
        let entry = dyad_entry(
            "5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541",
        );
        assert!(!is_same_version_pair(&entry));

        // Unknown vulnerable (0:0) - should be false
        let entry = dyad_entry("0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da");
        assert!(!is_same_version_pair(&entry));
    }

    #[test]
    fn test_should_issue_cve() {
        // Has real vulnerability window - should issue CVE
        let entries = vec![dyad_entry(
            "5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da",
        )];
        assert!(should_issue_cve(&entries));

        // Only same-version pairs - should NOT issue CVE
        let entries = vec![dyad_entry(
            "6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33",
        )];
        assert!(!should_issue_cve(&entries));

        // Mixed entries - should issue CVE (at least one real window)
        let entries = vec![
            dyad_entry("6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33"),
            dyad_entry("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541"),
        ];
        assert!(should_issue_cve(&entries));

        // Unknown vulnerable version - should issue CVE
        let entries = vec![dyad_entry(
            "0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da",
        )];
        assert!(should_issue_cve(&entries));
    }

    #[test]
    fn test_determine_default_status() {
        // Unknown vulnerable version - should be "affected"
        let entries = vec![dyad_entry(
            "0:0:5.15:11c52d250b34a0862edc29db03fbec23b30db6da",
        )];
        assert_eq!(determine_default_status(&entries), "affected");

        // Mainline vulnerability spanning versions - should be "affected"
        let entries = vec![dyad_entry(
            "5.11:e478d6029dca9d8462f426aee0d32896ef64f10f:5.15:11c52d250b34a0862edc29db03fbec23b30db6da",
        )];
        assert_eq!(determine_default_status(&entries), "affected");

        // Same-version pair only - should be "unaffected"
        let entries = vec![dyad_entry(
            "6.1:7bd7ad3c310cd6766f170927381eea0aa6f46c69:6.1:1a0398915d2243fc14be6506a6d226e0593a1c33",
        )];
        assert_eq!(determine_default_status(&entries), "unaffected");

        // Stable-only vulnerability - should be "unaffected"
        let entries = vec![dyad_entry(
            "5.15.1:569fd073a954616c8be5a26f37678a1311cc7f91:5.15.2:5dbe126056fb5a1a4de6970ca86e2e567157033a",
        )];
        assert_eq!(determine_default_status(&entries), "unaffected");
    }

    #[test]
    fn test_truncate_description() {
        // Short description - unchanged
        let short = "This is a short description.";
        assert_eq!(truncate_description(short), short);

        // At limit - unchanged
        let at_limit = "a".repeat(MAX_DESCRIPTION_LENGTH);
        assert_eq!(truncate_description(&at_limit), at_limit);

        // Over limit - truncated with marker
        let over_limit = "a".repeat(4000);
        let result = truncate_description(&over_limit);
        assert!(result.len() <= MAX_DESCRIPTION_LENGTH + 16);
        assert!(result.ends_with("---truncated---"));

        // Just over by newline - trim newline
        let with_newline = "a".repeat(MAX_DESCRIPTION_LENGTH - 1) + "\n";
        assert_eq!(
            truncate_description(&with_newline),
            "a".repeat(MAX_DESCRIPTION_LENGTH - 1)
        );
    }

}
