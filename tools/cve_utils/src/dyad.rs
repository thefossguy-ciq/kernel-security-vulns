// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use crate::Kernel;
use thiserror::Error;

/// Error types for the dyad output
#[derive(Error, Debug)]
pub enum DyadError {
    /// Error when parsing a dyad entry
    #[error("Invalid dyad entry: {0}")]
    InvalidDyadEntry(String),

    #[error("Invalid dyad git_id: {0}")]
    InvalidDyadGitId(String),

    #[error("Invalid dyad version: {0}")]
    InvalidDyadVersion(String),
}

/// `DyadEntry` represents a kernel vulnerability range entry from the dyad script
#[derive(Debug, Clone)]
pub struct DyadEntry {
    pub vulnerable: Kernel,
    pub fixed: Kernel,
}

impl DyadEntry {
    /// Create a new `DyadEntry` from a colon-separated string
    pub fn new(s: &str) -> Result<Self, DyadError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(DyadError::InvalidDyadEntry(s.to_string()));
        }

        let vulnerable_version = parts[0].to_string();
        let vulnerable_git = parts[1].to_string();
        let fixed_version = parts[2].to_string();
        let fixed_git = parts[3].to_string();

        // Create the vulnerable and fixed kernels by the git id, verifying that this is a valid
        // git id AND that the version number is what dyad gave us so that we don't go off of crazy
        // information somehow.
        let vulnerable_kernel = match Kernel::from_id(&vulnerable_git) {
            Ok(v) => v,
            Err(_e) => return Err(DyadError::InvalidDyadGitId(vulnerable_git)),
        };
        if vulnerable_kernel.version() != vulnerable_version {
            return Err(DyadError::InvalidDyadVersion(vulnerable_version));
        }

        let fixed_kernel = match Kernel::from_id(&fixed_git) {
            Ok(v) => v,
            Err(_e) => return Err(DyadError::InvalidDyadGitId(fixed_git)),
        };
        if fixed_kernel.version() != fixed_version {
            return Err(DyadError::InvalidDyadVersion(fixed_version));
        }

        Ok(Self {
            vulnerable: vulnerable_kernel,
            fixed: fixed_kernel,
        })
    }

    /// Create a new `DyadEntry` from a colon-separated string with NO validation
    /// Only do this if you know what you are doing (i.e. the output comes straight from dyad
    /// directly.
    pub fn new_no_validate(s: &str) -> Result<Self, DyadError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(DyadError::InvalidDyadEntry(s.to_string()));
        }

        let vulnerable_version = parts[0].to_string();
        let vulnerable_git = parts[1].to_string();
        let fixed_version = parts[2].to_string();
        let fixed_git = parts[3].to_string();

        let vulnerable_kernel = Kernel::from_id_no_validate(&vulnerable_git, &vulnerable_version);
        let fixed_kernel = Kernel::from_id_no_validate(&fixed_git, &fixed_version);

        Ok(Self {
            vulnerable: vulnerable_kernel,
            fixed: fixed_kernel,
        })
    }

    /// Check if this is a valid dyad entry by verifying that the sha values match the release, AND
    /// that the sha values are "full".  Useful if you create a dyad object from calling
    /// new_no_validate()
    pub fn is_valid(&self) -> bool {
        // FIXME
        true
    }

    /// Check if this vulnerability is found/fixed in the same kernel version
    pub fn is_same_version(&self) -> bool {
        self.vulnerable.version() == self.fixed.version()
    }

    /// Check if this vulnerability has been fixed
    #[cfg(test)]
    pub fn is_fixed(&self) -> bool {
        !self.fixed.is_empty()
    }

    /// Check if vulnerability spans across different kernel versions
    #[cfg(test)]
    pub fn is_cross_version(&self) -> bool {
        !self.vulnerable.is_empty()
            && !self.fixed.is_empty()
            && self.vulnerable.version() != self.fixed.version()
    }
}

#[cfg(test)]
mod tests {
    use crate::dyad::DyadEntry;
//    use super::*;
//    use cve_utils::version_utils::{version_is_mainline, version_is_queue, version_is_rc};
//    use std::fs::File;
//    use std::io::Write;
//    use tempfile::tempdir;

    #[test]
    fn test_dyad_entry_parsing() {
        let entry = DyadEntry::new("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap();
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
            DyadEntry::new("5.15:11c52d250b34a0862edc29db03fbec23b30db6da:0:0").unwrap();
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
            DyadEntry::new("0:0:5.16:2b503c8598d1b232e7fc7526bce9326d92331541").unwrap();
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
        let result = DyadEntry::new("invalid:format");
        assert!(result.is_err());
    }

    // --- Tests for new_no_validate ---

    #[test]
    fn test_new_no_validate_basic() {
        let entry = DyadEntry::new_no_validate(
            "6.8:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:6.9:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert_eq!(entry.vulnerable.version(), "6.8");
        assert_eq!(
            entry.vulnerable.git_id(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(entry.fixed.version(), "6.9");
        assert_eq!(
            entry.fixed.git_id(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn test_new_no_validate_with_zero_entries() {
        let entry = DyadEntry::new_no_validate(
            "0:0:6.8:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert!(entry.vulnerable.is_empty());
        assert_eq!(entry.fixed.version(), "6.8");
    }

    #[test]
    fn test_new_no_validate_unfixed() {
        let entry = DyadEntry::new_no_validate(
            "6.8:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:0",
        )
        .unwrap();
        assert_eq!(entry.vulnerable.version(), "6.8");
        assert!(entry.fixed.is_empty());
    }

    // --- Tests for is_same_version ---

    #[test]
    fn test_is_same_version_true() {
        let entry = DyadEntry::new_no_validate(
            "6.6.16:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:6.6.16:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(entry.is_same_version());
    }

    #[test]
    fn test_is_same_version_false() {
        let entry = DyadEntry::new_no_validate(
            "6.6.16:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:6.6.17:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(!entry.is_same_version());
    }

    // --- Malformed input ---

    #[test]
    fn test_new_no_validate_too_few_fields() {
        let result = DyadEntry::new_no_validate("6.8:abc:6.9");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_no_validate_too_many_fields() {
        let result = DyadEntry::new_no_validate("6.8:abc:6.9:def:extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_new_no_validate_empty_string() {
        let result = DyadEntry::new_no_validate("");
        assert!(result.is_err());
    }

    // --- Empty git IDs ---

    #[test]
    fn test_new_no_validate_empty_git_ids() {
        let entry = DyadEntry::new_no_validate("6.8::6.9:").unwrap();
        assert_eq!(entry.vulnerable.version(), "6.8");
        assert_eq!(entry.vulnerable.git_id(), "");
        assert_eq!(entry.fixed.version(), "6.9");
        assert_eq!(entry.fixed.git_id(), "");
    }
}
