// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

//! Version utilities for kernel version management

use anyhow::Result;
use std::cmp::Ordering;
use std::str::FromStr;

/// Represents a parsed Linux kernel version
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVersion {
    /// Version components (e.g., [5, 10, 7])
    components: Vec<u32>,
    /// Release candidate number if applicable
    rc_num: Option<u32>,
    /// Whether this is a queue version
    is_queue: bool,
    /// Whether this version contains "-rc" in its name
    is_rc_by_name: bool,
}

impl KernelVersion {
    /// Creates a new `KernelVersion` from parsed components
    #[must_use]
    pub fn new(
        components: Vec<u32>,
        rc_num: Option<u32>,
        is_queue: bool,
        is_rc_by_name: bool,
    ) -> Self {
        Self {
            components,
            rc_num,
            is_queue,
            is_rc_by_name,
        }
    }

    /// Returns whether this is a release candidate version
    #[must_use]
    pub fn is_rc(&self) -> bool {
        // A version is considered an RC if it has "-rc" in its representation,
        // even if we couldn't parse a valid RC number
        self.rc_num.is_some() || self.is_rc_by_name
    }

    /// Returns whether this is a queue version
    #[must_use]
    pub fn is_queue(&self) -> bool {
        self.is_queue
    }

    /// Returns whether this is a mainline version (e.g., 5.10, not 5.10.7)
    #[must_use]
    pub fn is_mainline(&self) -> bool {
        if self.components.is_empty() || self.components[0] == 0 {
            return false;
        }

        // If it's an RC, it's considered mainline
        if self.is_rc() {
            return true;
        }

        // If it's in a queue, it's not mainline
        if self.is_queue() {
            return false;
        }

        // Check for 2.6.x and 2.4.x special cases
        if self.components.len() >= 3
            && self.components[0] == 2
            && (self.components[1] == 6 || self.components[1] == 4)
        {
            return self.components.len() == 3;
        }

        // Regular mainline versions have exactly two components (e.g., 5.10)
        self.components.len() == 2
    }

    /// Gets the major version (e.g., "5.10" from "5.10.7")
    #[must_use]
    pub fn major_version(&self) -> String {
        if self.components.is_empty() {
            return String::new();
        }

        // Special case for 2.6.x kernels
        if self.components.len() >= 3 && self.components[0] == 2 && self.components[1] == 6 {
            return format!("2.6.{}", self.components[2]);
        }

        // Regular major version is just the first two components
        if self.components.len() >= 2 {
            return format!("{}.{}", self.components[0], self.components[1]);
        }

        String::new()
    }

    /// Checks if the major version matches another kernel version
    #[must_use]
    pub fn major_matches(&self, other: &KernelVersion) -> bool {
        !self.major_version().is_empty()
            && !other.major_version().is_empty()
            && self.major_version() == other.major_version()
    }
}

impl FromStr for KernelVersion {
    type Err = anyhow::Error;

    fn from_str(version: &str) -> Result<Self, Self::Err> {
        let is_queue = version.contains("-queue");
        let is_rc_by_name = version.contains("-rc");

        // Handle RC versions
        let (base_version, rc_num) = if let Some(rc_idx) = version.find("-rc") {
            let base = &version[0..rc_idx];

            // Parse RC number if present
            let rc_number = if rc_idx + 3 < version.len() {
                version[rc_idx + 3..].parse::<u32>().ok()
            } else {
                Some(0) // Just "-rc" without number
            };

            (base, rc_number)
        } else {
            (version, None)
        };

        // Parse version components
        let components: Vec<u32> = base_version
            .split('.')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect();

        Ok(KernelVersion::new(
            components,
            rc_num,
            is_queue,
            is_rc_by_name,
        ))
    }
}

impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Special case for mainline vs stable of same major version
        if self.major_matches(other) {
            if self.is_mainline() && !other.is_mainline() {
                return Ordering::Less;
            }
            if !self.is_mainline() && other.is_mainline() {
                return Ordering::Greater;
            }
        }

        // Compare version components
        let max_len = std::cmp::max(self.components.len(), other.components.len());
        for i in 0..max_len {
            let v1 = self.components.get(i).copied().unwrap_or(0);
            let v2 = other.components.get(i).copied().unwrap_or(0);

            match v1.cmp(&v2) {
                Ordering::Equal => {}
                other_ord => return other_ord,
            }
        }

        // If components are equal, compare RC status
        match (self.is_rc(), other.is_rc()) {
            (true, false) => Ordering::Less,    // RC is less than final
            (false, true) => Ordering::Greater, // Final is greater than RC
            (true, true) => {
                // Both are RCs, compare RC numbers
                let rc1 = self.rc_num.unwrap_or(0);
                let rc2 = other.rc_num.unwrap_or(0);
                rc1.cmp(&rc2)
            }
            (false, false) => Ordering::Equal,
        }
    }
}

// Wrapper functions to maintain backward compatibility

/// Check if a kernel version is a release candidate (ends with -rc)
#[must_use]
pub fn version_is_rc(version: &str) -> bool {
    KernelVersion::from_str(version)
        .map(|v| v.is_rc())
        .unwrap_or(false)
}

/// Check if a kernel version is a queue (ends with -queue)
#[must_use]
pub fn version_is_queue(version: &str) -> bool {
    KernelVersion::from_str(version)
        .map(|v| v.is_queue())
        .unwrap_or(false)
}

/// Check if a version is a mainline kernel version
#[must_use]
pub fn version_is_mainline(version: &str) -> bool {
    KernelVersion::from_str(version)
        .map(|v| v.is_mainline())
        .unwrap_or(false)
}

/// Extract the "major" portion of a kernel version string
#[must_use]
pub fn kernel_version_major(version: &str) -> String {
    KernelVersion::from_str(version)
        .map(|v| v.major_version())
        .unwrap_or_default()
}

/// Check if the major version components of two kernel versions match
#[must_use]
pub fn version_major_match(version1: &str, version2: &str) -> bool {
    match (
        KernelVersion::from_str(version1),
        KernelVersion::from_str(version2),
    ) {
        (Ok(v1), Ok(v2)) => v1.major_matches(&v2),
        _ => false,
    }
}

/// Get the RC number from a kernel version if present
#[must_use]
pub fn get_rc_number(version: &str) -> Option<u32> {
    KernelVersion::from_str(version).ok()?.rc_num
}

/// Compare two kernel versions
#[must_use]
pub fn compare_kernel_versions(version1: &str, version2: &str) -> Ordering {
    // Fast path: exact same version
    if version1 == version2 {
        return Ordering::Equal;
    }

    match (
        KernelVersion::from_str(version1),
        KernelVersion::from_str(version2),
    ) {
        (Ok(v1), Ok(v2)) => v1.cmp(&v2),
        _ => version1.cmp(version2), // Fallback to string comparison
    }
}

#[cfg(test)]
mod tests {
    use crate::version_utils;
//    use super::*;

    #[test]
    fn test_version_is_mainline() {
        assert!(version_utils::version_is_mainline("5.4"));
        assert!(version_utils::version_is_mainline("4.19"));
        assert!(version_utils::version_is_mainline("2.6.39"));
        assert!(version_utils::version_is_mainline("5.4-rc1"));
        assert!(!version_utils::version_is_mainline("5.4.123"));
        assert!(!version_utils::version_is_mainline("5.4-queue"));
        assert!(!version_utils::version_is_mainline("next"));
        assert!(!version_utils::version_is_mainline("0"));
        assert!(!version_utils::version_is_mainline("2.6.39.12"));
    }

    #[test]
    fn test_version_is_rc() {
        assert!(version_utils::version_is_rc("5.4-rc1"));
        assert!(version_utils::version_is_rc("6.5-rc"));
        assert!(version_utils::version_is_rc("2.6.12.13-rc1"));
        assert!(!version_utils::version_is_rc("5.4"));
        assert!(!version_utils::version_is_rc("5.4.123"));
        assert!(!version_utils::version_is_rc("2.6.12.13"));
    }

    #[test]
    fn test_version_is_queue() {
        assert!(version_utils::version_is_queue("5.4-queue"));
        assert!(version_utils::version_is_queue("6.5-queue"));
        assert!(!version_utils::version_is_queue("5.4"));
        assert!(!version_utils::version_is_queue("5.4.123"));
    }
}
