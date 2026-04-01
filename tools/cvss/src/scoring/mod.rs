// SPDX-License-Identifier: GPL-2.0-only
//
// Re-export scoring modules from cve_utils shared library.

pub use cve_utils::cvss::formula;
pub use cve_utils::cvss::metrics;
pub use cve_utils::cvss::vector;
