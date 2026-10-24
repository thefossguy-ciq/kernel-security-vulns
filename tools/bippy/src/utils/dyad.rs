// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::Result;
use cve_utils::dyad_core;

/// Run the dyad engine to get version range information.
///
/// The engine runs in-process (`cve_utils::dyad_core`); the returned string
/// is the canonical output the dyad tool prints, so the parsing done by
/// callers is unchanged.
pub fn run_dyad(git_shas: &[String], vulnerable_shas: &[String]) -> Result<String> {
    let result = dyad_core::run(git_shas, vulnerable_shas)?;
    Ok(dyad_core::format_output(&result))
}
