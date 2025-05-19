// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use std::path::Path;

/// Reads the tags file from the script directory
pub fn read_tags_file(script_dir: &Path) -> Result<Vec<String>> {
    let tags_path = script_dir.join("tags");
    let content = std::fs::read_to_string(&tags_path)
        .with_context(|| format!("Failed to read tags file at {}", tags_path.display()))?;

    Ok(content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#')) // Added filter for comments
        .collect())
}

/// Read the UUID for the Linux kernel CVE team from a file
pub fn read_uuid(script_dir: &Path) -> Result<String> {
    let uuid_path = script_dir.join("linux.uuid");
    let content = std::fs::read_to_string(&uuid_path)
        .with_context(|| format!("Failed to read UUID file at {}", uuid_path.display()))?;

    let uuid = content.trim();
    if uuid.is_empty() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "UUID file is empty").into(),
        );
    }

    Ok(uuid.to_string())
}
