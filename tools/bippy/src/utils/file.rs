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

/// Read a .message file if it exists
pub fn read_message_file(file_path: &Path) -> Result<Option<String>> {
    if file_path.exists() {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read message file at {}", file_path.display()))?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_message_file_exists() {
        // Create a temporary directory and file
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("test.message");

        let test_content = "This is a test message file content\nWith multiple lines";
        fs::write(&message_path, test_content).unwrap();

        // Test reading the file
        let result = read_message_file(&message_path).unwrap();
        assert_eq!(result, Some(test_content.to_string()));
    }

    #[test]
    fn test_read_message_file_not_exists() {
        // Test with a non-existent file
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("nonexistent.message");

        let result = read_message_file(&message_path).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_read_message_file_empty() {
        // Create an empty file
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("empty.message");

        fs::write(&message_path, "").unwrap();

        // Test reading empty file
        let result = read_message_file(&message_path).unwrap();
        assert_eq!(result, Some("".to_string()));
    }
}
