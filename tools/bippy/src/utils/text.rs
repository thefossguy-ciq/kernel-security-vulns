// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

/// Strip commit text to only keep the relevant parts
/// Removes Signed-off-by and other tags from the commit message
pub fn strip_commit_text(text: &str, tags: &[String]) -> String {
    let mut result =
        String::from("In the Linux kernel, the following vulnerability has been resolved:\n\n");

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

    // Add the rest of the message, skipping only lines that exactly start with a tag
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip only if the line actually starts with a recognized tag
        let is_tag_line = tags.iter().any(|tag| {
            let tag_with_colon = format!("{tag}:");
            trimmed
                .to_lowercase()
                .starts_with(&tag_with_colon.to_lowercase())
        });

        if !is_tag_line {
            result.push_str(line);
            result.push('\n');
        }

        i += 1;
    }

    // Trim trailing whitespace and ensure exactly one newline at the end
    result.trim_end().to_string() + "\n"
}