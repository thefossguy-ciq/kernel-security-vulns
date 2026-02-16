// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

/// Strip commit text to only keep the relevant parts
/// Removes Signed-off-by and other tags from the commit message
pub fn strip_commit_text(text: &str, tags: &[String]) -> String {
    let mut result =
        String::from("In the Linux kernel, the following vulnerability has been resolved:\n\n");

    // Pre-compute lowercase tag patterns once to avoid repeated allocations
    let tag_patterns: Vec<String> = tags
        .iter()
        .map(|tag| format!("{}:", tag.to_lowercase()))
        .collect();

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
        let trimmed_lower = line.trim().to_lowercase();

        // Check against pre-computed lowercase tag patterns
        let is_tag_line = tag_patterns
            .iter()
            .any(|pattern| trimmed_lower.starts_with(pattern));

        if !is_tag_line {
            result.push_str(line);
            result.push('\n');
        }

        i += 1;
    }

    // Trim trailing whitespace and ensure exactly one newline at the end
    result.trim_end().to_string() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags() -> Vec<String> {
        vec![
            "Signed-off-by".to_string(),
            "Reviewed-by".to_string(),
            "Acked-by".to_string(),
            "Cc".to_string(),
        ]
    }

    #[test]
    fn test_strip_empty_commit_text() {
        let result = strip_commit_text("", &tags());
        assert!(result.starts_with("In the Linux kernel"));
        // Just the prefix, no commit content
        assert_eq!(
            result,
            "In the Linux kernel, the following vulnerability has been resolved:\n"
        );
    }

    #[test]
    fn test_strip_all_tag_lines() {
        let text = "Fix a bug\n\nSigned-off-by: Someone <s@e.com>\nReviewed-by: Other <o@e.com>";
        let result = strip_commit_text(text, &tags());
        assert!(result.contains("Fix a bug"));
        assert!(!result.contains("Signed-off-by"));
        assert!(!result.contains("Reviewed-by"));
    }

    #[test]
    fn test_strip_tags_mixed_case() {
        let text = "Fix a bug\n\nsigned-off-by: Someone <s@e.com>\nSIGNED-OFF-BY: Other <o@e.com>";
        let result = strip_commit_text(text, &tags());
        assert!(result.contains("Fix a bug"));
        assert!(!result.contains("signed-off-by"));
        assert!(!result.contains("SIGNED-OFF-BY"));
    }

    #[test]
    fn test_strip_no_tags_preserves_full_text() {
        let text = "Fix a bug\n\nThis is a detailed description of the fix.\nIt spans multiple lines.";
        let result = strip_commit_text(text, &tags());
        assert!(result.contains("Fix a bug"));
        assert!(result.contains("This is a detailed description of the fix."));
        assert!(result.contains("It spans multiple lines."));
    }
}
