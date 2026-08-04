// SPDX-License-Identifier: GPL-2.0-only
//
// Reading and writing the .cvss files that sit next to each published CVE.
//
// A .cvss file has a header of one or more "CNA_ID VECTOR" lines, optionally
// followed by a blank line and the rationale for the score:
//
//     f4215fc3-5b6b-47ff-a258-f7189bd81038 CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
//
//     AV:L - Despite living in net/sctp/, `proc_sctp_do_auth()` is a procfs
//         sysctl ->proc_handler that no received SCTP packet ever invokes.
//     AC:L - ...
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::NamedTempFile;

use super::formula::{compute_base_score, ScoreResult};
use super::metrics::CvssMetrics;
use super::rationale::Rationale;
use super::vector::{format_vector, parse_vector};

/// One scored vector, attributed to the CNA that assigned it.
#[derive(Debug, Clone, PartialEq)]
pub struct CvssEntry {
    pub cna_id: String,
    pub metrics: CvssMetrics,
}

impl CvssEntry {
    pub fn vector_string(&self) -> String {
        format_vector(&self.metrics)
    }

    pub fn score(&self) -> ScoreResult {
        compute_base_score(&self.metrics)
    }
}

/// The parsed contents of a .cvss file.
#[derive(Debug, Clone, PartialEq)]
pub struct CvssFile {
    pub entries: Vec<CvssEntry>,
    pub rationale: Option<Rationale>,
}

impl CvssFile {
    pub fn new(entries: Vec<CvssEntry>, rationale: Option<Rationale>) -> Self {
        Self { entries, rationale }
    }

    pub fn read(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .context(format!("failed to read {}", path.display()))?;
        Self::parse(&content).context(format!("invalid CVSS file {}", path.display()))
    }

    /// Parse the file contents. The header runs up to the first blank line;
    /// everything after it is the rationale.
    pub fn parse(content: &str) -> Result<Self> {
        // A file that came back through an editor with CRLF endings has no
        // literal "\n\n", which would put the whole rationale in the header
        // and make the file unreadable rather than merely ugly.
        let normalized;
        let content = if content.contains('\r') {
            normalized = content.replace("\r\n", "\n");
            normalized.as_str()
        } else {
            content
        };

        let (header, body) = match content.split_once("\n\n") {
            Some((header, body)) => (header, Some(body)),
            None => (content, None),
        };

        let mut entries = Vec::new();
        for line in header.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (cna_id, vector) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| anyhow!("expected 'CNA_ID VECTOR', got: '{line}'"))?;

            entries.push(CvssEntry {
                cna_id: cna_id.trim().to_string(),
                metrics: parse_vector(vector.trim())?,
            });
        }

        if entries.is_empty() {
            return Err(anyhow!("no CVSS vector found"));
        }

        let rationale = match body {
            Some(body) if !body.trim().is_empty() => Some(Rationale::parse(body)?),
            _ => None,
        };

        Ok(Self { entries, rationale })
    }

    /// Render to the on-disk form. Always ends with a newline.
    pub fn render(&self) -> String {
        let mut out = String::new();

        for entry in &self.entries {
            out.push_str(&entry.cna_id);
            out.push(' ');
            out.push_str(&entry.vector_string());
            out.push('\n');
        }

        if let Some(rationale) = &self.rationale {
            out.push('\n');
            out.push_str(&rationale.render());
        }

        out
    }

    /// Replace the file atomically, so a write that fails part way through
    /// cannot leave a truncated file where a rationale used to be.
    pub fn write(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = NamedTempFile::new_in(dir)
            .context(format!("failed to create a temporary file in {}", dir.display()))?;

        tmp.write_all(self.render().as_bytes())
            .context(format!("failed to write {}", path.display()))?;
        tmp.as_file()
            .sync_all()
            .context(format!("failed to flush {}", path.display()))?;

        // NamedTempFile is 0600; .cvss files are world readable like the rest
        // of the tree.
        let mode = fs::metadata(path).map_or(0o644, |m| m.permissions().mode());
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))
            .context(format!("failed to set permissions on {}", path.display()))?;

        tmp.persist(path)
            .map_err(|e| anyhow!("failed to replace {}: {e}", path.display()))?;

        Ok(())
    }

    /// Check that the rationale, if any, describes the scored vector.
    ///
    /// With more than one entry there is no single vector to check against,
    /// so the rationale is accepted as-is.
    pub fn validate(&self) -> Result<()> {
        let Some(rationale) = &self.rationale else {
            return Ok(());
        };

        if let [entry] = self.entries.as_slice() {
            rationale.validate(&entry.metrics)?;
        }

        rationale.checked_scenario_value()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvss::rationale::MetricKey;

    const CNA: &str = "f4215fc3-5b6b-47ff-a258-f7189bd81038";
    const VECTOR: &str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";

    fn rationale_text() -> String {
        [
            "AV:L - reachable only through local file I/O",
            "AC:L - fully deterministic, no race to win",
            "PR:L - an unprivileged local user suffices",
            "UI:N - no action from any other user is needed",
            "S:U - stays inside the kernel's own security authority",
            "C:N - the fault happens before any data is returned",
            "I:H - an attacker-chosen modification of protected state",
            "A:H - panics outright on panic_on_oops builds",
        ]
        .join("\n")
    }

    fn with_rationale() -> String {
        format!("{CNA} {VECTOR}\n\n{}\n", rationale_text())
    }

    #[test]
    fn parses_legacy_header_only_file() {
        let file = CvssFile::parse(&format!("{CNA} {VECTOR}\n")).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].cna_id, CNA);
        assert_eq!(file.entries[0].vector_string(), VECTOR);
        assert!(file.rationale.is_none());
        assert_eq!(file.entries[0].score().score, 7.1);
    }

    #[test]
    fn parses_header_and_rationale() {
        let file = CvssFile::parse(&with_rationale()).unwrap();
        assert_eq!(file.entries.len(), 1);
        let rationale = file.rationale.as_ref().unwrap();
        let Rationale::PerMetric(entries) = rationale else {
            panic!("expected per-metric rationale");
        };
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[0].key, MetricKey::Av);
        file.validate().unwrap();
    }

    #[test]
    fn skips_comments_in_the_header() {
        let file = CvssFile::parse(&format!("# a note\n{CNA} {VECTOR}\n")).unwrap();
        assert_eq!(file.entries.len(), 1);
    }

    #[test]
    fn round_trips() {
        let file = CvssFile::parse(&with_rationale()).unwrap();
        let rendered = file.render();
        assert_eq!(CvssFile::parse(&rendered).unwrap(), file);
        assert_eq!(CvssFile::parse(&rendered).unwrap().render(), rendered);
    }

    #[test]
    fn render_keeps_the_first_line_intact() {
        let rendered = CvssFile::parse(&with_rationale()).unwrap().render();
        assert_eq!(rendered.lines().next().unwrap(), format!("{CNA} {VECTOR}"));
        assert_eq!(rendered.lines().nth(1).unwrap(), "");
    }

    #[test]
    fn parses_crlf_files() {
        // With CRLF there is no literal "\n\n", so without normalising the
        // rationale lines would be read as vector headers and the whole file
        // - score included - would be rejected.
        let file = CvssFile::parse(&with_rationale().replace('\n', "\r\n")).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].vector_string(), VECTOR);
        assert!(file.rationale.is_some());
        assert_eq!(file, CvssFile::parse(&with_rationale()).unwrap());
        file.validate().unwrap();
    }

    #[test]
    fn crlf_does_not_merge_prose_paragraphs() {
        let content = format!("{CNA} {VECTOR}\n\nFirst paragraph.\n\nSecond paragraph.\n");
        let file = CvssFile::parse(&content.replace('\n', "\r\n")).unwrap();
        let Some(Rationale::Prose(paragraphs)) = &file.rationale else {
            panic!("expected prose rationale");
        };
        assert_eq!(paragraphs.len(), 2);
    }

    #[test]
    fn write_leaves_the_old_file_alone_when_it_cannot_finish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CVE-2026-00001.cvss");
        let file = CvssFile::parse(&with_rationale()).unwrap();
        file.write(&path).unwrap();

        // Writing into a directory that no longer exists must fail before
        // anything touches the destination.
        let gone = dir.path().join("gone").join("CVE-2026-00002.cvss");
        assert!(file.write(&gone).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), file.render());
    }

    #[test]
    fn write_keeps_the_file_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CVE-2026-00001.cvss");
        CvssFile::parse(&with_rationale())
            .unwrap()
            .write(&path)
            .unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o044, 0o044, "mode is {mode:o}, not world readable");
    }

    #[test]
    fn rejects_empty_file() {
        assert!(CvssFile::parse("").is_err());
        assert!(CvssFile::parse("# only a comment\n").is_err());
    }

    #[test]
    fn rejects_malformed_header() {
        assert!(CvssFile::parse("just-one-field\n").is_err());
        assert!(CvssFile::parse(&format!("{CNA} CVSS:3.1/AV:X\n")).is_err());
    }

    #[test]
    fn validate_rejects_rationale_that_disagrees_with_the_vector() {
        let content = format!(
            "{CNA} CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H\n\n{}\n",
            rationale_text()
        );
        let file = CvssFile::parse(&content).unwrap();
        assert!(file.validate().is_err());
    }

    #[test]
    fn validate_accepts_a_file_with_no_rationale() {
        CvssFile::parse(&format!("{CNA} {VECTOR}\n"))
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn writes_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CVE-2026-00001.cvss");

        let file = CvssFile::parse(&with_rationale()).unwrap();
        file.write(&path).unwrap();

        assert_eq!(CvssFile::read(&path).unwrap(), file);
        assert_eq!(fs::read_to_string(&path).unwrap(), file.render());
    }
}
