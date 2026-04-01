// SPDX-License-Identifier: GPL-2.0-only
//
// Insert/update CVSS metrics in CVE JSON files.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::ser::{PrettyFormatter, Serializer};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Build the metrics JSON Value to insert into a CVE record.
pub fn build_metrics_value(vector: &str, score: f64, severity: &str) -> Value {
    serde_json::json!([
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": vector,
                "baseScore": score,
                "baseSeverity": severity
            }
        }
    ])
}

/// Serialize a serde_json::Value with 3-space indentation (matching bippy convention).
fn serialize_json_3space(value: &Value) -> Result<String> {
    let formatter = PrettyFormatter::with_indent(b"   ");
    let mut output = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut output, formatter);

    value
        .serialize(&mut serializer)
        .map_err(|e| anyhow!("error serializing JSON: {e}"))?;

    let mut json_string =
        String::from_utf8(output).map_err(|e| anyhow!("error converting JSON to string: {e}"))?;

    if !json_string.ends_with('\n') {
        json_string.push('\n');
    }

    Ok(json_string)
}

/// Insert or update CVSS metrics in a CVE JSON file.
pub fn write_metrics(json_path: &Path, vector: &str, score: f64, severity: &str) -> Result<()> {
    let content =
        fs::read_to_string(json_path).context(format!("failed to read {}", json_path.display()))?;

    let mut root: Value =
        serde_json::from_str(&content).context(format!("invalid JSON in {}", json_path.display()))?;

    let cna = root
        .get_mut("containers")
        .and_then(|c| c.get_mut("cna"))
        .ok_or_else(|| anyhow!("missing containers.cna in {}", json_path.display()))?;

    let cna_obj = cna
        .as_object_mut()
        .ok_or_else(|| anyhow!("containers.cna is not an object"))?;

    let metrics = build_metrics_value(vector, score, severity);
    cna_obj.insert("metrics".to_string(), metrics);

    let json_string = serialize_json_3space(&root)?;
    fs::write(json_path, &json_string)
        .context(format!("failed to write {}", json_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_metrics_structure() {
        let metrics = build_metrics_value(
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            5.5,
            "MEDIUM",
        );

        assert!(metrics.is_array());
        let arr = metrics.as_array().unwrap();
        assert_eq!(arr.len(), 1);

        let cvss = &arr[0]["cvssV3_1"];
        assert_eq!(cvss["version"], "3.1");
        assert_eq!(
            cvss["vectorString"],
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
        );
        assert_eq!(cvss["baseScore"], 5.5);
        assert_eq!(cvss["baseSeverity"], "MEDIUM");
    }

    #[test]
    fn serialize_3space_indentation() {
        let value = serde_json::json!({"a": {"b": 1}});
        let output = serialize_json_3space(&value).unwrap();
        assert!(output.contains("   "), "should use 3-space indentation");
        assert!(output.ends_with('\n'), "should end with newline");
    }

    #[test]
    fn write_metrics_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("test.json");

        let original = serde_json::json!({
            "containers": {
                "cna": {
                    "title": "test",
                    "descriptions": [{"lang": "en", "value": "test desc"}]
                }
            },
            "cveMetadata": {"cveID": "CVE-2026-99999", "state": "PUBLISHED"},
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0"
        });
        fs::write(&json_path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

        write_metrics(
            &json_path,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            "CRITICAL",
        )
        .unwrap();

        let written = fs::read_to_string(&json_path).unwrap();
        let parsed: Value = serde_json::from_str(&written).unwrap();

        let metrics = &parsed["containers"]["cna"]["metrics"];
        assert!(metrics.is_array());
        assert_eq!(metrics[0]["cvssV3_1"]["baseScore"], 9.8);
        assert_eq!(metrics[0]["cvssV3_1"]["baseSeverity"], "CRITICAL");

        // Original fields preserved
        assert_eq!(parsed["containers"]["cna"]["title"], "test");
        assert_eq!(parsed["cveMetadata"]["cveID"], "CVE-2026-99999");

        // 3-space indentation
        assert!(written.contains("   \"title\""));
        assert!(written.ends_with('\n'));
    }

    #[test]
    fn write_metrics_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("test.json");

        let original = serde_json::json!({
            "containers": {
                "cna": {
                    "title": "test",
                    "metrics": [{"cvssV3_1": {"baseScore": 1.0}}]
                }
            },
            "cveMetadata": {"cveID": "CVE-2026-99999"},
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0"
        });
        fs::write(&json_path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

        write_metrics(
            &json_path,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            7.8,
            "HIGH",
        )
        .unwrap();

        let parsed: Value =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(parsed["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"], 7.8);
    }
}
