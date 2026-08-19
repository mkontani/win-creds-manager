//! Plaintext JSON export/import model (used only with `--plaintext --i-know`
//! and for GUI/tooling interchange). Encrypted export reuses the vault format.

use serde::{Deserialize, Serialize};

use crate::item::Item;
use crate::vault::VaultBody;
use crate::{Error, Result};

/// Export format version.
pub const PLAIN_EXPORT_VERSION: u8 = 1;

/// Plaintext export document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainExport {
    /// Format version (1).
    pub version: u8,
    /// RFC 3339 export time.
    pub exported: String,
    /// Items.
    pub items: Vec<Item>,
}

impl PlainExport {
    /// Builds an export from a body.
    pub fn from_body(body: &VaultBody, now: &str) -> PlainExport {
        PlainExport {
            version: PLAIN_EXPORT_VERSION,
            exported: now.to_string(),
            items: body.items.clone(),
        }
    }

    /// Pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Format(format!("export encode: {e}")))
    }

    /// Parses JSON produced by [`PlainExport::to_json`].
    pub fn from_json(s: &str) -> Result<PlainExport> {
        let e: PlainExport =
            serde_json::from_str(s).map_err(|e| Error::Format(format!("export decode: {e}")))?;
        if e.version != PLAIN_EXPORT_VERSION {
            return Err(Error::Format(format!(
                "unsupported export version {}",
                e.version
            )));
        }
        Ok(e)
    }
}

/// How to combine imported items with existing ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeMode {
    /// Keep existing items; add new ones; skip conflicting names.
    Merge,
    /// Overwrite items with the same name.
    Overwrite,
    /// Drop all existing items first.
    Replace,
}

/// Result of a merge.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize)]
pub struct MergeReport {
    /// Items added.
    pub added: usize,
    /// Items overwritten.
    pub overwritten: usize,
    /// Items skipped due to name conflict.
    pub skipped: usize,
}

/// Merges `incoming` into `body` per `mode`, returning the new body and a report.
pub fn merge(
    body: &VaultBody,
    incoming: &[Item],
    mode: MergeMode,
) -> Result<(VaultBody, MergeReport)> {
    let mut out = match mode {
        MergeMode::Replace => VaultBody {
            items: Vec::new(),
            settings: body.settings.clone(),
        },
        _ => body.clone(),
    };
    let mut report = MergeReport::default();
    for item in incoming {
        let exists = out.get(&item.name).is_some();
        match (exists, mode) {
            (true, MergeMode::Merge) => report.skipped += 1,
            (true, MergeMode::Overwrite) => {
                out = out.insert(item.clone(), true)?;
                report.overwritten += 1;
            }
            _ => {
                out = out.insert(item.clone(), true)?;
                report.added += 1;
            }
        }
    }
    Ok((out, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Field, ItemKind};

    fn item(name: &str, v: &str) -> Item {
        Item::new(name, ItemKind::Password, "t").with_field("password", Field::secret_text(v))
    }

    #[test]
    fn json_roundtrip_with_binary() {
        let body = VaultBody::default()
            .insert(
                item("a", "1").with_field("blob", Field::secret_bytes(vec![0, 255])),
                false,
            )
            .expect("i");
        let e = PlainExport::from_body(&body, "2026-01-01T00:00:00Z");
        let json = e.to_json().expect("json");
        assert!(json.contains("\"b64\": \"AP8=\""));
        let back = PlainExport::from_json(&json).expect("parse");
        assert_eq!(back, e);
        assert!(matches!(
            PlainExport::from_json("{bad"),
            Err(Error::Format(_))
        ));
        assert!(matches!(
            PlainExport::from_json("{\"version\":9,\"exported\":\"x\",\"items\":[]}"),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn merge_modes() {
        let body = VaultBody::default()
            .insert(item("a", "old"), false)
            .expect("i");
        let incoming = vec![item("a", "new"), item("b", "b")];

        let (m, r) = merge(&body, &incoming, MergeMode::Merge).expect("merge");
        assert_eq!(
            r,
            MergeReport {
                added: 1,
                overwritten: 0,
                skipped: 1
            }
        );
        assert_eq!(
            m.get("a")
                .and_then(|i| i.primary())
                .and_then(|f| f.value.as_text()),
            Some("old")
        );
        assert_eq!(m.items.len(), 2);

        let (o, r) = merge(&body, &incoming, MergeMode::Overwrite).expect("merge");
        assert_eq!(
            r,
            MergeReport {
                added: 1,
                overwritten: 1,
                skipped: 0
            }
        );
        assert_eq!(
            o.get("a")
                .and_then(|i| i.primary())
                .and_then(|f| f.value.as_text()),
            Some("new")
        );

        let (rep, r) = merge(&body, &incoming[1..], MergeMode::Replace).expect("merge");
        assert_eq!(
            r,
            MergeReport {
                added: 1,
                overwritten: 0,
                skipped: 0
            }
        );
        assert!(rep.get("a").is_none());
        assert_eq!(rep.items.len(), 1);
        assert_eq!(body.items.len(), 1, "original untouched");
    }
}
