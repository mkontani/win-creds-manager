//! Plaintext JSON export/import model (used only with `--plaintext --i-know`
//! and for GUI/tooling interchange). Encrypted export reuses the vault format.

use serde::{Deserialize, Serialize};

use crate::item::{validate_field_name, validate_name, Item};
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

/// Control characters allowed inside free-form notes.
const NOTE_WHITESPACE: [char; 3] = ['\n', '\r', '\t'];

/// Renders untrusted text for an error message (escapes control characters).
fn quoted(s: &str) -> String {
    s.escape_debug().to_string()
}

/// Validates one item coming from an export file.
///
/// Import data is attacker-controlled: an item name, field key, tag or note may
/// otherwise carry terminal escape sequences (output forgery in `ls` / `show`)
/// or break invariants `wcm add` enforces. Every failure maps to
/// [`Error::Format`] — the *document* is malformed, not the user's command line.
pub fn validate_incoming(item: &Item) -> Result<()> {
    validate_name(&item.name)
        .map_err(|e| Error::Format(format!("invalid item name \"{}\": {e}", quoted(&item.name))))?;
    for key in item.fields.keys() {
        validate_field_name(key).map_err(|e| {
            Error::Format(format!(
                "item \"{}\": invalid field name \"{}\": {e}",
                quoted(&item.name),
                quoted(key)
            ))
        })?;
    }
    if item
        .notes
        .chars()
        .any(|c| c.is_control() && !NOTE_WHITESPACE.contains(&c))
    {
        return Err(Error::Format(format!(
            "item \"{}\": notes contain control characters",
            quoted(&item.name)
        )));
    }
    for tag in &item.tags {
        if tag.is_empty() || tag.chars().any(char::is_control) {
            return Err(Error::Format(format!(
                "item \"{}\": invalid tag \"{}\"",
                quoted(&item.name),
                quoted(tag)
            )));
        }
    }
    Ok(())
}

/// Merges `incoming` into `body` per `mode`, returning the new body and a report.
///
/// Every incoming item is validated first, so a malformed document changes
/// nothing.
pub fn merge(
    body: &VaultBody,
    incoming: &[Item],
    mode: MergeMode,
) -> Result<(VaultBody, MergeReport)> {
    for item in incoming {
        validate_incoming(item)?;
    }
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
    fn hostile_items_are_format_errors() {
        let body = VaultBody::default();
        let cases = vec![
            item("", "v"),
            item(&"x".repeat(201), "v"),
            item("a\u{1b}[2Kforged", "v"),
            item("/leading", "v"),
            item("a", "v").with_field("bad key", Field::secret_text("v")),
            item("a", "v").with_notes("line\u{1b}[31m"),
            Item::new("a", ItemKind::Password, "t").with_tags(vec!["ok\u{7}".into()]),
            Item::new("a", ItemKind::Password, "t").with_tags(vec![String::new()]),
        ];
        for it in cases {
            let name = it.name.clone();
            let e = merge(&body, std::slice::from_ref(&it), MergeMode::Merge)
                .expect_err("must be rejected");
            assert!(matches!(e, Error::Format(_)), "{name:?} -> {e:?}");
            // The message never carries the raw escape sequence.
            assert!(!e.to_string().contains('\u{1b}'), "{e}");
        }
        // Nothing is imported when a later item is malformed.
        let (b, _) = merge(&body, &[item("good", "v")], MergeMode::Merge).expect("ok");
        assert!(merge(
            &b,
            &[item("also-good", "v"), item("", "v")],
            MergeMode::Merge
        )
        .is_err());
    }

    #[test]
    fn legitimate_items_survive_validation() {
        let ok = item("github/token", "v")
            .with_notes("first line\nsecond\tline\r\n")
            .with_tags(vec!["work".into(), "日本語".into()]);
        validate_incoming(&ok).expect("valid");
        let (b, r) = merge(&VaultBody::default(), &[ok], MergeMode::Merge).expect("merge");
        assert_eq!(r.added, 1);
        assert!(b.get("github/token").is_some());
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
