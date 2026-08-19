//! `wcm get <name>...` — print one field of one or more items (stdout, file or clipboard).

use std::path::Path;

use serde::Serialize;
use wcm_core::item::FieldValue;
use wcm_core::vault::VaultBody;
use wcm_core::{Error, Result};

use crate::cli::GetArgs;
use crate::clip;
use crate::context::Ctx;

/// One resolved value.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub field: String,
    pub value: FieldValue,
    pub secret: bool,
}

pub fn run(ctx: &Ctx, args: &GetArgs) -> Result<()> {
    let single_only = args.clip || args.out_file.is_some();
    if single_only && args.names.len() != 1 {
        return Err(Error::Invalid(
            "--clip and --out-file accept exactly one item name".into(),
        ));
    }
    let v = ctx.unlock("get item")?;
    let entries = resolve_all(&v.body, &args.names, args.field.as_deref())?;

    // --clip / --out-file never print the value (not even as JSON).
    if let Some(first) = entries.first().filter(|_| single_only) {
        if args.clip {
            let text = first.value.as_text().ok_or_else(|| {
                Error::Invalid("value is binary; it cannot be copied to the clipboard".into())
            })?;
            return clip::copy_and_notify(&ctx.out, text, args.clip_timeout);
        }
        if let Some(path) = &args.out_file {
            return write_file(ctx, path, first.value.as_bytes());
        }
    }
    if ctx.out.json {
        return ctx.out.json(&entries);
    }
    let newline = !(args.raw || args.no_newline);
    if ctx.out.stdout_is_tty() && entries.iter().any(|e| is_binary(&e.value)) {
        return Err(Error::Invalid(
            "refusing to write binary to a terminal; use --out-file or pipe".into(),
        ));
    }
    for e in &entries {
        ctx.out.bytes(e.value.as_bytes())?;
        if newline {
            ctx.out.bytes(b"\n")?;
        }
    }
    Ok(())
}

/// Resolves every `(name, field)` pair before anything is printed.
pub fn resolve_all(body: &VaultBody, names: &[String], field: Option<&str>) -> Result<Vec<Entry>> {
    names.iter().map(|n| resolve_one(body, n, field)).collect()
}

/// Looks up `field` (or the kind's primary field) of item `name`.
pub fn resolve_one(body: &VaultBody, name: &str, field: Option<&str>) -> Result<Entry> {
    let item = body
        .get(name)
        .ok_or_else(|| Error::NotFound(name.to_string()))?;
    let field_name = field.unwrap_or_else(|| item.kind.primary_field());
    let f = item
        .fields
        .get(field_name)
        .ok_or_else(|| Error::NotFound(format!("item {name} has no field {field_name}")))?;
    Ok(Entry {
        name: name.to_string(),
        field: field_name.to_string(),
        value: f.value.clone(),
        secret: f.secret,
    })
}

/// Bytes that are not valid UTF-8.
fn is_binary(v: &FieldValue) -> bool {
    v.is_binary() && v.as_text().is_none()
}

fn write_file(ctx: &Ctx, path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
    ctx.out.notice(&format!(
        "wrote {} bytes to {}",
        bytes.len(),
        path.display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{Field, Item, ItemKind};

    fn body() -> VaultBody {
        let it = Item::new("a", ItemKind::Login, "2026-01-01T00:00:00Z")
            .with_field("password", Field::secret_text("pw"))
            .with_field("username", Field::public_text("alice"))
            .with_field("blob", Field::secret_bytes(vec![0xff]));
        VaultBody::default().insert(it, false).expect("insert")
    }

    #[test]
    fn resolves_primary_and_named_fields() {
        let b = body();
        let e = resolve_one(&b, "a", None).expect("primary");
        assert_eq!(e.field, "password");
        assert_eq!(e.value, FieldValue::Text("pw".into()));
        assert!(e.secret);
        let e = resolve_one(&b, "a", Some("username")).expect("named");
        assert_eq!(e.value.as_text(), Some("alice"));
        assert!(!e.secret);
    }

    #[test]
    fn missing_item_or_field_is_not_found() {
        let b = body();
        assert!(matches!(
            resolve_one(&b, "zz", None),
            Err(Error::NotFound(m)) if m == "zz"
        ));
        assert!(matches!(
            resolve_one(&b, "a", Some("nope")),
            Err(Error::NotFound(m)) if m.contains("no field nope")
        ));
        // resolve_all fails on the first missing one
        assert!(matches!(
            resolve_all(&b, &["a".into(), "zz".into()], None),
            Err(Error::NotFound(_))
        ));
        assert_eq!(
            resolve_all(&b, &["a".into(), "a".into()], Some("username"))
                .expect("all")
                .len(),
            2
        );
    }

    #[test]
    fn binary_detection() {
        assert!(is_binary(&FieldValue::Bytes(vec![0xff])));
        assert!(!is_binary(&FieldValue::Bytes(b"ok".to_vec())));
        assert!(!is_binary(&FieldValue::Text("x".into())));
    }
}
