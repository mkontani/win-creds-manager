//! `wcm show <name>` — metadata and fields of one item (secrets masked unless `--reveal`).

use std::collections::BTreeMap;

use serde::Serialize;
use wcm_core::item::{FieldValue, Item};
use wcm_core::{Error, Result};

use crate::cli::ShowArgs;
use crate::context::Ctx;
use crate::output::mask;

/// Placeholder for masked secret values in JSON.
pub const MASKED: &str = "•••";

#[derive(Serialize, Debug, PartialEq, Eq)]
struct FieldView {
    value: serde_json::Value,
    secret: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct ItemView {
    id: String,
    name: String,
    kind: &'static str,
    fields: BTreeMap<String, FieldView>,
    notes: String,
    tags: Vec<String>,
    created: String,
    updated: String,
}

pub fn run(ctx: &Ctx, args: &ShowArgs) -> Result<()> {
    let v = ctx.unlock("show item")?;
    let item = v
        .body
        .get(&args.name)
        .ok_or_else(|| Error::NotFound(args.name.clone()))?;
    if ctx.out.json {
        return ctx.out.json(&view(item, args.reveal)?);
    }
    print_human(ctx, item, args.reveal)
}

fn view(item: &Item, reveal: bool) -> Result<ItemView> {
    let fields = item
        .fields
        .iter()
        .map(|(k, f)| {
            let value = if f.secret && !reveal {
                serde_json::Value::String(MASKED.into())
            } else {
                serde_json::to_value(&f.value)
                    .map_err(|e| Error::Other(format!("json encode: {e}")))?
            };
            Ok((
                k.clone(),
                FieldView {
                    value,
                    secret: f.secret,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(ItemView {
        id: item.id_hex(),
        name: item.name.clone(),
        kind: item.kind.as_str(),
        fields,
        notes: item.notes.clone(),
        tags: item.tags.clone(),
        created: item.created.clone(),
        updated: item.updated.clone(),
    })
}

fn print_human(ctx: &Ctx, item: &Item, reveal: bool) -> Result<()> {
    ctx.out.line(&format!("name:    {}", item.name))?;
    ctx.out.line(&format!("kind:    {}", item.kind))?;
    ctx.out.line(&format!("id:      {}", item.id_hex()))?;
    ctx.out.line(&format!("created: {}", item.created))?;
    ctx.out.line(&format!("updated: {}", item.updated))?;
    if !item.tags.is_empty() {
        ctx.out
            .line(&format!("tags:    {}", item.tags.join(", ")))?;
    }
    if !item.notes.is_empty() {
        ctx.out.line(&format!("notes:   {}", item.notes))?;
    }
    ctx.out.line("fields:")?;
    for (k, f) in &item.fields {
        let shown = display_value(&f.value, f.secret, reveal);
        if shown.contains('\n') {
            ctx.out.line(&format!("  {k}:"))?;
            for l in shown.lines() {
                ctx.out.line(&format!("    {l}"))?;
            }
        } else {
            ctx.out.line(&format!("  {k}: {shown}"))?;
        }
    }
    Ok(())
}

/// Human rendering of one field value.
fn display_value(v: &FieldValue, secret: bool, reveal: bool) -> String {
    match v.as_text() {
        Some(t) if !v.is_binary() || reveal => {
            if secret && !reveal {
                mask(t.chars().count())
            } else {
                t.to_string()
            }
        }
        _ => format!("<{} bytes>", v.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{Field, ItemKind};

    fn item() -> Item {
        Item::new("a", ItemKind::Login, "2026-01-01T00:00:00Z")
            .with_field("password", Field::secret_text("pw"))
            .with_field("username", Field::public_text("alice"))
            .with_field("blob", Field::secret_bytes(vec![0xff, 0]))
            .with_tags(vec!["t".into()])
            .with_notes("n")
    }

    #[test]
    fn json_view_masks_unless_reveal() {
        let v = view(&item(), false).expect("view");
        assert_eq!(v.fields["password"].value, serde_json::json!(MASKED));
        assert!(v.fields["password"].secret);
        assert_eq!(v.fields["username"].value, serde_json::json!("alice"));
        assert_eq!(v.fields["blob"].value, serde_json::json!(MASKED));
        assert_eq!(v.kind, "login");
        assert_eq!(v.tags, vec!["t".to_string()]);
        assert_eq!(v.id.len(), 32);

        let v = view(&item(), true).expect("view");
        assert_eq!(v.fields["password"].value, serde_json::json!("pw"));
        assert_eq!(v.fields["blob"].value, serde_json::json!({"b64": "/wA="}));
    }

    #[test]
    fn human_value_rendering() {
        let t = FieldValue::Text("secret".into());
        assert_eq!(display_value(&t, true, false), mask(6));
        assert_eq!(display_value(&t, true, true), "secret");
        assert_eq!(display_value(&t, false, false), "secret");
        let b = FieldValue::Bytes(vec![0xff, 0, 1]);
        assert_eq!(display_value(&b, true, false), "<3 bytes>");
        assert_eq!(display_value(&b, true, true), "<3 bytes>");
        assert_eq!(display_value(&b, false, false), "<3 bytes>");
        let utf8 = FieldValue::Bytes(b"abc".to_vec());
        assert_eq!(display_value(&utf8, true, false), "<3 bytes>");
        assert_eq!(display_value(&utf8, true, true), "abc");
    }
}
