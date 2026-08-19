//! `wcm set <name> <field>` — upsert (or `--delete`) one field of an existing item.

use serde::Serialize;
use wcm_core::item::{validate_field_name, Field, Item};
use wcm_core::vault::now_rfc3339;
use wcm_core::{Error, Result};

use crate::cli::SetArgs;
use crate::commands::add::is_interactive;
use crate::context::Ctx;
use crate::secrets::resolve_secret;

#[derive(Serialize)]
struct SetReport {
    name: String,
    field: String,
    action: &'static str,
}

pub fn run(ctx: &Ctx, args: &SetArgs) -> Result<()> {
    validate_field_name(&args.field)?;
    let new_field = if args.delete {
        None
    } else {
        let input = resolve_secret(
            &args.secret,
            &ctx.prompter,
            &format!("Value for {}", args.field),
            true,
            is_interactive(&args.secret),
        )?;
        Some(Field {
            value: input.into_value(false),
            secret: !args.public,
        })
    };
    let action = if new_field.is_some() {
        "set"
    } else {
        "deleted"
    };

    let mut v = ctx.unlock("set field")?;
    let now = now_rfc3339();
    v = v.map_body(|b| {
        b.update(&args.name, |it| {
            apply(it, &args.name, &args.field, new_field, &now)
        })
    })?;
    ctx.save(&mut v)?;

    if ctx.out.json {
        return ctx.out.json(&SetReport {
            name: args.name.clone(),
            field: args.field.clone(),
            action,
        });
    }
    let verb = if action == "set" { "Set" } else { "Deleted" };
    ctx.out
        .notice(&format!("{verb} {}.{}", args.name, args.field));
    Ok(())
}

/// Sets or deletes `field` on `item`; deleting a missing field is `NotFound`.
fn apply(item: Item, name: &str, field: &str, new: Option<Field>, now: &str) -> Result<Item> {
    match new {
        Some(f) => Ok(item.with_field(field, f).touched(now)),
        None if item.fields.contains_key(field) => Ok(item.without_field(field).touched(now)),
        None => Err(Error::NotFound(format!("item {name} has no field {field}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{FieldValue, ItemKind};

    const NOW: &str = "2026-01-01T00:00:00Z";
    const LATER: &str = "2026-02-02T00:00:00Z";

    #[test]
    fn apply_sets_and_deletes() {
        let it =
            Item::new("a", ItemKind::Login, NOW).with_field("password", Field::secret_text("pw"));
        let set = apply(
            it.clone(),
            "a",
            "username",
            Some(Field::public_text("u")),
            LATER,
        )
        .expect("set");
        assert_eq!(set.fields["username"].value, FieldValue::Text("u".into()));
        assert_eq!(set.updated, LATER);
        let del = apply(set, "a", "username", None, LATER).expect("del");
        assert!(!del.fields.contains_key("username"));
        assert!(matches!(
            apply(it, "a", "username", None, LATER),
            Err(Error::NotFound(m)) if m.contains("no field username")
        ));
    }
}
