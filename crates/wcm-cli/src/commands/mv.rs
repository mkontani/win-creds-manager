//! `wcm mv <old> <new>` — rename an item (`-f` replaces an existing target).

use serde::Serialize;
use wcm_core::item::validate_name;
use wcm_core::vault::{now_rfc3339, VaultBody};
use wcm_core::{Error, Result};

use crate::cli::MvArgs;
use crate::context::Ctx;

#[derive(Serialize)]
struct MvReport {
    old: String,
    new: String,
}

pub fn run(ctx: &Ctx, args: &MvArgs) -> Result<()> {
    validate_name(&args.new)?;
    let mut v = ctx.unlock("rename item")?;
    let now = now_rfc3339();
    v = v.map_body(|b| rename(b, &args.old, &args.new, args.force, &now))?;
    ctx.save(&mut v)?;
    if ctx.out.json {
        return ctx.out.json(&MvReport {
            old: args.old.clone(),
            new: args.new.clone(),
        });
    }
    ctx.out
        .notice(&format!("Renamed {} -> {}", args.old, args.new));
    Ok(())
}

/// Renames `old` to `new`; with `force` an existing `new` is removed first.
fn rename(body: &VaultBody, old: &str, new: &str, force: bool, now: &str) -> Result<VaultBody> {
    if body.get(old).is_none() {
        return Err(Error::NotFound(old.to_string()));
    }
    if old != new && body.get(new).is_some() {
        if !force {
            return Err(Error::AlreadyExists(new.to_string()));
        }
        return body.remove(new)?.rename(old, new, now);
    }
    body.rename(old, new, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{Field, Item, ItemKind};

    const NOW: &str = "2026-01-01T00:00:00Z";

    fn body() -> VaultBody {
        let a = Item::new("a", ItemKind::Password, NOW)
            .with_field("password", Field::secret_text("va"));
        let b = Item::new("b", ItemKind::Password, NOW)
            .with_field("password", Field::secret_text("vb"));
        VaultBody::default()
            .insert(a, false)
            .expect("a")
            .insert(b, false)
            .expect("b")
    }

    #[test]
    fn rename_paths() {
        let b = body();
        let r = rename(&b, "a", "c", false, NOW).expect("rename");
        assert!(r.get("a").is_none() && r.get("c").is_some());
        assert!(matches!(
            rename(&b, "zz", "c", false, NOW),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            rename(&b, "a", "b", false, NOW),
            Err(Error::AlreadyExists(_))
        ));
        let r = rename(&b, "a", "b", true, NOW).expect("force");
        assert_eq!(r.items.len(), 1);
        assert_eq!(
            r.get("b")
                .and_then(|i| i.primary())
                .and_then(|f| f.value.as_text()),
            Some("va")
        );
        assert_eq!(rename(&b, "a", "a", false, NOW).expect("same"), b);
        assert_eq!(b.items.len(), 2, "original untouched");
    }
}
