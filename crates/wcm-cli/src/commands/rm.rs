//! `wcm rm <name>...` — remove items (all must exist; confirmation unless `-f`).

use serde::Serialize;
use wcm_core::slot::Prompter;
use wcm_core::vault::VaultBody;
use wcm_core::{Error, Result};

use crate::cli::RmArgs;
use crate::context::Ctx;

#[derive(Serialize)]
struct RmReport {
    removed: Vec<String>,
}

pub fn run(ctx: &Ctx, args: &RmArgs) -> Result<()> {
    let names = dedup(&args.names);
    let mut v = ctx.unlock("remove item")?;
    check_all_exist(&v.body, &names)?;
    if !args.force {
        let msg = format!("Remove {} item(s)?", names.len());
        if !ctx.prompter.confirm(&msg)? {
            return Err(Error::Invalid("confirmation required; use -f".into()));
        }
    }
    v = v.map_body(|b| remove_all(b, &names))?;
    ctx.save(&mut v)?;
    if ctx.out.json {
        return ctx.out.json(&RmReport { removed: names });
    }
    for n in &names {
        ctx.out.notice(&format!("Removed {n}"));
    }
    Ok(())
}

/// Removes duplicates while keeping the first occurrence order.
fn dedup(names: &[String]) -> Vec<String> {
    names.iter().fold(Vec::new(), |mut acc, n| {
        if !acc.contains(n) {
            acc.push(n.clone());
        }
        acc
    })
}

/// `NotFound` for the first missing name.
fn check_all_exist(body: &VaultBody, names: &[String]) -> Result<()> {
    match names.iter().find(|n| body.get(n).is_none()) {
        Some(missing) => Err(Error::NotFound(missing.clone())),
        None => Ok(()),
    }
}

fn remove_all(body: &VaultBody, names: &[String]) -> Result<VaultBody> {
    names.iter().try_fold(body.clone(), |b, n| b.remove(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{Item, ItemKind};

    fn body(names: &[&str]) -> VaultBody {
        names.iter().fold(VaultBody::default(), |b, n| {
            b.insert(Item::new(n, ItemKind::Note, "2026-01-01T00:00:00Z"), false)
                .expect("insert")
        })
    }

    #[test]
    fn dedup_keeps_order() {
        let v: Vec<String> = ["b", "a", "b", "c", "a"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(dedup(&v), vec!["b", "a", "c"]);
    }

    #[test]
    fn existence_check_and_removal() {
        let b = body(&["a", "b", "c"]);
        assert!(check_all_exist(&b, &["a".into(), "c".into()]).is_ok());
        assert!(matches!(
            check_all_exist(&b, &["a".into(), "zz".into(), "yy".into()]),
            Err(Error::NotFound(m)) if m == "zz"
        ));
        let out = remove_all(&b, &["a".into(), "c".into()]).expect("remove");
        assert_eq!(out.items.len(), 1);
        assert!(out.get("b").is_some());
        assert_eq!(b.items.len(), 3, "original untouched");
    }
}
