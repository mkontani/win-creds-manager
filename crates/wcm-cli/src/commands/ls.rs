//! `wcm ls [PREFIX]` — list items (names only, `-l` for a table, `--json` for details).

use serde::Serialize;
use wcm_core::item::{Item, ItemKind};
use wcm_core::Result;

use crate::cli::LsArgs;
use crate::context::Ctx;

#[derive(Serialize, Debug, PartialEq, Eq)]
struct Row {
    name: String,
    kind: &'static str,
    tags: Vec<String>,
    created: String,
    updated: String,
    /// Names of the non-secret fields.
    fields: Vec<String>,
}

pub fn run(ctx: &Ctx, args: &LsArgs) -> Result<()> {
    let v = ctx.unlock("list items")?;
    let kind: Option<ItemKind> = args.kind.map(Into::into);
    let rows: Vec<Row> = v
        .body
        .list(args.prefix.as_deref(), kind, args.tag.as_deref())
        .into_iter()
        .map(row)
        .collect();
    if ctx.out.json {
        return ctx.out.json(&rows);
    }
    let lines = if args.long {
        long_lines(&rows)
    } else {
        rows.iter().map(|r| r.name.clone()).collect()
    };
    for l in lines {
        ctx.out.line(&l)?;
    }
    Ok(())
}

fn row(item: &Item) -> Row {
    Row {
        name: item.name.clone(),
        kind: item.kind.as_str(),
        tags: item.tags.clone(),
        created: item.created.clone(),
        updated: item.updated.clone(),
        fields: item
            .fields
            .iter()
            .filter(|(_, f)| !f.secret)
            .map(|(k, _)| k.clone())
            .collect(),
    }
}

/// `name  kind  updated  tags` with the name column padded to the longest name.
fn long_lines(rows: &[Row]) -> Vec<String> {
    let width = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|r| {
            format!(
                "{:<width$}  {:<8}  {}  {}",
                r.name,
                r.kind,
                r.updated,
                r.tags.join(","),
                width = width
            )
            .trim_end()
            .to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::Field;

    #[test]
    fn row_lists_only_public_fields() {
        let it = Item::new("a", ItemKind::Login, "2026-01-01T00:00:00Z")
            .with_field("password", Field::secret_text("pw"))
            .with_field("username", Field::public_text("u"))
            .with_tags(vec!["x".into()]);
        let r = row(&it);
        assert_eq!(r.fields, vec!["username".to_string()]);
        assert_eq!(r.kind, "login");
        assert_eq!(r.tags, vec!["x".to_string()]);
    }

    #[test]
    fn long_format_pads_names() {
        let rows = vec![
            Row {
                name: "a".into(),
                kind: "password",
                tags: vec!["t1".into(), "t2".into()],
                created: "c".into(),
                updated: "2026-01-01T00:00:00Z".into(),
                fields: vec![],
            },
            Row {
                name: "longer".into(),
                kind: "ssh-key",
                tags: vec![],
                created: "c".into(),
                updated: "2026-01-02T00:00:00Z".into(),
                fields: vec![],
            },
        ];
        let lines = long_lines(&rows);
        assert_eq!(
            lines,
            vec![
                "a       password  2026-01-01T00:00:00Z  t1,t2",
                "longer  ssh-key   2026-01-02T00:00:00Z",
            ]
        );
        assert!(long_lines(&[]).is_empty());
    }
}
