//! `wcm add <name>` — store a new item (secret from stdin / file / generator / prompt).

use std::path::Path;

use serde::Serialize;
use wcm_core::item::{validate_name, Field, FieldValue, Item, ItemKind};
use wcm_core::vault::now_rfc3339;
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

use crate::cli::{AddArgs, SecretSource};
use crate::clip;
use crate::context::Ctx;
use crate::secrets::{parse_kv, resolve_secret, SecretInput, SecretOrigin};
use crate::sshkey;

#[derive(Serialize)]
struct AddReport {
    name: String,
    kind: &'static str,
    fields: Vec<String>,
    generated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

pub fn run(ctx: &Ctx, args: &AddArgs) -> Result<()> {
    validate_name(&args.name)?;
    let explicit_kind: Option<ItemKind> = args.kind.map(Into::into);
    let extra: Vec<(String, String)> = args
        .fields
        .iter()
        .map(|kv| parse_kv(kv))
        .collect::<Result<_>>()?;

    let strip_newline = explicit_kind != Some(ItemKind::File);
    let input = resolve_secret(
        &args.secret,
        &ctx.prompter,
        "Secret",
        strip_newline,
        is_interactive(&args.secret),
    )?;
    let generated = input.origin == SecretOrigin::Generated;
    let kind = detect_kind(explicit_kind, &input);
    let secret_text: Option<Zeroizing<String>> = std::str::from_utf8(&input.bytes)
        .ok()
        .map(|s| Zeroizing::new(s.to_string()));

    let now = now_rfc3339();
    let item = build_item(
        &args.name,
        kind,
        input,
        args.secret.file.as_deref(),
        &extra,
        args.notes.as_deref(),
        &args.tags,
        &now,
    )?;
    let field_names: Vec<String> = item.fields.keys().cloned().collect();

    let mut v = ctx.unlock("add item")?;
    v = v.map_body(|b| b.insert(item, args.force))?;
    ctx.save(&mut v)?;

    if args.clip {
        let text = secret_text
            .as_deref()
            .ok_or_else(|| Error::Invalid("cannot copy a binary value to the clipboard".into()))?;
        clip::copy_and_notify(&ctx.out, text, clip::DEFAULT_TIMEOUT_SECS)?;
    }
    let shown_value = if generated && !args.clip {
        secret_text.as_ref().map(|s| s.to_string())
    } else {
        None
    };
    if ctx.out.json {
        return ctx.out.json(&AddReport {
            name: args.name.clone(),
            kind: kind.as_str(),
            fields: field_names,
            generated,
            value: shown_value,
        });
    }
    ctx.out
        .notice(&format!("Added {} ({})", args.name, kind.as_str()));
    if let Some(v) = shown_value {
        ctx.out.line(&v)?;
    }
    Ok(())
}

/// Whether no explicit secret source was given (→ interactive hidden prompt).
pub fn is_interactive(s: &SecretSource) -> bool {
    !s.stdin && s.file.is_none() && s.generate.is_none() && s.value.is_none()
}

/// `--kind` wins; otherwise OpenSSH keys are detected from content, `--file` → file, else password.
fn detect_kind(explicit: Option<ItemKind>, input: &SecretInput) -> ItemKind {
    if let Some(k) = explicit {
        return k;
    }
    if sshkey::looks_like_openssh_private_key(&input.bytes) {
        return ItemKind::SshKey;
    }
    if input.origin == SecretOrigin::File {
        return ItemKind::File;
    }
    ItemKind::Password
}

/// Builds the item: public `--field`s, kind-derived public fields, then the primary secret.
#[allow(clippy::too_many_arguments)]
fn build_item(
    name: &str,
    kind: ItemKind,
    input: SecretInput,
    file: Option<&Path>,
    extra: &[(String, String)],
    notes: Option<&str>,
    tags: &[String],
    now: &str,
) -> Result<Item> {
    let mut item = Item::new(name, kind, now);
    for (k, v) in extra {
        item = item.with_field(k, Field::public_text(v.clone()));
    }
    if let Some(n) = notes {
        item = item.with_notes(n);
    }
    if !tags.is_empty() {
        item = item.with_tags(tags.to_vec());
    }
    let value: FieldValue = match kind {
        ItemKind::SshKey => {
            let info = sshkey::inspect(&input.bytes)?;
            item = item
                .with_field("public_key", Field::public_text(info.public_key))
                .with_field("fingerprint", Field::public_text(info.fingerprint))
                .with_field("algorithm", Field::public_text(info.algorithm));
            input.into_value(false)
        }
        ItemKind::File => {
            if let Some(base) = file.and_then(Path::file_name) {
                item = item.with_field(
                    "filename",
                    Field::public_text(base.to_string_lossy().into_owned()),
                );
            }
            input.into_value(true)
        }
        _ => input.into_value(false),
    };
    Ok(item.with_field(
        kind.primary_field(),
        Field {
            value,
            secret: true,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SecretSource {
        SecretSource {
            stdin: false,
            file: None,
            generate: None,
            words: None,
            no_symbols: false,
            value: None,
        }
    }

    fn input(bytes: &[u8], origin: SecretOrigin) -> SecretInput {
        SecretInput {
            bytes: Zeroizing::new(bytes.to_vec()),
            origin,
        }
    }

    #[test]
    fn interactive_only_without_source_flags() {
        assert!(is_interactive(&src()));
        assert!(!is_interactive(&SecretSource {
            stdin: true,
            ..src()
        }));
        assert!(!is_interactive(&SecretSource {
            value: Some("x".into()),
            ..src()
        }));
        assert!(!is_interactive(&SecretSource {
            generate: Some(8),
            ..src()
        }));
        assert!(!is_interactive(&SecretSource {
            file: Some("/x".into()),
            ..src()
        }));
    }

    #[test]
    fn kind_detection_order() {
        let pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\n";
        assert_eq!(
            detect_kind(None, &input(pem, SecretOrigin::File)),
            ItemKind::SshKey
        );
        assert_eq!(
            detect_kind(None, &input(b"x", SecretOrigin::File)),
            ItemKind::File
        );
        assert_eq!(
            detect_kind(None, &input(b"x", SecretOrigin::Stdin)),
            ItemKind::Password
        );
        assert_eq!(
            detect_kind(Some(ItemKind::Note), &input(pem, SecretOrigin::File)),
            ItemKind::Note
        );
    }

    #[test]
    fn build_item_file_kind_keeps_bytes_and_filename() {
        let it = build_item(
            "f",
            ItemKind::File,
            input(b"abc", SecretOrigin::File),
            Some(Path::new("/tmp/dir/report.pdf")),
            &[("owner".into(), "me".into())],
            Some("n"),
            &["b".into(), "a".into(), "a".into()],
            "2026-01-01T00:00:00Z",
        )
        .expect("item");
        assert_eq!(
            it.fields["content"].value,
            FieldValue::Bytes(b"abc".to_vec())
        );
        assert!(it.fields["content"].secret);
        assert_eq!(
            it.fields["filename"].value,
            FieldValue::Text("report.pdf".into())
        );
        assert!(!it.fields["filename"].secret);
        assert_eq!(it.fields["owner"].value, FieldValue::Text("me".into()));
        assert_eq!(it.notes, "n");
        assert_eq!(it.tags, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn build_item_ssh_kind_rejects_garbage() {
        let r = build_item(
            "k",
            ItemKind::SshKey,
            input(b"nope", SecretOrigin::Value),
            None,
            &[],
            None,
            &[],
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(r, Err(Error::Invalid(_))));
    }

    #[test]
    fn build_item_password_is_text() {
        let it = build_item(
            "p",
            ItemKind::Password,
            input(b"pw", SecretOrigin::Stdin),
            None,
            &[],
            None,
            &[],
            "2026-01-01T00:00:00Z",
        )
        .expect("item");
        assert_eq!(it.primary().map(|f| f.value.as_text()), Some(Some("pw")));
    }
}
