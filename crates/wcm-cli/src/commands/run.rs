//! `wcm run --env VAR=name[/field] ... [--env-file FILE] -- cmd args`
//!
//! Resolves every mapping with a single unlock, drops the vault, then runs the
//! command with the secrets in its environment (stdio inherited).

use std::io::Write;
use std::process::{Command, Stdio};

use wcm_core::item::FieldValue;
use wcm_core::vault::VaultBody;
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

use crate::cli::RunArgs;
use crate::context::Ctx;

/// URL scheme marking a secret reference inside `--env-file`.
pub const WCM_SCHEME: &str = "wcm://";

/// One environment variable to set for the child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvSpec {
    /// `VAR` ← secret `name[/field]` from the vault.
    Secret {
        /// Variable name.
        var: String,
        /// `name` or `name/field`.
        spec: String,
    },
    /// `VAR` ← literal value (from `--env-file`).
    Plain {
        /// Variable name.
        var: String,
        /// Literal value.
        value: String,
    },
}

impl EnvSpec {
    fn var(&self) -> &str {
        match self {
            EnvSpec::Secret { var, .. } | EnvSpec::Plain { var, .. } => var,
        }
    }
}

/// Validates an environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn validate_var_name(var: &str) -> Result<()> {
    let mut chars = var.chars();
    let ok_first = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let ok_rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok_first && ok_rest {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "invalid environment variable name '{var}' (use [A-Za-z_][A-Za-z0-9_]*)"
        )))
    }
}

/// Parses `VAR=name[/field]` (the `--env` syntax).
pub fn parse_mapping(s: &str) -> Result<EnvSpec> {
    let (var, spec) = s.split_once('=').ok_or_else(|| {
        Error::Invalid(format!(
            "invalid --env mapping '{s}': expected VAR=name or VAR=name/field"
        ))
    })?;
    validate_var_name(var)?;
    validate_spec(spec)?;
    Ok(EnvSpec::Secret {
        var: var.to_string(),
        spec: spec.to_string(),
    })
}

/// `name[/field]` must look like an item name (a field suffix obeys the same rules).
fn validate_spec(spec: &str) -> Result<()> {
    wcm_core::item::validate_name(spec)
        .map_err(|e| Error::Invalid(format!("invalid item reference '{spec}': {e}")))
}

/// Parses an env file: blank lines and `#` comments are skipped;
/// `VAR=wcm://name[/field]` lines are secret references; other `VAR=value`
/// lines are plain variables (key and value trimmed of surrounding whitespace).
pub fn parse_env_file(content: &str) -> Result<Vec<EnvSpec>> {
    content
        .lines()
        .enumerate()
        .map(|(i, raw)| (i + 1, raw.trim_end_matches('\r').trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(lineno, line)| parse_env_file_line(line).map_err(|e| annotate(lineno, e)))
        .collect()
}

fn annotate(lineno: usize, e: Error) -> Error {
    match e {
        Error::Invalid(m) => Error::Invalid(format!("env file line {lineno}: {m}")),
        other => other,
    }
}

fn parse_env_file_line(line: &str) -> Result<EnvSpec> {
    let (var, value) = line.split_once('=').ok_or_else(|| {
        Error::Invalid(format!(
            "expected VAR=value or VAR=wcm://name[/field], got '{line}'"
        ))
    })?;
    let (var, value) = (var.trim(), value.trim());
    validate_var_name(var)?;
    match value.strip_prefix(WCM_SCHEME) {
        Some(spec) => {
            validate_spec(spec)?;
            Ok(EnvSpec::Secret {
                var: var.to_string(),
                spec: spec.to_string(),
            })
        }
        None => Ok(EnvSpec::Plain {
            var: var.to_string(),
            value: value.to_string(),
        }),
    }
}

/// Resolves `name[/field]` against the body.
///
/// An exact item name wins (item names may contain `/`); otherwise the part
/// after the last `/` is the field and the rest is the item name. Without a
/// field the kind's primary field is used. Binary values are rejected.
pub fn resolve_secret(body: &VaultBody, spec: &str) -> Result<Zeroizing<String>> {
    let (item, field_name) = match body.get(spec) {
        Some(item) => (item, item.kind.primary_field().to_string()),
        None => {
            let (name, field) = spec
                .rsplit_once('/')
                .ok_or_else(|| Error::NotFound(spec.to_string()))?;
            let item = body
                .get(name)
                .ok_or_else(|| Error::NotFound(spec.to_string()))?;
            (item, field.to_string())
        }
    };
    let field = item
        .fields
        .get(&field_name)
        .ok_or_else(|| Error::NotFound(format!("field '{field_name}' of item '{}'", item.name)))?;
    match &field.value {
        FieldValue::Text(s) if s.contains('\0') => Err(Error::Invalid(format!(
            "value of '{spec}' contains a NUL byte and cannot be an environment variable"
        ))),
        FieldValue::Text(s) => Ok(Zeroizing::new(s.clone())),
        FieldValue::Bytes(_) => Err(Error::Invalid(format!(
            "binary value cannot be an environment variable ('{spec}')"
        ))),
    }
}

/// Collects specs from `--env-file` (first) and `--env` (last wins on duplicates).
fn collect_specs(args: &RunArgs) -> Result<Vec<EnvSpec>> {
    let mut specs = Vec::new();
    if let Some(path) = &args.env_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
        specs.extend(parse_env_file(&content)?);
    }
    for m in &args.env {
        specs.push(parse_mapping(m)?);
    }
    Ok(dedup_last_wins(specs))
}

/// Keeps only the last spec for each variable name (preserving first-seen order).
fn dedup_last_wins(specs: Vec<EnvSpec>) -> Vec<EnvSpec> {
    let mut out: Vec<EnvSpec> = Vec::with_capacity(specs.len());
    for s in specs {
        match out.iter().position(|o| o.var() == s.var()) {
            Some(i) => out[i] = s,
            None => out.push(s),
        }
    }
    out
}

/// Resolves all specs to `(VAR, value)` pairs with at most one unlock.
fn resolve_all(ctx: &Ctx, specs: &[EnvSpec]) -> Result<Vec<(String, Zeroizing<String>)>> {
    let needs_vault = specs.iter().any(|s| matches!(s, EnvSpec::Secret { .. }));
    let body: Option<VaultBody> = if needs_vault {
        // Unlock once; keep only the body and let the DEK drop right away.
        Some(ctx.unlock("inject secrets into the environment")?.body)
    } else {
        None
    };
    specs
        .iter()
        .map(|s| match s {
            EnvSpec::Plain { var, value } => Ok((var.clone(), Zeroizing::new(value.clone()))),
            EnvSpec::Secret { var, spec } => {
                let body = body
                    .as_ref()
                    .ok_or_else(|| Error::Other("vault not unlocked".into()))?;
                Ok((var.clone(), resolve_secret(body, spec)?))
            }
        })
        .collect()
}

pub fn run(ctx: &Ctx, args: &RunArgs) -> Result<()> {
    let (program, rest) = args
        .cmd
        .split_first()
        .ok_or_else(|| Error::Invalid("no command given after `--`".into()))?;
    let specs = collect_specs(args)?;
    let env = resolve_all(ctx, &specs)?;
    // `env` (and the vault body) is dropped before the child outlives us; the
    // child only ever sees the resolved values.

    let status = Command::new(program)
        .args(rest)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| Error::Helper(format!("cannot run '{program}': {e}")))?;
    drop(env);

    // Propagate the child's exit status verbatim. `main` maps wcm errors to
    // exit codes and prints an error message; neither is wanted here, so this
    // is the one place that exits the process directly (after flushing).
    let code = match status.code() {
        Some(0) => return Ok(()),
        Some(c) => c,
        None => i32::from(wcm_core::error::EXIT_INTERRUPTED),
    };
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wcm_core::item::{Field, Item, ItemKind};

    fn body() -> VaultBody {
        let now = "2026-01-01T00:00:00Z";
        let login = Item::new("login", ItemKind::Login, now)
            .with_field("password", Field::secret_text("pw"))
            .with_field("username", Field::public_text("alice"));
        let nested = Item::new("a/b", ItemKind::Token, now)
            .with_field("token", Field::secret_text("nested-token"));
        let a = Item::new("a", ItemKind::Login, now)
            .with_field("b", Field::secret_text("field-b"))
            .with_field("bin", Field::secret_bytes(vec![0, 1]))
            .with_field("nul", Field::secret_text("x\0y"));
        VaultBody::default()
            .insert(login, false)
            .and_then(|b| b.insert(nested, false))
            .and_then(|b| b.insert(a, false))
            .expect("body")
    }

    #[test]
    fn var_name_rules() {
        for ok in ["A", "_x", "Ab9_", "HOME"] {
            assert!(validate_var_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A B", "A=B", "é"] {
            assert!(
                matches!(validate_var_name(bad), Err(Error::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_mapping_syntax() {
        assert_eq!(
            parse_mapping("A=login/username").expect("ok"),
            EnvSpec::Secret {
                var: "A".into(),
                spec: "login/username".into()
            }
        );
        for bad in ["noequals", "1A=x", "=x", "A=", "A=/x", "A=x/", "A=-x"] {
            assert!(
                matches!(parse_mapping(bad), Err(Error::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn parse_env_file_lines() {
        let specs = parse_env_file(
            "# c\n\n  PASS=wcm://login\nUSER = wcm://login/username\nPLAIN=a=b\r\nEMPTY=\n",
        )
        .expect("parse");
        assert_eq!(
            specs,
            vec![
                EnvSpec::Secret {
                    var: "PASS".into(),
                    spec: "login".into()
                },
                // `USER = wcm://...`: key and value are trimmed.
                EnvSpec::Secret {
                    var: "USER".into(),
                    spec: "login/username".into()
                },
                EnvSpec::Plain {
                    var: "PLAIN".into(),
                    value: "a=b".into()
                },
                EnvSpec::Plain {
                    var: "EMPTY".into(),
                    value: String::new()
                },
            ]
        );
        let err = parse_env_file("OK=1\nBROKEN\n").expect_err("bad line");
        match err {
            Error::Invalid(m) => assert!(m.contains("line 2"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(parse_env_file("A=wcm://"), Err(Error::Invalid(_))));
        assert!(matches!(parse_env_file("1A=x"), Err(Error::Invalid(_))));
    }

    #[test]
    fn resolve_exact_name_wins_then_name_slash_field() {
        let b = body();
        assert_eq!(resolve_secret(&b, "login").expect("primary").as_str(), "pw");
        assert_eq!(
            resolve_secret(&b, "login/username")
                .expect("field")
                .as_str(),
            "alice"
        );
        // "a/b" is an item → its primary field, not field b of item a.
        assert_eq!(
            resolve_secret(&b, "a/b").expect("exact").as_str(),
            "nested-token"
        );
        assert!(matches!(
            resolve_secret(&b, "nope"),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            resolve_secret(&b, "nope/field"),
            Err(Error::NotFound(_))
        ));
        match resolve_secret(&b, "login/nofield") {
            Err(Error::NotFound(m)) => assert!(m.contains("nofield"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        match resolve_secret(&b, "a/bin") {
            Err(Error::Invalid(m)) => assert!(m.contains("binary"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            resolve_secret(&b, "a/nul"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn later_specs_override_earlier_ones() {
        let specs = dedup_last_wins(vec![
            EnvSpec::Plain {
                var: "A".into(),
                value: "1".into(),
            },
            EnvSpec::Plain {
                var: "B".into(),
                value: "2".into(),
            },
            EnvSpec::Secret {
                var: "A".into(),
                spec: "login".into(),
            },
        ]);
        assert_eq!(specs.len(), 2);
        assert_eq!(
            specs[0],
            EnvSpec::Secret {
                var: "A".into(),
                spec: "login".into()
            }
        );
        assert_eq!(specs[1].var(), "B");
    }
}
