//! `wcm generate [LEN]` — print (or copy) a fresh password / passphrase; no vault needed.

use serde::Serialize;
use wcm_core::generate::{generate, GenOptions};
use wcm_core::Result;
use zeroize::Zeroizing;

use crate::cli::GenerateArgs;
use crate::clip;
use crate::context::Ctx;

#[derive(Serialize)]
struct GenReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    length: usize,
}

pub fn run(ctx: &Ctx, args: &GenerateArgs) -> Result<()> {
    let value = Zeroizing::new(generate(&options(args))?);
    let length = value.chars().count();
    if args.clip {
        clip::copy_and_notify(&ctx.out, &value, args.clip_timeout)?;
    }
    if ctx.out.json {
        return ctx.out.json(&GenReport {
            value: (!args.clip).then(|| value.to_string()),
            length,
        });
    }
    if !args.clip {
        ctx.out.line(&value)?;
    }
    Ok(())
}

fn options(args: &GenerateArgs) -> GenOptions {
    GenOptions {
        length: args.length,
        symbols: !args.no_symbols,
        words: args.words,
        separator: args.sep.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_map_flags() {
        let a = GenerateArgs {
            length: 10,
            no_symbols: true,
            words: Some(3),
            sep: " ".into(),
            clip: false,
            clip_timeout: 45,
        };
        let o = options(&a);
        assert_eq!(o.length, 10);
        assert!(!o.symbols);
        assert_eq!(o.words, Some(3));
        assert_eq!(o.separator, " ");
    }
}
