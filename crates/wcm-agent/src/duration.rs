//! Human-friendly durations for `--idle` / `--ttl` (`90s`, `10m`, `1h`, `1h30m`).

use std::time::Duration;

use wcm_core::{Error, Result};

/// Parses one or more `<integer><unit>` tokens (units `s`, `m`, `h`) into a
/// duration. Every number needs a unit and the total must be positive.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let text = s.trim();
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut seen_unit = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let multiplier = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(invalid(text)),
        };
        if digits.is_empty() {
            return Err(invalid(text));
        }
        let n: u64 = digits.parse().map_err(|_| invalid(text))?;
        total = n
            .checked_mul(multiplier)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| invalid(text))?;
        digits.clear();
        seen_unit = true;
    }
    if !digits.is_empty() || !seen_unit || total == 0 {
        return Err(invalid(text));
    }
    Ok(Duration::from_secs(total))
}

fn invalid(s: &str) -> Error {
    Error::Invalid(format!(
        "invalid duration '{s}' (use e.g. 90s, 10m, 1h or 1h30m)"
    ))
}

/// Formats whole seconds as the shortest `XhYmZs` (`0s` for zero).
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_and_combinations() {
        assert_eq!(parse_duration("90s").expect("90s"), Duration::from_secs(90));
        assert_eq!(
            parse_duration("10m").expect("10m"),
            Duration::from_secs(600)
        );
        assert_eq!(parse_duration("1h").expect("1h"), Duration::from_secs(3600));
        assert_eq!(
            parse_duration("1h30m").expect("1h30m"),
            Duration::from_secs(5400)
        );
        assert_eq!(
            parse_duration(" 2m ").expect("2m"),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn rejects_zero_missing_unit_and_garbage() {
        for bad in ["", "0", "0s", "10", "abc", "5x", "m", "-1m", "1.5h", "1h30"] {
            assert!(
                matches!(parse_duration(bad), Err(Error::Invalid(_))),
                "{bad:?} should be invalid"
            );
        }
    }

    #[test]
    fn formats_compactly() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(600)), "10m");
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h1m1s");
    }
}
