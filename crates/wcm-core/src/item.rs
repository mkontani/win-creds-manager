//! Items stored in the vault: name, kind, fields, notes, tags, timestamps.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// Item category. Determines the *primary* secret field name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// A bare password / secret string.
    Password,
    /// username + password (+ url).
    Login,
    /// API token / PAT.
    Token,
    /// OpenSSH private key (+ public key, fingerprint).
    SshKey,
    /// Arbitrary binary file.
    File,
    /// Free-form secret note.
    Note,
}

impl ItemKind {
    /// All kinds, in display order.
    pub const ALL: [ItemKind; 6] = [
        ItemKind::Password,
        ItemKind::Login,
        ItemKind::Token,
        ItemKind::SshKey,
        ItemKind::File,
        ItemKind::Note,
    ];

    /// Name of the field returned by `wcm get <name>` when `--field` is omitted.
    pub fn primary_field(&self) -> &'static str {
        match self {
            ItemKind::Password | ItemKind::Login => "password",
            ItemKind::Token => "token",
            ItemKind::SshKey => "private_key",
            ItemKind::File => "content",
            ItemKind::Note => "note",
        }
    }

    /// Kebab-case name.
    pub fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Password => "password",
            ItemKind::Login => "login",
            ItemKind::Token => "token",
            ItemKind::SshKey => "ssh-key",
            ItemKind::File => "file",
            ItemKind::Note => "note",
        }
    }

    /// Parses a kebab-case name (case-insensitive, `_` accepted).
    pub fn parse(s: &str) -> Option<ItemKind> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        ItemKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A field value: UTF-8 text or raw bytes.
///
/// Serialized as a CBOR text/byte string in the vault, and as a JSON string or
/// `{"b64": "..."}` object in human-readable formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    /// Text value.
    Text(String),
    /// Binary value.
    Bytes(Vec<u8>),
}

impl FieldValue {
    /// Raw bytes of the value.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            FieldValue::Text(s) => s.as_bytes(),
            FieldValue::Bytes(b) => b,
        }
    }

    /// Text view if this is text (or valid UTF-8 bytes).
    pub fn as_text(&self) -> Option<&str> {
        match self {
            FieldValue::Text(s) => Some(s),
            FieldValue::Bytes(b) => std::str::from_utf8(b).ok(),
        }
    }

    /// Whether the value is binary.
    pub fn is_binary(&self) -> bool {
        matches!(self, FieldValue::Bytes(_))
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Serialize for FieldValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            FieldValue::Text(s) => serializer.serialize_str(s),
            FieldValue::Bytes(b) if serializer.is_human_readable() => {
                use serde::ser::SerializeMap;
                let mut m = serializer.serialize_map(Some(1))?;
                m.serialize_entry("b64", &base64::engine::general_purpose::STANDARD.encode(b))?;
                m.end()
            }
            FieldValue::Bytes(b) => serializer.serialize_bytes(b),
        }
    }
}

impl<'de> Deserialize<'de> for FieldValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FieldValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, a byte string, or {\"b64\": \"...\"}")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<FieldValue, E> {
                Ok(FieldValue::Text(v.to_string()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<FieldValue, E> {
                Ok(FieldValue::Text(v))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<FieldValue, E> {
                Ok(FieldValue::Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E: de::Error>(
                self,
                v: Vec<u8>,
            ) -> std::result::Result<FieldValue, E> {
                Ok(FieldValue::Bytes(v))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<FieldValue, A::Error> {
                let mut out = None;
                while let Some(k) = map.next_key::<String>()? {
                    if k == "b64" {
                        let s: String = map.next_value()?;
                        let b = base64::engine::general_purpose::STANDARD
                            .decode(s.as_bytes())
                            .map_err(|e| de::Error::custom(format!("invalid base64: {e}")))?;
                        out = Some(FieldValue::Bytes(b));
                    } else {
                        let _: de::IgnoredAny = map.next_value()?;
                    }
                }
                out.ok_or_else(|| de::Error::custom("expected {\"b64\": \"...\"}"))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// A named field of an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// Value.
    pub value: FieldValue,
    /// Whether the value is secret (masked in `show`, hidden from `ls -l`).
    pub secret: bool,
}

impl Field {
    /// Secret text field.
    pub fn secret_text(s: impl Into<String>) -> Self {
        Field {
            value: FieldValue::Text(s.into()),
            secret: true,
        }
    }
    /// Secret binary field.
    pub fn secret_bytes(b: Vec<u8>) -> Self {
        Field {
            value: FieldValue::Bytes(b),
            secret: true,
        }
    }
    /// Non-secret text field (username, url, ...).
    pub fn public_text(s: impl Into<String>) -> Self {
        Field {
            value: FieldValue::Text(s.into()),
            secret: false,
        }
    }
}

/// One credential entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// 16 random bytes; stable across renames.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// Unique, user-chosen name (e.g. `github/token`).
    pub name: String,
    /// Kind.
    pub kind: ItemKind,
    /// Fields keyed by name.
    pub fields: BTreeMap<String, Field>,
    /// Free-form notes.
    pub notes: String,
    /// Tags.
    pub tags: Vec<String>,
    /// RFC 3339 creation time.
    pub created: String,
    /// RFC 3339 last update time.
    pub updated: String,
}

impl Item {
    /// New empty item with a fresh random id.
    pub fn new(name: &str, kind: ItemKind, now: &str) -> Item {
        Item {
            id: crate::crypto::aead::random_bytes::<16>().to_vec(),
            name: name.to_string(),
            kind,
            fields: BTreeMap::new(),
            notes: String::new(),
            tags: Vec::new(),
            created: now.to_string(),
            updated: now.to_string(),
        }
    }

    /// Returns a copy with `field` set.
    pub fn with_field(mut self, name: &str, field: Field) -> Item {
        self.fields.insert(name.to_string(), field);
        self
    }

    /// Returns a copy without `field`.
    pub fn without_field(mut self, name: &str) -> Item {
        self.fields.remove(name);
        self
    }

    /// Returns a copy with `notes` replaced.
    pub fn with_notes(mut self, notes: &str) -> Item {
        self.notes = notes.to_string();
        self
    }

    /// Returns a copy with `tags` replaced (deduplicated, sorted).
    pub fn with_tags(mut self, tags: Vec<String>) -> Item {
        let mut t = tags;
        t.sort();
        t.dedup();
        self.tags = t;
        self
    }

    /// Returns a copy with `updated` set to `now`.
    pub fn touched(mut self, now: &str) -> Item {
        self.updated = now.to_string();
        self
    }

    /// The primary secret field for this item's kind, if present.
    pub fn primary(&self) -> Option<&Field> {
        self.fields.get(self.kind.primary_field())
    }

    /// Hex id.
    pub fn id_hex(&self) -> String {
        self.id.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Maximum item name length in characters.
pub const MAX_NAME_LEN: usize = 200;

/// Validates an item name: 1..=200 chars, no control chars, no leading `-`,
/// no leading/trailing `/`, no `..` segment, no leading/trailing whitespace.
pub fn validate_name(name: &str) -> Result<()> {
    let n = name.chars().count();
    if n == 0 {
        return Err(Error::Invalid("item name must not be empty".into()));
    }
    if n > MAX_NAME_LEN {
        return Err(Error::Invalid(format!(
            "item name longer than {MAX_NAME_LEN} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "item name must not contain control characters".into(),
        ));
    }
    if name.starts_with('-') {
        return Err(Error::Invalid("item name must not start with '-'".into()));
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err(Error::Invalid(
            "item name must not start or end with '/'".into(),
        ));
    }
    if name.split('/').any(|seg| seg == "..") || name.split('/').any(str::is_empty) {
        return Err(Error::Invalid(
            "item name must not contain '..' or empty segments".into(),
        ));
    }
    if name.trim() != name {
        return Err(Error::Invalid(
            "item name must not start or end with whitespace".into(),
        ));
    }
    Ok(())
}

/// Validates a field name: 1..=64 chars of `[A-Za-z0-9_.-]`.
pub fn validate_field_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::Invalid(
            "field name must be 1..=64 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(Error::Invalid(format!(
            "invalid field name '{name}': use letters, digits, '_', '.', '-'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_parse_and_primary() {
        assert_eq!(ItemKind::parse("ssh-key"), Some(ItemKind::SshKey));
        assert_eq!(ItemKind::parse("SSH_KEY"), Some(ItemKind::SshKey));
        assert_eq!(ItemKind::parse("nope"), None);
        assert_eq!(ItemKind::SshKey.primary_field(), "private_key");
        assert_eq!(ItemKind::Login.primary_field(), "password");
        assert_eq!(ItemKind::File.primary_field(), "content");
        assert_eq!(ItemKind::Note.to_string(), "note");
        for k in ItemKind::ALL {
            assert_eq!(ItemKind::parse(k.as_str()), Some(k));
        }
    }

    #[test]
    fn validate_name_rules() {
        assert!(validate_name("github/token").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("日本語/名前").is_ok());
        for bad in [
            "",
            "-x",
            "/x",
            "x/",
            "a//b",
            "a/../b",
            "a\nb",
            " a",
            "a ",
            &"x".repeat(201),
        ] {
            assert!(
                matches!(validate_name(bad), Err(Error::Invalid(_))),
                "{bad:?}"
            );
        }
        assert!(validate_name(&"x".repeat(200)).is_ok());
    }

    #[test]
    fn validate_field_name_rules() {
        assert!(validate_field_name("private_key").is_ok());
        assert!(validate_field_name("a.b-c").is_ok());
        for bad in ["", "a b", "a/b", &"x".repeat(65)] {
            assert!(
                matches!(validate_field_name(bad), Err(Error::Invalid(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn item_builders_are_immutable() {
        let a = Item::new("n", ItemKind::Password, "2026-01-01T00:00:00Z");
        let b = a
            .clone()
            .with_field("password", Field::secret_text("pw"))
            .with_tags(vec!["b".into(), "a".into(), "a".into()]);
        assert!(a.fields.is_empty());
        assert_eq!(b.fields.len(), 1);
        assert_eq!(b.tags, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(b.primary().map(|f| f.value.as_text()), Some(Some("pw")));
        let c = b
            .clone()
            .without_field("password")
            .touched("2026-02-02T00:00:00Z");
        assert!(c.primary().is_none());
        assert_eq!(b.updated, "2026-01-01T00:00:00Z");
        assert_eq!(c.updated, "2026-02-02T00:00:00Z");
        assert_eq!(a.id, b.id);
        assert_eq!(a.id_hex().len(), 32);
    }

    #[test]
    fn field_value_cbor_uses_native_strings_and_bytes() {
        let t = FieldValue::Text("héllo".into());
        let b = FieldValue::Bytes(vec![0, 1, 2, 255]);
        let mut buf = Vec::new();
        ciborium::into_writer(&t, &mut buf).expect("cbor");
        assert_eq!(buf[0], 0x66); // tstr of 6 bytes
        let back: FieldValue = ciborium::from_reader(&buf[..]).expect("decode");
        assert_eq!(back, t);

        let mut buf = Vec::new();
        ciborium::into_writer(&b, &mut buf).expect("cbor");
        assert_eq!(buf, vec![0x44, 0, 1, 2, 255]); // bstr of 4 bytes
        let back: FieldValue = ciborium::from_reader(&buf[..]).expect("decode");
        assert_eq!(back, b);
    }

    #[test]
    fn field_value_json_uses_string_and_b64_object() {
        let t = FieldValue::Text("hi".into());
        let b = FieldValue::Bytes(vec![0, 1, 2, 255]);
        assert_eq!(serde_json::to_string(&t).expect("json"), "\"hi\"");
        assert_eq!(
            serde_json::to_string(&b).expect("json"),
            "{\"b64\":\"AAEC/w==\"}"
        );
        let back: FieldValue = serde_json::from_str("{\"b64\":\"AAEC/w==\"}").expect("decode");
        assert_eq!(back, b);
        let back: FieldValue = serde_json::from_str("\"hi\"").expect("decode");
        assert_eq!(back, t);
        assert!(serde_json::from_str::<FieldValue>("{\"b64\":\"!!\"}").is_err());
        assert!(serde_json::from_str::<FieldValue>("{\"x\":1}").is_err());
        assert!(serde_json::from_str::<FieldValue>("12").is_err());
    }

    #[test]
    fn field_value_helpers() {
        let b = FieldValue::Bytes(vec![0xff]);
        assert!(b.is_binary());
        assert_eq!(b.as_text(), None);
        assert_eq!(FieldValue::Bytes(b"ok".to_vec()).as_text(), Some("ok"));
        assert!(FieldValue::Text(String::new()).is_empty());
        assert_eq!(FieldValue::Text("abc".into()).len(), 3);
    }
}
