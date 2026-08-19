//! Encrypted vault body: all items and settings. Every mutation returns a new body.

use serde::{Deserialize, Serialize};

use crate::item::{validate_name, Item, ItemKind};
use crate::{Error, Result};

/// Non-item settings stored inside the encrypted body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Settings {
    /// RFC 3339 time of the last `wcm export`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_export: Option<String>,
}

/// Plaintext content of the vault (before AEAD).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VaultBody {
    /// Items, kept sorted by name.
    pub items: Vec<Item>,
    /// Settings.
    #[serde(default)]
    pub settings: Settings,
}

impl VaultBody {
    /// Looks up an item by exact name.
    pub fn get(&self, name: &str) -> Option<&Item> {
        self.items.iter().find(|i| i.name == name)
    }

    /// Returns a new body with `item` inserted (replacing an existing one only if `overwrite`).
    pub fn insert(&self, item: Item, overwrite: bool) -> Result<VaultBody> {
        validate_name(&item.name)?;
        let mut items: Vec<Item> = self
            .items
            .iter()
            .filter(|i| i.name != item.name)
            .cloned()
            .collect();
        if items.len() != self.items.len() && !overwrite {
            return Err(Error::AlreadyExists(item.name));
        }
        items.push(item);
        Ok(self.with_items(items))
    }

    /// Returns a new body without the named item.
    pub fn remove(&self, name: &str) -> Result<VaultBody> {
        if self.get(name).is_none() {
            return Err(Error::NotFound(name.to_string()));
        }
        let items = self
            .items
            .iter()
            .filter(|i| i.name != name)
            .cloned()
            .collect();
        Ok(self.with_items(items))
    }

    /// Returns a new body with the item renamed (fails if `new` exists).
    pub fn rename(&self, old: &str, new: &str, now: &str) -> Result<VaultBody> {
        validate_name(new)?;
        if old == new {
            return Ok(self.clone());
        }
        if self.get(new).is_some() {
            return Err(Error::AlreadyExists(new.to_string()));
        }
        self.update(old, |mut it| {
            it.name = new.to_string();
            Ok(it.touched(now))
        })
    }

    /// Returns a new body with `f` applied to the named item.
    pub fn update<F: FnOnce(Item) -> Result<Item>>(&self, name: &str, f: F) -> Result<VaultBody> {
        let cur = self
            .get(name)
            .ok_or_else(|| Error::NotFound(name.to_string()))?
            .clone();
        let updated = f(cur)?;
        let items = self
            .items
            .iter()
            .filter(|i| i.name != name)
            .cloned()
            .chain(std::iter::once(updated))
            .collect();
        Ok(self.with_items(items))
    }

    /// Items filtered by name prefix, kind and tag; sorted by name.
    pub fn list(
        &self,
        prefix: Option<&str>,
        kind: Option<ItemKind>,
        tag: Option<&str>,
    ) -> Vec<&Item> {
        self.items
            .iter()
            .filter(|i| prefix.is_none_or(|p| i.name.starts_with(p)))
            .filter(|i| kind.is_none_or(|k| i.kind == k))
            .filter(|i| tag.is_none_or(|t| i.tags.iter().any(|x| x == t)))
            .collect()
    }

    /// Returns a new body with settings replaced.
    pub fn with_settings(&self, settings: Settings) -> VaultBody {
        VaultBody {
            items: self.items.clone(),
            settings,
        }
    }

    /// CBOR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| Error::Integrity(format!("body encode: {e}")))?;
        Ok(buf)
    }

    /// CBOR decoding.
    pub fn decode(bytes: &[u8]) -> Result<VaultBody> {
        let body: VaultBody = ciborium::from_reader(bytes)
            .map_err(|e| Error::Integrity(format!("body decode: {e}")))?;
        Ok(body.with_items(body.items.clone()))
    }

    fn with_items(&self, mut items: Vec<Item>) -> VaultBody {
        items.sort_by(|a, b| a.name.cmp(&b.name));
        VaultBody {
            items,
            settings: self.settings.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Field;

    const NOW: &str = "2026-01-01T00:00:00Z";

    fn item(name: &str) -> Item {
        Item::new(name, ItemKind::Password, NOW).with_field("password", Field::secret_text("x"))
    }

    #[test]
    fn insert_get_remove_are_immutable_and_sorted() {
        let empty = VaultBody::default();
        let one = empty.insert(item("b"), false).expect("insert");
        let two = one.insert(item("a"), false).expect("insert");
        assert!(empty.items.is_empty());
        assert_eq!(one.items.len(), 1);
        assert_eq!(
            two.items
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(two.get("a").is_some());
        assert!(matches!(
            two.insert(item("a"), false),
            Err(Error::AlreadyExists(_))
        ));
        let replaced = two
            .insert(item("a").with_notes("new"), true)
            .expect("overwrite");
        assert_eq!(replaced.get("a").map(|i| i.notes.as_str()), Some("new"));
        assert_eq!(replaced.items.len(), 2);
        let less = replaced.remove("a").expect("remove");
        assert!(less.get("a").is_none());
        assert!(matches!(less.remove("zzz"), Err(Error::NotFound(_))));
        assert!(matches!(
            empty.insert(item("-bad"), false),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn rename_and_update() {
        let b = VaultBody::default()
            .insert(item("a"), false)
            .expect("i")
            .insert(item("b"), false)
            .expect("i");
        let r = b.rename("a", "c", "2026-02-02T00:00:00Z").expect("rename");
        assert!(r.get("a").is_none());
        assert_eq!(
            r.get("c").map(|i| i.updated.as_str()),
            Some("2026-02-02T00:00:00Z")
        );
        assert_eq!(
            b.get("a").map(|i| i.id.clone()),
            r.get("c").map(|i| i.id.clone())
        );
        assert!(matches!(
            b.rename("a", "b", NOW),
            Err(Error::AlreadyExists(_))
        ));
        assert!(matches!(b.rename("zz", "q", NOW), Err(Error::NotFound(_))));
        assert_eq!(b.rename("a", "a", NOW).expect("same"), b);

        let u = b.update("a", |it| Ok(it.with_notes("n"))).expect("update");
        assert_eq!(u.get("a").map(|i| i.notes.as_str()), Some("n"));
        assert_eq!(b.get("a").map(|i| i.notes.as_str()), Some(""));
        assert!(matches!(b.update("nope", Ok), Err(Error::NotFound(_))));
        assert!(matches!(
            b.update("a", |_| Err(Error::Invalid("x".into()))),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn list_filters() {
        let b = VaultBody::default()
            .insert(item("git/a").with_tags(vec!["work".into()]), false)
            .expect("i")
            .insert(item("git/b"), false)
            .expect("i")
            .insert(Item::new("ssh/x", ItemKind::SshKey, NOW), false)
            .expect("i");
        assert_eq!(b.list(None, None, None).len(), 3);
        assert_eq!(b.list(Some("git/"), None, None).len(), 2);
        assert_eq!(b.list(None, Some(ItemKind::SshKey), None).len(), 1);
        assert_eq!(b.list(None, None, Some("work")).len(), 1);
        assert_eq!(b.list(Some("git/"), Some(ItemKind::SshKey), None).len(), 0);
    }

    #[test]
    fn cbor_roundtrip_and_settings() {
        let b = VaultBody::default()
            .insert(
                item("a").with_field("blob", Field::secret_bytes(vec![0, 255])),
                false,
            )
            .expect("i")
            .with_settings(Settings {
                last_export: Some(NOW.into()),
            });
        let enc = b.encode().expect("enc");
        let dec = VaultBody::decode(&enc).expect("dec");
        assert_eq!(dec, b);
        assert!(matches!(
            VaultBody::decode(b"\xff\xff"),
            Err(Error::Integrity(_))
        ));
        // settings default when absent
        let minimal: VaultBody = ciborium::from_reader(
            &{
                let mut v = Vec::new();
                ciborium::into_writer(&serde_json::json!({"items": []}), &mut v).expect("cbor");
                v
            }[..],
        )
        .expect("decode");
        assert_eq!(minimal.settings, Settings::default());
    }
}
