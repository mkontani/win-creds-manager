//! Vault file: header (plaintext, AAD) + AEAD body.

pub mod body;
pub mod file;
pub mod header;

use std::path::{Path, PathBuf};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::crypto::aead;
use crate::slot::{open_slot, Dek, Envelope, KeySlot, KeySlotBackend, UnlockContext};
use crate::{Error, Result};

pub use body::{Settings, VaultBody};
pub use header::Header;

/// Maps a key slot to the backend/envelope pair able to open it.
///
/// Returning `None` skips the slot (e.g. Hello slot on a non-Windows machine).
pub trait SlotResolver {
    /// Resolve backend + envelope for `slot`.
    fn resolve(&self, slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)>;
}

/// A vault file on disk.
#[derive(Clone, Debug)]
pub struct Vault {
    /// Path of the vault file.
    pub path: PathBuf,
}

/// An opened vault: header, plaintext body and the DEK.
pub struct UnlockedVault {
    /// Header as loaded (generation etc.).
    pub header: Header,
    /// Decrypted body.
    pub body: VaultBody,
    dek: Dek,
    loaded_generation: u64,
}

impl Vault {
    /// Vault at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Vault {
        Vault { path: path.into() }
    }

    /// Whether the file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Reads and decodes only the header.
    pub fn read_header(&self) -> Result<Header> {
        let bytes = file::read_all(&self.path)?;
        Ok(Header::decode(&bytes)?.0)
    }

    /// Creates a new vault file with the given slots and an empty body.
    /// Fails if the file already exists.
    pub fn create(
        &self,
        slots: Vec<KeySlot>,
        dek: Dek,
        vault_id: [u8; 16],
        now: &str,
    ) -> Result<UnlockedVault> {
        if self.exists() {
            return Err(Error::AlreadyExists(format!(
                "vault file {}",
                self.path.display()
            )));
        }
        let header = Header::new(vault_id, now, slots);
        let mut v = UnlockedVault {
            header,
            body: VaultBody::default(),
            dek,
            loaded_generation: 0,
        };
        v.write(self, true)?;
        Ok(v)
    }

    /// Opens the vault with an already-known DEK.
    pub fn open_with_dek(&self, dek: Dek) -> Result<UnlockedVault> {
        let bytes = file::read_all(&self.path)?;
        let (header, end) = Header::decode(&bytes)?;
        let nonce: [u8; aead::NONCE_LEN] = aead::to_array("body nonce", &header.body_nonce)?;
        let plaintext = aead::open(&dek, &nonce, &bytes[..end], &bytes[end..])?;
        let body = VaultBody::decode(&plaintext)?;
        Ok(UnlockedVault {
            loaded_generation: header.generation,
            header,
            body,
            dek,
        })
    }

    /// Unlocks the vault by trying key slots in order.
    ///
    /// The slot labelled `preferred` (if any) is tried first. Slots the resolver
    /// cannot handle, or whose backend reports [`Error::AuthUnavailable`], are
    /// skipped with a notice; [`Error::AuthCancelled`] and [`Error::Integrity`]
    /// (wrong passphrase / bad signature) abort immediately.
    pub fn unlock(
        &self,
        resolver: &dyn SlotResolver,
        ctx: &UnlockContext,
        preferred: Option<&str>,
    ) -> Result<UnlockedVault> {
        let header = self.read_header()?;
        if header.vault_id_arr() != ctx.vault_id {
            return Err(Error::Invalid(
                "unlock context vault id does not match the vault".into(),
            ));
        }
        let mut ordered: Vec<&KeySlot> = Vec::with_capacity(header.slots.len());
        if let Some(p) = preferred {
            match header.slot(p) {
                Some(s) => ordered.push(s),
                None => return Err(Error::Invalid(format!("no key slot labelled '{p}'"))),
            }
        }
        ordered.extend(
            header
                .slots
                .iter()
                .filter(|s| Some(s.label.as_str()) != preferred),
        );

        let mut skipped: Vec<String> = Vec::new();
        for slot in ordered {
            let Some((backend, envelope)) = resolver.resolve(slot) else {
                skipped.push(format!("{} (no backend on this platform)", slot.label));
                continue;
            };
            match open_slot(slot, backend, envelope, ctx) {
                Ok(dek) => return self.open_with_dek(dek),
                Err(Error::AuthUnavailable(reason)) => {
                    ctx.prompter
                        .notice(&format!("key slot '{}' unavailable: {reason}", slot.label));
                    skipped.push(format!("{} ({reason})", slot.label));
                }
                Err(e) => return Err(e),
            }
        }
        Err(Error::AuthUnavailable(format!(
            "no usable key slot; tried: {}",
            skipped.join(", ")
        )))
    }
}

impl UnlockedVault {
    /// The data encryption key.
    pub fn dek(&self) -> &Dek {
        &self.dek
    }

    /// Generation loaded from disk (for display / concurrency diagnostics).
    pub fn loaded_generation(&self) -> u64 {
        self.loaded_generation
    }

    /// Returns the vault with a new body.
    pub fn with_body(self, body: VaultBody) -> UnlockedVault {
        UnlockedVault { body, ..self }
    }

    /// Returns the vault with `f` applied to the body (functional update).
    pub fn map_body<F: FnOnce(&VaultBody) -> Result<VaultBody>>(
        self,
        f: F,
    ) -> Result<UnlockedVault> {
        let body = f(&self.body)?;
        Ok(self.with_body(body))
    }

    /// Returns the vault with new slots.
    pub fn with_slots(mut self, slots: Vec<KeySlot>) -> UnlockedVault {
        self.header.slots = slots;
        self
    }

    /// Returns the vault re-keyed with a fresh DEK. Callers must re-seal every slot.
    pub fn with_dek(self, dek: Dek) -> UnlockedVault {
        UnlockedVault { dek, ..self }
    }

    /// Persists header + body atomically. Increments the generation and uses a
    /// fresh body nonce. Fails with [`Error::Locked`] if the file on disk has a
    /// different generation than the one loaded (concurrent modification).
    pub fn save(&mut self, vault: &Vault) -> Result<()> {
        self.write(vault, false)
    }

    fn write(&mut self, vault: &Vault, creating: bool) -> Result<()> {
        let _guard = file::lock(&vault.path)?;
        if !creating {
            let on_disk = vault.read_header()?;
            if on_disk.generation != self.loaded_generation {
                return Err(Error::Locked);
            }
        } else if vault.exists() {
            return Err(Error::AlreadyExists(format!(
                "vault file {}",
                vault.path.display()
            )));
        }
        let mut header = self.header.clone();
        header.generation = if creating {
            1
        } else {
            self.loaded_generation + 1
        };
        let nonce = aead::random_nonce();
        header.body_nonce = nonce.to_vec();
        let prefix = header.encode()?;
        let plaintext = self.body.encode()?;
        let ct = aead::seal(&self.dek, &nonce, &prefix, &plaintext)?;
        let mut out = prefix;
        out.extend_from_slice(&ct);
        file::write_atomic(&vault.path, &out)?;
        self.header = header;
        self.loaded_generation = self.header.generation;
        Ok(())
    }
}

/// Fresh random vault id.
pub fn new_vault_id() -> [u8; 16] {
    aead::random_bytes()
}

/// Current UTC time as RFC 3339 (second precision).
pub fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Default vault path: `<data_local_dir>/wcm/vault.wcm`.
pub fn default_vault_path(data_local_dir: &Path) -> PathBuf {
    data_local_dir.join("wcm").join("vault.wcm")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::item::{Field, Item, ItemKind};
    use crate::slot::mock::{MockBackend, TestPrompter};
    use crate::slot::passphrase::PassphraseBackend;
    use crate::slot::{seal_slot, IdentityEnvelope};

    struct Resolver {
        hello: Option<MockBackend>,
        pass: Option<PassphraseBackend>,
    }
    impl SlotResolver for Resolver {
        fn resolve(&self, slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)> {
            match slot.kind() {
                crate::slot::SlotKind::Hello => self
                    .hello
                    .as_ref()
                    .map(|b| (b as &dyn KeySlotBackend, &IdentityEnvelope as &dyn Envelope)),
                crate::slot::SlotKind::Passphrase => self
                    .pass
                    .as_ref()
                    .map(|b| (b as &dyn KeySlotBackend, &IdentityEnvelope as &dyn Envelope)),
            }
        }
    }

    fn setup(dir: &Path) -> (Vault, [u8; 16], Dek) {
        let vault = Vault::new(dir.join("vault.wcm"));
        let vid = new_vault_id();
        let dek = aead::random_key();
        (vault, vid, dek)
    }

    fn ctx<'a>(p: &'a TestPrompter, vid: [u8; 16]) -> UnlockContext<'a> {
        UnlockContext {
            vault_id: vid,
            reason: "t",
            prompter: p,
            allow_ui: true,
        }
    }

    fn pass(pw: &str) -> PassphraseBackend {
        PassphraseBackend::with_secret(pw.into(), Argon2Params::FAST_TEST)
    }

    #[test]
    fn create_modify_save_reopen() {
        let dir = tempfile::tempdir().expect("tmp");
        let (vault, vid, dek) = setup(dir.path());
        let p = TestPrompter::default();
        let c = ctx(&p, vid);
        let hello = MockBackend::hello(b"h".to_vec());
        let slots = vec![
            seal_slot(1, "hello", &hello, &IdentityEnvelope, &c, &dek).expect("s1"),
            seal_slot(2, "recovery", &pass("pw"), &IdentityEnvelope, &c, &dek).expect("s2"),
        ];
        assert!(!vault.exists());
        let mut v = vault
            .create(slots, dek.clone(), vid, "2026-01-01T00:00:00Z")
            .expect("create");
        assert!(vault.exists());
        assert_eq!(v.header.generation, 1);
        assert!(matches!(
            vault.create(vec![], dek.clone(), vid, "x"),
            Err(Error::AlreadyExists(_))
        ));

        v = v
            .map_body(|b| {
                b.insert(
                    Item::new("a", ItemKind::Password, "t")
                        .with_field("password", Field::secret_text("s")),
                    false,
                )
            })
            .expect("ins");
        v.save(&vault).expect("save");
        assert_eq!(v.header.generation, 2);
        assert!(file::backup_path(&vault.path).exists());

        let reopened = vault.open_with_dek(dek.clone()).expect("open");
        assert_eq!(reopened.header.generation, 2);
        assert_eq!(
            reopened
                .body
                .get("a")
                .and_then(|i| i.primary())
                .and_then(|f| f.value.as_text()),
            Some("s")
        );
        assert_eq!(**reopened.dek(), *dek);

        let wrong = aead::random_key();
        assert!(matches!(
            vault.open_with_dek(wrong),
            Err(Error::Integrity(_))
        ));
        assert!(matches!(
            Vault::new(dir.path().join("nope.wcm")).read_header(),
            Err(Error::NotInitialized(_))
        ));
    }

    #[test]
    fn header_tampering_breaks_body_authentication() {
        let dir = tempfile::tempdir().expect("tmp");
        let (vault, vid, dek) = setup(dir.path());
        let p = TestPrompter::default();
        let c = ctx(&p, vid);
        let slot = seal_slot(1, "recovery", &pass("pw"), &IdentityEnvelope, &c, &dek).expect("s");
        vault
            .create(vec![slot], dek.clone(), vid, "t")
            .expect("create");
        let mut bytes = std::fs::read(&vault.path).expect("read");
        let (mut h, end) = Header::decode(&bytes).expect("dec");
        h.created = "1999-01-01T00:00:00Z".into();
        let mut forged = h.encode().expect("enc");
        forged.extend_from_slice(&bytes[end..]);
        std::fs::write(&vault.path, &forged).expect("write");
        assert!(matches!(
            vault.open_with_dek(dek.clone()),
            Err(Error::Integrity(_))
        ));
        // ciphertext tamper
        bytes[end] ^= 1;
        std::fs::write(&vault.path, &bytes).expect("write");
        assert!(matches!(vault.open_with_dek(dek), Err(Error::Integrity(_))));
    }

    #[test]
    fn concurrent_modification_is_detected() {
        let dir = tempfile::tempdir().expect("tmp");
        let (vault, vid, dek) = setup(dir.path());
        let p = TestPrompter::default();
        let c = ctx(&p, vid);
        let slot = seal_slot(1, "recovery", &pass("pw"), &IdentityEnvelope, &c, &dek).expect("s");
        let mut a = vault
            .create(vec![slot], dek.clone(), vid, "t")
            .expect("create");
        let mut b = vault.open_with_dek(dek.clone()).expect("open");
        b = b
            .map_body(|x| x.insert(Item::new("b", ItemKind::Note, "t"), false))
            .expect("i");
        b.save(&vault).expect("save b");
        a = a
            .map_body(|x| x.insert(Item::new("a", ItemKind::Note, "t"), false))
            .expect("i");
        assert!(matches!(a.save(&vault), Err(Error::Locked)));
        // reload and retry
        let mut fresh = vault.open_with_dek(dek).expect("open");
        fresh = fresh
            .map_body(|x| x.insert(Item::new("a", ItemKind::Note, "t"), false))
            .expect("i");
        fresh.save(&vault).expect("save");
        assert_eq!(fresh.body.items.len(), 2);
        assert_eq!(fresh.loaded_generation(), 3);
    }

    #[test]
    fn unlock_tries_slots_in_order_and_skips_unavailable() {
        let dir = tempfile::tempdir().expect("tmp");
        let (vault, vid, dek) = setup(dir.path());
        let p = TestPrompter::default();
        let c = ctx(&p, vid);
        let hello = MockBackend::hello(b"h".to_vec());
        let slots = vec![
            seal_slot(1, "hello", &hello, &IdentityEnvelope, &c, &dek).expect("s1"),
            seal_slot(2, "recovery", &pass("pw"), &IdentityEnvelope, &c, &dek).expect("s2"),
        ];
        vault.create(slots, dek.clone(), vid, "t").expect("create");

        // Hello available → used, passphrase untouched.
        let r = Resolver {
            hello: Some(MockBackend::hello(b"h".to_vec())),
            pass: Some(pass("pw")),
        };
        let v = vault.unlock(&r, &c, None).expect("unlock");
        assert_eq!(**v.dek(), *dek);
        assert_eq!(r.hello.as_ref().map(|h| h.open_calls.get()), Some(1));

        // Hello unavailable → notice + fall through to recovery.
        let mut h = MockBackend::hello(b"h".to_vec());
        h.fail_open = Some(Error::AuthUnavailable("key gone".into()));
        let r = Resolver {
            hello: Some(h),
            pass: Some(pass("pw")),
        };
        let v = vault.unlock(&r, &c, None).expect("unlock via recovery");
        assert_eq!(**v.dek(), *dek);
        assert!(p.notices.borrow().iter().any(|n| n.contains("key gone")));

        // No hello backend on this platform → skipped silently, recovery used.
        let r = Resolver {
            hello: None,
            pass: Some(pass("pw")),
        };
        assert!(vault.unlock(&r, &c, None).is_ok());

        // Preferred label first: wrong passphrase → Integrity (no fallthrough to hello).
        let r = Resolver {
            hello: Some(MockBackend::hello(b"h".to_vec())),
            pass: Some(pass("bad")),
        };
        assert!(matches!(
            vault.unlock(&r, &c, Some("recovery")),
            Err(Error::Integrity(_))
        ));
        assert_eq!(r.hello.as_ref().map(|h| h.open_calls.get()), Some(0));
        assert!(matches!(
            vault.unlock(&r, &c, Some("nope")),
            Err(Error::Invalid(_))
        ));

        // Cancel aborts.
        let mut h = MockBackend::hello(b"h".to_vec());
        h.fail_open = Some(Error::AuthCancelled);
        let r = Resolver {
            hello: Some(h),
            pass: Some(pass("pw")),
        };
        assert!(matches!(
            vault.unlock(&r, &c, None),
            Err(Error::AuthCancelled)
        ));

        // Nothing usable.
        let r = Resolver {
            hello: None,
            pass: None,
        };
        assert!(matches!(
            vault.unlock(&r, &c, None),
            Err(Error::AuthUnavailable(_))
        ));

        // Wrong vault id in context.
        let other = UnlockContext {
            vault_id: [0u8; 16],
            ..ctx(&p, vid)
        };
        assert!(matches!(
            vault.unlock(&r, &other, None),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn helpers() {
        let now = now_rfc3339();
        assert!(now.ends_with('Z') && now.len() == 20, "{now}");
        assert_ne!(new_vault_id(), new_vault_id());
        assert_eq!(
            default_vault_path(Path::new("/x")),
            PathBuf::from("/x/wcm/vault.wcm")
        );
    }
}
