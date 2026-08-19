//! Golden vault vectors. Any change to the v1 format must keep these opening.
//!
//! Regenerate a *new* vector (never overwrite an old one) with:
//! `WCM_WRITE_VECTORS=1 cargo test -p wcm-core --test vectors`

use std::path::PathBuf;

use wcm_core::crypto::kdf::Argon2Params;
use wcm_core::item::{Field, Item, ItemKind};
use wcm_core::slot::mock::TestPrompter;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{
    seal_slot, Envelope, IdentityEnvelope, KeySlot, KeySlotBackend, UnlockContext,
};
use wcm_core::vault::{SlotResolver, Vault};

const PASSPHRASE: &str = "test-passphrase";

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v1")
        .join(name)
}

struct PassResolver(PassphraseBackend);
impl SlotResolver for PassResolver {
    fn resolve(&self, _slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)> {
        Some((&self.0, &IdentityEnvelope))
    }
}

fn write_basic_vector() {
    let path = vector_path("basic.wcm");
    if path.exists() {
        panic!("refusing to overwrite existing vector {}", path.display());
    }
    let vault = Vault::new(&path);
    let vid: [u8; 16] = *b"wcm-vector-0001!";
    let dek = wcm_core::crypto::aead::random_key();
    let p = TestPrompter::default();
    let ctx = UnlockContext {
        vault_id: vid,
        reason: "vector",
        prompter: &p,
        allow_ui: false,
    };
    let backend = PassphraseBackend::with_secret(PASSPHRASE.into(), Argon2Params::FAST_TEST);
    let slot = seal_slot(1, "recovery", &backend, &IdentityEnvelope, &ctx, &dek).expect("seal");
    let mut v = vault
        .create(vec![slot], dek, vid, "2026-08-19T00:00:00Z")
        .expect("create");
    v = v
        .map_body(|b| {
            b.insert(
                Item::new("github/token", ItemKind::Token, "2026-08-19T00:00:00Z")
                    .with_field("token", Field::secret_text("ghp_example"))
                    .with_field("username", Field::public_text("octocat"))
                    .with_tags(vec!["work".into()]),
                false,
            )
        })
        .expect("insert");
    v = v
        .map_body(|b| {
            b.insert(
                Item::new("files/blob", ItemKind::File, "2026-08-19T00:00:00Z")
                    .with_field("content", Field::secret_bytes(vec![0, 1, 2, 3, 255, 254]))
                    .with_notes("binary sample"),
                false,
            )
        })
        .expect("insert");
    v.save(&vault).expect("save");
    let _ = std::fs::remove_file(wcm_core::vault::file::lock_path(&path));
    let _ = std::fs::remove_file(wcm_core::vault::file::backup_path(&path));
}

#[test]
fn basic_v1_vector_opens_and_matches() {
    if std::env::var_os("WCM_WRITE_VECTORS").is_some() {
        write_basic_vector();
    }
    let path = vector_path("basic.wcm");
    let vault = Vault::new(&path);
    let header = vault.read_header().expect("header");
    assert_eq!(header.v, 1);
    assert_eq!(header.vault_id, b"wcm-vector-0001!".to_vec());
    assert_eq!(header.generation, 2);
    assert_eq!(header.slots.len(), 1);
    assert_eq!(header.slots[0].label, "recovery");

    let p = TestPrompter::default();
    let ctx = UnlockContext {
        vault_id: header.vault_id_arr(),
        reason: "vector",
        prompter: &p,
        allow_ui: false,
    };
    let resolver = PassResolver(PassphraseBackend::with_secret(
        PASSPHRASE.into(),
        Argon2Params::FAST_TEST,
    ));
    let v = vault.unlock(&resolver, &ctx, None).expect("unlock");
    assert_eq!(v.body.items.len(), 2);
    let tok = v.body.get("github/token").expect("token item");
    assert_eq!(tok.kind, ItemKind::Token);
    assert_eq!(
        tok.primary().and_then(|f| f.value.as_text()),
        Some("ghp_example")
    );
    assert_eq!(tok.fields.get("username").map(|f| f.secret), Some(false));
    assert_eq!(tok.tags, vec!["work".to_string()]);
    let blob = v.body.get("files/blob").expect("blob item");
    assert_eq!(
        blob.primary().map(|f| f.value.as_bytes().to_vec()),
        Some(vec![0, 1, 2, 3, 255, 254])
    );
    assert_eq!(blob.notes, "binary sample");

    let wrong = PassResolver(PassphraseBackend::with_secret(
        "nope".into(),
        Argon2Params::FAST_TEST,
    ));
    assert!(matches!(
        vault.unlock(&wrong, &ctx, None),
        Err(wcm_core::Error::Integrity(_))
    ));
}
