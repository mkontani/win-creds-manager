//! Shared helpers for CLI integration tests (passphrase backend, temp vault).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Passphrase used by all tests (via `WCM_PASSPHRASE`).
pub const PASS: &str = "test-passphrase-123";

/// A temporary vault directory.
pub struct TestVault {
    pub dir: TempDir,
}

impl TestVault {
    /// Fresh, uninitialized vault location.
    pub fn new() -> TestVault {
        TestVault {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Vault file path.
    pub fn path(&self) -> PathBuf {
        self.dir.path().join("vault.wcm")
    }

    /// A `wcm` command pre-configured for this vault with the test passphrase and no Hello.
    pub fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("wcm").expect("wcm binary");
        c.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            c.env("PATH", path);
        }
        c.env("WCM_VAULT", self.path());
        c.env("WCM_PASSPHRASE", PASS);
        c.env("WCM_NO_WSL_PROXY", "1");
        c.env("HOME", self.dir.path());
        c.arg("--no-input");
        c
    }

    /// Initializes the vault with a passphrase slot (fast Argon2) and returns the recovery key.
    pub fn init(&self) -> String {
        let out = self
            .cmd()
            .args([
                "--json",
                "init",
                "--no-hello",
                "--passphrase",
                "--argon2-test-params",
            ])
            .output()
            .expect("run init");
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("init json");
        v["recovery_key"]
            .as_str()
            .expect("recovery_key")
            .to_string()
    }

    /// Initialized vault.
    pub fn initialized() -> (TestVault, String) {
        let v = TestVault::new();
        let key = v.init();
        (v, key)
    }
}

/// Parses stdout as JSON.
pub fn json(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid json ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Parses the JSON error envelope from stderr.
pub fn json_err(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stderr).unwrap_or_else(|e| {
        panic!(
            "invalid json error ({e}): {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Writes a file in the test dir.
pub fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("write file");
    p
}

// ---------------------------------------------------------------------------
// Direct vault manipulation (for tests of commands that do not depend on `add`).
// ---------------------------------------------------------------------------

use wcm_core::crypto::kdf::Argon2Params;
use wcm_core::item::{Field, Item, ItemKind};
use wcm_core::slot::mock::TestPrompter;
use wcm_core::slot::passphrase::PassphraseBackend;
use wcm_core::slot::{Envelope, IdentityEnvelope, KeySlot, KeySlotBackend, UnlockContext};
use wcm_core::vault::{SlotResolver, Vault, VaultBody};

/// Label of the passphrase slot created by [`TestVault::init`].
pub const PASSPHRASE_SLOT: &str = "passphrase";

/// Resolver that opens every slot with the fixed test passphrase.
struct PassResolver(PassphraseBackend);

impl SlotResolver for PassResolver {
    fn resolve(&self, _slot: &KeySlot) -> Option<(&dyn KeySlotBackend, &dyn Envelope)> {
        Some((&self.0, &IdentityEnvelope))
    }
}

impl TestVault {
    /// Opens the initialized vault with the test passphrase, applies `f` to the
    /// body and saves the result (one generation bump).
    pub fn with_body<F>(&self, f: F)
    where
        F: FnOnce(&VaultBody) -> wcm_core::Result<VaultBody>,
    {
        let vault = Vault::new(self.path());
        let header = vault.read_header().expect("read header");
        let prompter = TestPrompter::default();
        let ctx = UnlockContext {
            vault_id: header.vault_id_arr(),
            reason: "test setup",
            prompter: &prompter,
            allow_ui: false,
        };
        let resolver = PassResolver(PassphraseBackend::with_secret(
            PASS.into(),
            Argon2Params::FAST_TEST,
        ));
        let mut v = vault
            .unlock(&resolver, &ctx, Some(PASSPHRASE_SLOT))
            .expect("unlock test vault");
        v = v.map_body(f).expect("apply body change");
        v.save(&vault).expect("save test vault");
    }

    /// Inserts items directly into the vault (overwriting same-named items).
    pub fn insert_items(&self, items: Vec<Item>) {
        self.with_body(|body| {
            items
                .iter()
                .try_fold(body.clone(), |b, item| b.insert(item.clone(), true))
        });
    }

    /// Reads the vault body back (for assertions).
    pub fn read_body(&self) -> VaultBody {
        let mut captured = None;
        self.with_body(|body| {
            captured = Some(body.clone());
            Ok(body.clone())
        });
        captured.expect("body captured")
    }
}

/// Builds an item with text fields; keys listed in `secret_keys` are marked secret.
pub fn text_item(
    name: &str,
    kind: ItemKind,
    fields: &[(&str, &str)],
    secret_keys: &[&str],
) -> Item {
    let now = wcm_core::vault::now_rfc3339();
    fields
        .iter()
        .fold(Item::new(name, kind, &now), |item, (k, v)| {
            let f = if secret_keys.contains(k) {
                Field::secret_text(*v)
            } else {
                Field::public_text(*v)
            };
            item.with_field(k, f)
        })
}

/// A freshly generated OpenSSH key pair for tests.
pub struct TestSshKey {
    /// OpenSSH PEM private key (LF line endings, trailing newline).
    pub private_pem: String,
    /// `authorized_keys` line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
}

/// Generates an ed25519 key; `passphrase` encrypts the private key.
pub fn gen_ssh_key(comment: &str, passphrase: Option<&str>) -> TestSshKey {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("keygen");
    key.set_comment(comment);
    let public_key = key.public_key().to_openssh().expect("pubkey");
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let key = match passphrase {
        Some(p) => key.encrypt(&mut OsRng, p).expect("encrypt"),
        None => key,
    };
    let private_pem = key.to_openssh(LineEnding::LF).expect("pem").to_string();
    TestSshKey {
        private_pem,
        public_key,
        fingerprint,
    }
}

/// An `ssh-key` item with `private_key`, `public_key` and `fingerprint` fields.
pub fn ssh_item(name: &str, key: &TestSshKey) -> Item {
    text_item(
        name,
        ItemKind::SshKey,
        &[
            ("private_key", key.private_pem.as_str()),
            ("public_key", key.public_key.as_str()),
            ("fingerprint", key.fingerprint.as_str()),
        ],
        &["private_key"],
    )
}
