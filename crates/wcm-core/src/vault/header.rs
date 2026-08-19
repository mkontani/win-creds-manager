//! Plaintext vault header. The raw header bytes (magic + length + CBOR) are the
//! AAD of the body, so any modification breaks authentication.

use serde::{Deserialize, Serialize};

use crate::crypto::aead::NONCE_LEN;
use crate::slot::KeySlot;
use crate::{Error, Result};

/// File magic; the last byte is the format major version.
pub const MAGIC: [u8; 4] = *b"WCM\x01";
/// Format version stored inside the header.
pub const FORMAT_VERSION: u8 = 1;
/// Body cipher identifier.
pub const BODY_CIPHER: &str = "xchacha20poly1305";
/// Upper bound for the CBOR header (defensive; real headers are a few KiB).
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
/// Length of magic + header length prefix.
pub const PREFIX_LEN: usize = 8;

/// Plaintext header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Format version (1).
    pub v: u8,
    /// 16-byte vault id.
    #[serde(with = "serde_bytes")]
    pub vault_id: Vec<u8>,
    /// RFC 3339 creation time.
    pub created: String,
    /// Monotonic write counter.
    pub generation: u64,
    /// Key slots (at least one).
    pub slots: Vec<KeySlot>,
    /// Body cipher id.
    pub body_cipher: String,
    /// 24-byte body nonce (fresh per write).
    #[serde(with = "serde_bytes")]
    pub body_nonce: Vec<u8>,
}

impl Header {
    /// New header for a fresh vault (generation 0, empty nonce filled by the writer).
    pub fn new(vault_id: [u8; 16], created: &str, slots: Vec<KeySlot>) -> Header {
        Header {
            v: FORMAT_VERSION,
            vault_id: vault_id.to_vec(),
            created: created.to_string(),
            generation: 0,
            slots,
            body_cipher: BODY_CIPHER.to_string(),
            body_nonce: vec![0u8; NONCE_LEN],
        }
    }

    /// Encodes `magic || len(u32 LE) || cbor`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut cbor = Vec::new();
        ciborium::into_writer(self, &mut cbor)
            .map_err(|e| Error::Integrity(format!("header encode: {e}")))?;
        if cbor.len() > MAX_HEADER_LEN {
            return Err(Error::Integrity("header too large".into()));
        }
        let mut out = Vec::with_capacity(PREFIX_LEN + cbor.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(cbor.len() as u32).to_le_bytes());
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decodes a header from the start of `bytes`; returns it and the total prefix
    /// length (`8 + header_len`), which is the AAD boundary.
    pub fn decode(bytes: &[u8]) -> Result<(Header, usize)> {
        if bytes.len() < PREFIX_LEN {
            return Err(Error::Integrity("file too short".into()));
        }
        if bytes[..4] != MAGIC {
            if bytes[..3] == MAGIC[..3] {
                return Err(Error::Integrity(format!(
                    "unsupported vault format version {} (this build supports {})",
                    bytes[3], MAGIC[3]
                )));
            }
            return Err(Error::Integrity("not a wcm vault (bad magic)".into()));
        }
        let len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        if len > MAX_HEADER_LEN {
            return Err(Error::Integrity("header length out of range".into()));
        }
        let end = PREFIX_LEN + len;
        if bytes.len() < end {
            return Err(Error::Integrity("truncated header".into()));
        }
        let header: Header = ciborium::from_reader(&bytes[PREFIX_LEN..end])
            .map_err(|e| Error::Integrity(format!("header decode: {e}")))?;
        header.validate()?;
        Ok((header, end))
    }

    /// Vault id as an array.
    pub fn vault_id_arr(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.vault_id[..16]);
        a
    }

    /// Hex vault id.
    pub fn vault_id_hex(&self) -> String {
        self.vault_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Finds a slot by label.
    pub fn slot(&self, label: &str) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.label == label)
    }

    /// Next unused slot id.
    pub fn next_slot_id(&self) -> Result<u8> {
        (1..=u8::MAX)
            .find(|id| !self.slots.iter().any(|s| s.id == *id))
            .ok_or_else(|| Error::Invalid("no free slot id".into()))
    }

    fn validate(&self) -> Result<()> {
        if self.v != FORMAT_VERSION {
            return Err(Error::Integrity(format!(
                "unsupported header version {}",
                self.v
            )));
        }
        if self.vault_id.len() != 16 {
            return Err(Error::Integrity("vault_id must be 16 bytes".into()));
        }
        if self.body_cipher != BODY_CIPHER {
            return Err(Error::Integrity(format!(
                "unsupported body cipher {}",
                self.body_cipher
            )));
        }
        if self.body_nonce.len() != NONCE_LEN {
            return Err(Error::Integrity("body nonce must be 24 bytes".into()));
        }
        if self.slots.is_empty() {
            return Err(Error::Integrity("vault has no key slots".into()));
        }
        let mut ids: Vec<u8> = self.slots.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.slots.len() {
            return Err(Error::Integrity("duplicate slot ids".into()));
        }
        // Labels address slots (`--slot`, `slot rm`): duplicates make every such
        // command ambiguous, so they are a header defect, not a user error.
        let mut labels: Vec<&str> = self.slots.iter().map(|s| s.label.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        if labels.len() != self.slots.len() {
            return Err(Error::Integrity("duplicate slot labels".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::slot::SlotParams;

    fn slot(id: u8) -> KeySlot {
        KeySlot {
            id,
            label: format!("s{id}"),
            salt: vec![1; 32],
            nonce: vec![2; 24],
            ct: vec![3; 48],
            params: SlotParams::Passphrase {
                argon2: Argon2Params::FAST_TEST,
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let h = Header::new([9u8; 16], "2026-01-01T00:00:00Z", vec![slot(1), slot(2)]);
        let bytes = h.encode().expect("encode");
        assert_eq!(&bytes[..4], b"WCM\x01");
        let (back, end) = Header::decode(&bytes).expect("decode");
        assert_eq!(back, h);
        assert_eq!(end, bytes.len());
        assert_eq!(back.vault_id_arr(), [9u8; 16]);
        assert_eq!(back.vault_id_hex(), "09".repeat(16));
        assert_eq!(back.slot("s2").map(|s| s.id), Some(2));
        assert_eq!(back.next_slot_id().expect("id"), 3);
    }

    #[test]
    fn decode_rejects_bad_inputs() {
        let h = Header::new([9u8; 16], "t", vec![slot(1)]);
        let bytes = h.encode().expect("encode");

        assert!(matches!(
            Header::decode(&bytes[..5]),
            Err(Error::Integrity(_))
        ));
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            Header::decode(&bad_magic),
            Err(Error::Integrity(_))
        ));
        let mut bad_ver = bytes.clone();
        bad_ver[3] = 2;
        let err = Header::decode(&bad_ver).expect_err("version");
        assert!(err.to_string().contains("version 2"));
        let mut huge = bytes.clone();
        huge[4..8].copy_from_slice(&(MAX_HEADER_LEN as u32 + 1).to_le_bytes());
        assert!(matches!(Header::decode(&huge), Err(Error::Integrity(_))));
        let mut truncated = bytes.clone();
        truncated[4..8].copy_from_slice(&((bytes.len()) as u32).to_le_bytes());
        assert!(matches!(
            Header::decode(&truncated),
            Err(Error::Integrity(_))
        ));
        let mut garbage = bytes.clone();
        garbage[8] = 0xff;
        assert!(matches!(Header::decode(&garbage), Err(Error::Integrity(_))));
    }

    #[test]
    fn validation_rules() {
        let mut h = Header::new([9u8; 16], "t", vec![]);
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
        h.slots = vec![slot(1), slot(1)];
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
        // Same label on two different slots: `--slot LABEL` would be ambiguous.
        let mut dup = slot(2);
        dup.label = slot(1).label;
        h.slots = vec![slot(1), dup];
        let err = h.encode().expect_err("duplicate labels");
        assert!(err.to_string().contains("duplicate slot labels"), "{err}");
        h.slots = vec![slot(1)];
        h.body_cipher = "aes".into();
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
        h.body_cipher = BODY_CIPHER.into();
        h.body_nonce = vec![0; 12];
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
        h.body_nonce = vec![0; 24];
        h.vault_id = vec![0; 15];
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
        h.vault_id = vec![0; 16];
        h.v = 7;
        assert!(matches!(h.encode(), Err(Error::Integrity(_))));
    }
}
