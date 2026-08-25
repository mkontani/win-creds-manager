//! Wire protocol between `wcm` (client) and `wcm agent` (server): CBOR
//! messages in length-prefixed frames, one request and one response per
//! connection.

use std::fmt;
use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wcm_core::crypto::aead::KEY_LEN;
use wcm_core::slot::Dek;
use wcm_core::{Error, Result};
use zeroize::Zeroizing;

/// Bumped on any incompatible message change; both sides must agree.
pub const PROTOCOL_VERSION: u16 = 1;
/// Largest frame body accepted in either direction (bytes).
pub const MAX_FRAME: usize = 4096;

/// Vault identifier (the header's `vault_id`).
pub type VaultId = [u8; 16];

/// A DEK on the wire: raw bytes, zeroized on drop, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct WireDek(Zeroizing<Vec<u8>>);

impl WireDek {
    /// Wraps a vault key.
    pub fn from_dek(dek: &Dek) -> WireDek {
        WireDek(Zeroizing::new(dek.to_vec()))
    }

    /// Wraps arbitrary bytes (length is checked by [`WireDek::to_dek`]).
    pub fn from_bytes(bytes: Vec<u8>) -> WireDek {
        WireDek(Zeroizing::new(bytes))
    }

    /// The key, if it has exactly `KEY_LEN` bytes.
    pub fn to_dek(&self) -> Option<Dek> {
        if self.0.len() != KEY_LEN {
            return None;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&self.0);
        Some(key)
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for WireDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireDek({} bytes)", self.0.len())
    }
}

impl Serialize for WireDek {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serde_bytes::serialize(self.0.as_slice(), serializer)
    }
}

impl<'de> Deserialize<'de> for WireDek {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(WireDek(Zeroizing::new(bytes)))
    }
}

/// One request.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Request {
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u16,
    /// What to do.
    pub op: Op,
}

impl Request {
    /// A request for the current protocol version.
    pub fn new(op: Op) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            op,
        }
    }
}

/// Operations.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Op {
    /// Liveness check.
    Ping,
    /// Cache `dek` for `vault_id` (`path` is informational, shown by `status`).
    Put {
        #[serde(with = "serde_bytes")]
        vault_id: VaultId,
        path: String,
        dek: WireDek,
    },
    /// Fetch the cached key for `vault_id`.
    Get {
        #[serde(with = "serde_bytes")]
        vault_id: VaultId,
    },
    /// Forget the key for one vault.
    Lock {
        #[serde(with = "serde_bytes")]
        vault_id: VaultId,
    },
    /// Forget every key.
    LockAll,
    /// Report policy and cached entries.
    Status,
    /// Forget every key and exit.
    Stop,
}

/// Responses.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Response {
    /// Done.
    Ok,
    /// Cache hit.
    Dek { dek: WireDek },
    /// Cache miss (or expired).
    Miss,
    /// Answer to `Status`.
    Status {
        policy: PolicyInfo,
        entries: Vec<EntryInfo>,
    },
    /// Rejected request. `code` is `VERSION`, `BAD_REQUEST` or `INTERNAL`.
    Error { code: String, message: String },
}

/// Expiry policy as reported by `Status`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyInfo {
    pub idle_secs: u64,
    pub ttl_secs: u64,
    pub max_uses: Option<u32>,
}

/// One cached vault as reported by `Status` (no secrets).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    pub vault_id_hex: String,
    pub path: String,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub uses: u32,
    pub expires_in_secs: u64,
}

/// Encodes `value` as one frame: `u32` little-endian body length + CBOR body.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    ciborium::into_writer(value, &mut *body)
        .map_err(|e| Error::Helper(format!("agent: encode: {e}")))?;
    if body.len() > MAX_FRAME {
        return Err(Error::Helper(format!(
            "agent: frame too large ({} bytes, max {MAX_FRAME})",
            body.len()
        )));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Writes one frame and flushes.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    let frame = encode_frame(value)?;
    w.write_all(&frame)
        .map_err(|e| Error::Helper(format!("agent: write: {e}")))?;
    w.flush()
        .map_err(|e| Error::Helper(format!("agent: write: {e}")))
}

/// Reads one frame; bodies larger than [`MAX_FRAME`] are rejected before allocation.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|e| Error::Helper(format!("agent: read: {e}")))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Helper(format!(
            "agent: frame too large ({len} bytes, max {MAX_FRAME})"
        )));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body)
        .map_err(|e| Error::Helper(format!("agent: read: {e}")))?;
    ciborium::from_reader(&body[..]).map_err(|e| Error::Helper(format!("agent: decode: {e}")))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn dek(b: u8) -> Dek {
        Zeroizing::new([b; KEY_LEN])
    }

    fn every_op() -> Vec<Op> {
        vec![
            Op::Ping,
            Op::Put {
                vault_id: [1; 16],
                path: "C:\\v\\vault.wcm".into(),
                dek: WireDek::from_dek(&dek(2)),
            },
            Op::Get { vault_id: [3; 16] },
            Op::Lock { vault_id: [4; 16] },
            Op::LockAll,
            Op::Status,
            Op::Stop,
        ]
    }

    #[test]
    fn requests_round_trip_through_frames() {
        for op in every_op() {
            let frame = encode_frame(&Request::new(op)).expect("encode");
            let back: Request = read_frame(&mut Cursor::new(frame.to_vec())).expect("decode");
            assert_eq!(back.version, PROTOCOL_VERSION);
            let again = encode_frame(&back).expect("re-encode");
            assert_eq!(*frame, *again, "encoding is deterministic");
        }
    }

    #[test]
    fn responses_round_trip_through_frames() {
        let responses = vec![
            Response::Ok,
            Response::Dek {
                dek: WireDek::from_dek(&dek(9)),
            },
            Response::Miss,
            Response::Status {
                policy: PolicyInfo {
                    idle_secs: 600,
                    ttl_secs: 3600,
                    max_uses: Some(3),
                },
                entries: vec![EntryInfo {
                    vault_id_hex: "00".repeat(16),
                    path: "/v".into(),
                    age_secs: 1,
                    idle_secs: 0,
                    uses: 2,
                    expires_in_secs: 599,
                }],
            },
            Response::Error {
                code: "VERSION".into(),
                message: "nope".into(),
            },
        ];
        for response in responses {
            let mut buf = Vec::new();
            write_frame(&mut buf, &response).expect("write");
            let back: Response = read_frame(&mut Cursor::new(buf)).expect("read");
            assert_eq!(back, response);
        }
    }

    #[test]
    fn dek_and_vault_id_are_cbor_byte_strings() {
        let frame = encode_frame(&Op::Put {
            vault_id: [1; 16],
            path: "p".into(),
            dek: WireDek::from_dek(&dek(2)),
        })
        .expect("encode");
        let body = &frame[4..];
        // bstr(32) = 0x58 0x20 followed by the key; bstr(16) = 0x50 followed by the id.
        assert!(
            body.windows(2 + KEY_LEN)
                .any(|w| w[0] == 0x58 && w[1] == 0x20 && w[2..] == [2u8; KEY_LEN]),
            "dek should be a 32-byte cbor bstr"
        );
        assert!(
            body.windows(17)
                .any(|w| w[0] == 0x50 && w[1..] == [1u8; 16]),
            "vault_id should be a 16-byte cbor bstr"
        );
    }

    #[test]
    fn frame_length_prefix_is_little_endian_body_length() {
        let frame = encode_frame(&Op::Ping).expect("encode");
        let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
    }

    #[test]
    fn oversized_frames_are_rejected_both_ways() {
        let big = Op::Put {
            vault_id: [0; 16],
            path: "x".repeat(MAX_FRAME),
            dek: WireDek::from_dek(&dek(0)),
        };
        assert!(matches!(encode_frame(&big), Err(Error::Helper(_))));

        let mut bytes = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        bytes.extend([0u8; 8]);
        let err = read_frame::<_, Request>(&mut Cursor::new(bytes));
        assert!(matches!(err, Err(Error::Helper(_))));
    }

    #[test]
    fn truncated_frames_are_errors() {
        let frame = encode_frame(&Op::Ping).expect("encode");
        let short = frame[..frame.len() - 1].to_vec();
        assert!(read_frame::<_, Op>(&mut Cursor::new(short)).is_err());
        assert!(read_frame::<_, Op>(&mut Cursor::new(Vec::<u8>::new())).is_err());
    }

    #[test]
    fn wire_dek_checks_the_length_and_hides_bytes() {
        assert!(WireDek::from_bytes(vec![0; KEY_LEN - 1]).to_dek().is_none());
        assert!(WireDek::from_bytes(vec![0; KEY_LEN + 1]).to_dek().is_none());
        let d = WireDek::from_dek(&dek(7));
        assert_eq!(*d.to_dek().expect("32 bytes"), [7u8; KEY_LEN]);
        assert_eq!(d.len(), KEY_LEN);
        assert!(!d.is_empty());
        assert_eq!(format!("{d:?}"), "WireDek(32 bytes)");
    }
}
