# wcm vault format v1

This document describes the on-disk format of a `wcm` vault (`vault.wcm`)
byte by byte. Encrypted exports (`wcm export`) use exactly the same format
with a single passphrase slot, so everything here applies to them too.

Source of truth: `crates/wcm-core/src/vault/{header,body,mod,file}.rs`,
`crates/wcm-core/src/slot/{mod,passphrase}.rs`,
`crates/wcm-core/src/crypto/{aead,kdf}.rs`.

## 1. File layout

```
offset  size      content
0       4         magic        = b"WCM\x01"   (last byte = format major version)
4       4         header_len   = u32 little-endian, length of the CBOR header
8       header_len CBOR header (plaintext, see §2)
8+len   rest      body_ct      = XChaCha20-Poly1305(DEK, body_nonce, aad = file[0 .. 8+len], CBOR body) || 16-byte tag
```

* `PREFIX_LEN = 8`. The first `8 + header_len` bytes (magic, length and header)
  are the **additional authenticated data** of the body, so modifying any
  header field — even a cosmetic one like `created` — makes body decryption
  fail with `Integrity` (exit 8).
* `header_len` is bounded by `MAX_HEADER_LEN = 1 MiB`; larger values are
  rejected before parsing.
* A file shorter than 8 bytes, a bad magic, or a magic whose last byte is not
  `0x01` is rejected (`unsupported vault format version N`).
* There is exactly one body ciphertext; there are no per-item ciphertexts.
  Item names are therefore encrypted too (`wcm ls` needs an unlock).

## 2. Header (CBOR)

The header is a CBOR map produced by `ciborium` from the `Header` struct
(definite-length map, text keys, fields in declaration order):

| key           | CBOR type           | meaning |
|---------------|---------------------|---------|
| `v`           | uint (= 1)          | `FORMAT_VERSION`; must equal 1 |
| `vault_id`    | bstr (16)           | random vault id; binds slots, Hello credential name and DPAPI entropy to this vault |
| `created`     | tstr                | RFC 3339 creation time (`YYYY-MM-DDTHH:MM:SSZ`) |
| `generation`  | uint                | monotonic write counter; `1` after `init`, `+1` per save |
| `slots`       | array of KeySlot    | at least one; ids unique |
| `body_cipher` | tstr                | must be `"xchacha20poly1305"` |
| `body_nonce`  | bstr (24)           | fresh random nonce for the body on every write |

Validation (`Header::validate`, applied on encode *and* decode): `v == 1`,
`vault_id` is 16 bytes, `body_cipher` matches, `body_nonce` is 24 bytes,
`slots` non-empty, slot ids unique. Any violation is `Integrity`.

### 2.1 KeySlot

Each element of `slots` is a CBOR map (field order as listed):

| key      | CBOR type | meaning |
|----------|-----------|---------|
| `id`     | uint (u8) | slot id, unique within the vault (1, 2, …); part of the slot AAD |
| `label`  | tstr      | human label: `hello`, `recovery`, `passphrase`, … (used by `--slot LABEL`) |
| `salt`   | bstr (32) | HKDF salt; for passphrase slots also the Argon2id salt |
| `nonce`  | bstr (24) | XChaCha20-Poly1305 nonce for the wrapped DEK |
| `ct`     | bstr      | wrapped DEK: `XChaCha20-Poly1305(KEK, nonce, slot_aad, DEK)` = 32 + 16 = **48 bytes** — unless enveloped by DPAPI (§2.3), in which case it is the opaque DPAPI blob |
| `params` | map       | `SlotParams`, internally tagged on `kind` (§2.2) |

`SlotKind` numeric values (part of the AAD): `Hello = 1`, `Passphrase = 2`.
The kind is *derived from `params`*, never stored separately.

### 2.2 SlotParams

`#[serde(tag = "kind", rename_all = "lowercase")]`:

**Hello** (`kind: "hello"`):

| key         | CBOR type | meaning |
|-------------|-----------|---------|
| `cred_name` | tstr      | `KeyCredentialManager` credential name: `wcm-v1-<vault_id as 32 lowercase hex>` |
| `challenge` | bstr (32) | fixed random challenge signed on every unlock |
| `spki_der`  | bstr      | X.509 SubjectPublicKeyInfo (DER) of the Hello RSA-2048 key; signatures are verified against it (fail closed) |
| `dpapi`     | bool      | whether `ct` is additionally wrapped with DPAPI |
| `hw_backed` | bool      | whether attestation reported a TPM-backed key (informational; `wcm init` warns when `false`) |

**Passphrase** (`kind: "passphrase"`):

| key      | CBOR type | meaning |
|----------|-----------|---------|
| `argon2` | map `{m_kib: uint, t: uint, p: uint}` | Argon2id cost parameters used for this slot |

Argon2 defaults (`Argon2Params::DEFAULT`): `m_kib = 65536` (64 MiB),
`t = 3`, `p = 1`, output 32 bytes, Argon2id v0x13. Tests use
`FAST_TEST = {64, 1, 1}` (the hidden `--argon2-test-params` flag). Parameters
are stored per slot so they can be raised later without a format bump.

### 2.3 DPAPI envelope (Hello slot only, Windows only)

When `params.dpapi == true`, `ct` = `CryptProtectData(wrapped_dek,
description = "wcm", entropy = vault_id (16 bytes), flags =
CRYPTPROTECT_UI_FORBIDDEN)`. The envelope is applied **after** AEAD wrapping
and removed **before** AEAD unwrapping. It binds the Hello slot to the Windows
user profile as defense in depth; recovery/passphrase slots are never
enveloped so they stay portable to other machines and OSes. If DPAPI fails
(profile migrated, different user), the Hello slot is unusable and the vault
is opened through the recovery slot (`wcm recover` re-creates the Hello slot).

## 3. Key hierarchy

```
                 backend ikm
 Hello:      sig = RSASSA-PKCS1-v1_5/SHA-256(HelloKey, challenge)   (deterministic, 256 B)
             verify(spki_der, challenge, sig) must succeed, else Integrity (never used as ikm)
 Passphrase: ikm = Argon2id(secret, salt = slot.salt, params)        (32 B)
             recovery key secret = canonical "WCM1-XXXX-…-XXXX" string (uppercase, dashes)

 KEK = HKDF-SHA256(ikm, salt = slot.salt, info = INFO || vault_id)   (32 B)
       INFO = b"wcm/v1/kek/hello"  or  b"wcm/v1/kek/passphrase"
 slot.ct = XChaCha20-Poly1305(KEK, slot.nonce, aad = slot_aad, DEK)  (48 B)  [→ DPAPI]
 body_ct = XChaCha20-Poly1305(DEK, body_nonce, aad = file[0..8+len], CBOR body)
```

* **DEK** — 32 random bytes (OS CSPRNG), one per vault. Every slot wraps the
  *same* DEK. `wcm rekey` draws a fresh DEK and re-seals all slots.
* **slot_aad** (`slot::slot_aad`) = `b"wcm/v1/slot"` (11 bytes) ‖ `vault_id`
  (16) ‖ `id` (1 byte) ‖ `kind` (1 byte, 1 = Hello, 2 = Passphrase) — 29 bytes.
  A slot copied to another vault, renumbered, or relabelled as a different
  kind fails to unwrap.
* **HKDF** (`kdf::derive_kek`): extract with `salt`, expand with
  `info = INFO_LABEL ‖ vault_id`, 32 bytes out. The label separates Hello and
  passphrase domains; `vault_id` binds the KEK to the vault. Pinned test vector:
  `derive_kek(b"ikm", [0;32], INFO_HELLO, [0;16]) =
  5a9321816d17ea0bc5fa6269162a1d90568e3d151746bc39aee1f527c5e20262`.
* **Hello signature**: `KeyCredential.RequestSignAsync` over the 32-byte
  challenge returns an RSASSA-PKCS1-v1_5 signature with SHA-256, which is
  deterministic for a given key and message. The signature is verified
  against the stored `spki_der` *before* it is fed to HKDF: a randomized (PSS)
  or foreign signature cannot silently derive a wrong KEK; it fails closed
  with `Integrity`.
* **Recovery key**: 18 random bytes + 2 checksum bytes (first two bytes of
  SHA-256 of the random part), base32 (RFC 4648, no padding) → 32 characters,
  displayed as `WCM1-` + 8 groups of 4. Parsing is case-insensitive, ignores
  dashes/spaces/underscores and maps `0→O`, `1→I`, `8→B`. The *canonical
  display string* (not the raw bytes) is the Argon2id input, so a recovery slot
  is simply a passphrase slot with a 144-bit random passphrase.

## 4. Body (CBOR, encrypted)

```
{
  "items": [ Item, ... ],          // kept sorted by name
  "settings": { "last_export": tstr? }   // key omitted when None
}
```

**Item** (map, field order as listed):

| key       | CBOR type | meaning |
|-----------|-----------|---------|
| `id`      | bstr (16) | random, stable across renames |
| `name`    | tstr      | unique; 1..=200 chars, no control chars, no leading `-`, no leading/trailing `/`, no `..` or empty `/` segments, no surrounding whitespace |
| `kind`    | tstr      | `password` · `login` · `token` · `ssh-key` · `file` · `note` |
| `fields`  | map tstr → `{ "value": tstr \| bstr, "secret": bool }` | field values; text fields are CBOR text strings, binary fields (`--file`) are CBOR byte strings |
| `notes`   | tstr      | free-form notes |
| `tags`    | array tstr | sorted, deduplicated |
| `created` | tstr      | RFC 3339 |
| `updated` | tstr      | RFC 3339 |

The *primary* field per kind (what `wcm get NAME` prints without `--field`):
`password`/`login` → `password`, `token` → `token`, `ssh-key` → `private_key`,
`file` → `content`, `note` → `note`. `ssh-key` items also carry derived
non-secret `public_key` and `fingerprint` fields.

In human-readable encodings (plaintext JSON export, `--json` output) binary
values are represented as `{"b64": "<base64>"}`; text values as JSON strings.

## 5. Write, lock, backup and generation semantics

`UnlockedVault::save` (`vault/mod.rs` + `vault/file.rs`):

1. Acquire an exclusive advisory lock on `<vault>.lock` (blocking; file is
   created next to the vault and left in place).
2. Re-read the header from disk. If `generation` on disk differs from the
   generation that was loaded when the vault was unlocked, fail with
   `Locked` (exit 9) — another process saved in between. The caller retries
   from a fresh unlock; wcm never merges blindly.
3. `generation += 1`, draw a fresh `body_nonce`, encode header → prefix,
   encode body → CBOR, `seal(DEK, nonce, prefix, body)`.
4. Write `prefix ‖ ct` to a temp file in the same directory
   (`.vault-XXXX.tmp`), `fsync` it.
5. If the vault already exists, copy it to `<vault>.bak` (best effort; the
   backup is the *previous* generation and is readable with the same slots).
6. Atomically rename the temp file over the vault (`persist`).
7. Release the lock.

`Vault::create` writes generation `1` and fails with `AlreadyExists` if the
file exists. Creation also takes the lock. `wcm status` / `wcm doctor` read
only the header and never take the lock.

Because the nonce is fresh on every write and the DEK never changes between
writes (unless `rekey`), the nonce/key pair is unique per ciphertext; the
24-byte XChaCha nonce makes random generation safe.

## 6. Encrypted export

`wcm export -o file.wcm` writes a vault file with the *same* header/body
format and a single passphrase slot (Argon2id with `DEFAULT` parameters, key
from `WCM_EXPORT_PASSPHRASE` or a prompt), its own `vault_id` and DEK. Any
`wcm` build on any OS can open it with `wcm --vault file.wcm ls` (the only
slot is a passphrase slot, so no Hello is involved). Plaintext export
(`--plaintext --i-know`) is the JSON document
`{"version": 1, "exported": "<RFC3339>", "items": [...]}` (`PlainExport`).

## 7. Golden vector

`crates/wcm-core/tests/vectors/v1/basic.wcm` is a committed vault
(`vault_id = b"wcm-vector-0001!"`, generation 2, one `recovery` slot with
passphrase `test-passphrase` and `FAST_TEST` Argon2 parameters, two items:
`github/token` and `files/blob`). `cargo test -p wcm-core --test vectors`
must keep opening it unchanged; any change to the v1 code path that breaks
the vector is a format break and requires a new magic version byte and a
*new* vector file (old vectors are never overwritten; regenerate a fresh one
with `WCM_WRITE_VECTORS=1`).

## 8. Versioning rules

* The magic's last byte is the major version; readers reject other values.
* The serde structs do not use `deny_unknown_fields`, so a newer writer may
  add optional keys (marked `#[serde(default)]` on the reader side) without
  breaking older readers of the same major version; removing keys or changing
  their types is a major version bump.
* Argon2 parameters, slot kinds and cipher ids are recorded in the file so
  they can evolve per slot; the body cipher id is checked and currently only
  `xchacha20poly1305` is accepted.
