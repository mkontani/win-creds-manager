# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The vault file format has its own major version (magic `WCM\x01`), documented
in [docs/FORMAT.md](docs/FORMAT.md); format changes are called out explicitly.

## [Unreleased]

## [0.1.0] - 2026-08-19

### Added

- **Vault format v1** (`wcm-core`): single-file vault `WCM\x01 || u32 len ||
  CBOR header || XChaCha20-Poly1305 body` with the header as AEAD associated
  data; encrypted item names; atomic writes with `.bak`; advisory lock and
  generation check for concurrent writers; committed golden vector
  `tests/vectors/v1/basic.wcm`.
- **Key slots**: Windows Hello slot (deterministic RSASSA-PKCS1-v1_5 signature
  over a per-vault challenge, verified against the stored SPKI, HKDF-SHA256 →
  KEK), mandatory recovery-key slot and optional passphrase slots (Argon2id
  64 MiB/3/1 → HKDF), all wrapping one random DEK; slot AAD binds vault id,
  slot id and kind. DPAPI envelope (`CryptProtectData`, UI forbidden, vault
  id as entropy) on the Hello slot.
- **`wcm-hello`**: `KeyCredentialManager` backend via the `windows` crate
  (open → create → sign → verify state machine, one transient-TPM-error retry,
  attestation → `hw_backed`), session-0 detection, foreground-focus helper for
  the Hello dialog (`WCM_HELLO_FOCUS=0` to disable), DPAPI envelope. Fully
  unit-tested off-Windows through a `FakeKcm`.
- **`wcm` CLI**: `init`, `add`, `set`, `get`, `show`, `ls`, `rm`, `mv`,
  `generate`, `ssh add|pubkey|remove`, `run --env`, `export`/`import`
  (encrypted `.wcm` or plaintext JSON), `recover`, `rekey`, `slot ls|add|rm`,
  `status`, `doctor [--hello-selftest]`, `completions`, `version`,
  `--exit-codes`; global `--vault`, `--json`, `--slot`, `--no-input`, `--quiet`.
  One Windows Hello prompt per invocation. Clipboard copy with timed clear
  (`--clip`, detached `wcm unclip`). Item kinds password/login/token/ssh-key/
  file/note with auto-detection of files and OpenSSH keys (derived
  `public_key`/`fingerprint`).
- **WSL shim**: on WSL1/WSL2 the Linux binary locates `wcm.exe`
  (`WCM_WINDOWS_EXE` → `PATH` → `%LOCALAPPDATA%\Programs\wcm`), translates
  path arguments with `wslpath -w` and `exec`s it through interop; `ssh add`
  feeds the Linux `ssh-agent`. Reserved exit codes 126/127.
- **Stable exit codes** 0–12, 126, 127, 130 (`docs/EXIT_CODES.md`) and a JSON
  error envelope on stderr in `--json` mode.
- Password / EFF-short-wordlist passphrase generator; recovery keys
  `WCM1-XXXX-…` (144-bit, base32, checksum, typo-tolerant parsing).
- Documentation: README (EN + JA summary), `docs/FORMAT.md`,
  `docs/SECURITY.md`, `docs/WSL.md`, `docs/EXIT_CODES.md`,
  `docs/TESTER_CHECKLIST.md`.
- CI: fmt, clippy, tests and MSVC cross-check on Ubuntu/macOS, `cargo llvm-cov`
  gate (80% lines, `wcm-hello` excluded), Windows build/test with `wcm.exe`
  artifact, `cargo-deny`; release workflow producing Windows (x86_64/aarch64
  MSVC), Linux (x86_64) and macOS (aarch64) archives with `SHA256SUMS.txt`.

### Security

- Signatures from Windows Hello are verified against the stored public key
  before being used as key material; a randomized or foreign signature fails
  closed (`INTEGRITY`, exit 8) instead of deriving a wrong key.
- `WCM_PASSPHRASE` / `WCM_EXPORT_PASSPHRASE` bypass prompts and are reported
  by `wcm doctor`; intended for tests and automation only.

[Unreleased]: https://github.com/mkontani/win-creds-manager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mkontani/win-creds-manager/releases/tag/v0.1.0
