# wcm — Windows Hello protected credential manager

[![CI](https://github.com/mkontani/win-creds-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/mkontani/win-creds-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`wcm` is a command-line credential manager for Windows. Passwords, API
tokens, SSH private keys, arbitrary files and notes live in a **single
encrypted vault file** whose key is guarded by **Windows Hello** (PIN, face or
fingerprint) and the machine's **TPM**. It is written in Rust, works from
**WSL1/WSL2** with the exact same commands, and is scriptable (`--json`,
stable exit codes).

```text
$ wcm get github/token
Windows Hello: waiting for your PIN/biometric…      # ← dialog appears, once
ghp_16C7e42F292c6912E7710c838347Ae178B4a     # printed in clear (pipe it, or use --clip)
```

> **Status:** v0.1.0 — usable, format frozen (v1), Windows paths awaiting wider
> manual testing (see [docs/TESTER_CHECKLIST.md](docs/TESTER_CHECKLIST.md)).

## Security model in one paragraph

Every vault has a random 256-bit data key (DEK) that encrypts the whole body —
item names included — with XChaCha20-Poly1305. The DEK is wrapped by **key
slots**. The *Hello* slot asks a `KeyCredentialManager` RSA key (TPM-backed
where available; user presence required for every operation) to sign a fixed
per-vault challenge with RSASSA-PKCS1-v1_5/SHA-256; the deterministic signature
is **verified against the public key stored in the header** (fail closed),
then stretched with HKDF-SHA256 into a KEK that unwraps the DEK. A
**mandatory recovery slot** (144-bit recovery key → Argon2id → HKDF) and an
optional passphrase slot wrap the same DEK so a PIN reset, TPM clear or a
different machine never locks you out. The Hello slot is additionally wrapped
with **DPAPI** as defense in depth. The plaintext header is the body's AEAD
associated data, so tampering is detected. Full details:
[docs/SECURITY.md](docs/SECURITY.md), [docs/FORMAT.md](docs/FORMAT.md).

## Features

* Windows Hello (PIN / face / fingerprint) gate on every unlock — one prompt
  per `wcm` invocation; batch commands keep prompts to a minimum.
* TPM-backed keys when available (`hw_backed` recorded, warning otherwise).
* Single-file vault, atomic writes, `.bak` of the previous generation,
  concurrent-write detection, header-authenticated format with golden vectors.
* Item kinds: `password`, `login`, `token`, `ssh-key`, `file`, `note`; arbitrary
  extra fields (`--field username=alice`), tags, notes.
* `wcm ssh add` loads keys straight into `ssh-agent` (Windows or WSL side);
  `wcm run --env` injects secrets into a child process; `--clip` with
  auto-clear; password/passphrase generator (EFF wordlist).
* Encrypted export (same format, passphrase-only), plaintext export, import
  with merge/overwrite/replace.
* WSL1/WSL2: the Linux `wcm` is a thin shim that executes `wcm.exe` through
  interop — no daemon, no sockets, no secrets crossing the boundary.
* `--json` everywhere, stable exit codes, shell completions, `wcm doctor`.
* Portable core (`wcm-core`, `#![forbid(unsafe_code)]`) ready to be reused by
  a GUI.

## Install

### Prebuilt binaries

Download `wcm-<version>-x86_64-pc-windows-msvc.zip` (or `aarch64`) from the
[GitHub Releases](https://github.com/mkontani/win-creds-manager/releases)
page, verify it against `SHA256SUMS.txt`, unzip and put `wcm.exe` on your
`PATH` (e.g. `%LOCALAPPDATA%\Programs\wcm\`). Linux (`x86_64-unknown-linux-musl`,
statically linked — runs on any distro and on WSL1/WSL2 regardless of glibc)
and macOS (`aarch64-apple-darwin`) tarballs are provided for the WSL shim and
for opening recovery/passphrase-only vaults off-Windows.

### From source (on Windows)

```powershell
cargo install --path crates/wcm-cli
```

### Cross-build from macOS / Linux for Windows

```bash
rustup target add x86_64-pc-windows-gnu
brew install mingw-w64                      # macOS; on Debian/Ubuntu: apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/wcm.exe
```

`.cargo/config.toml` already points the `x86_64-pc-windows-gnu` target at
`x86_64-w64-mingw32-gcc`. The MSVC target can be *checked* from any host
(`cargo check --target x86_64-pc-windows-msvc`); linking it requires Windows.

Requirements: Rust 1.89 (see `rust-toolchain.toml`) to build; Windows 10 or
Windows 11 with Windows Hello set up (Settings → Accounts → Sign-in options).

## Quick start

```powershell
wcm init                                   # creates the vault, 2 Hello prompts, prints the RECOVERY KEY — store it!
wcm add github/token --kind token --stdin  # paste the token, Ctrl+Z/Enter (or Ctrl+D)
wcm add web/mail --kind login --generate --field username=me@example.com
wcm get github/token                       # prints the token (1 Hello prompt)
wcm get web/mail --clip                    # copy password, auto-clear after 45 s
wcm ls -l
wcm add ssh/work --file ~/.ssh/id_ed25519  # kind auto-detected: ssh-key
wcm ssh add ssh/work                       # → ssh-add -  (Windows ssh-agent, or the WSL one)
wcm run --env GITHUB_TOKEN=github/token -- gh auth status
wcm show web/mail --reveal
```

Exactly one Windows Hello prompt is shown per command, including multi-item
commands such as `wcm get a b c`.

## Commands

| Command | Purpose | Hello prompts |
|---|---|---:|
| `wcm init [--passphrase] [--no-hello] [--no-dpapi]` | Create a vault: Hello slot + mandatory recovery key (+ optional passphrase slot) | 2 |
| `wcm add <name> [--kind K] [--stdin\|--file P\|--generate [LEN] [--words N] [--no-symbols]] [--field k=v]… [--notes S] [--tag T]… [-f] [--clip]` | Add an item (kind auto-detected from `--file` / OpenSSH key) | 1 |
| `wcm set <name> <field> [--stdin\|--file P\|--generate\|--delete] [--public]` | Set, replace or delete one field | 1 |
| `wcm get <name>… [--field F] [--raw] [-n] [--clip [--clip-timeout S]] [--out-file P]` | Print a secret field of one or more items (`--raw`, `-n`, `--clip` and `--out-file` take exactly one name) | 1 |
| `wcm show <name> [--reveal]` | Show metadata and fields (secrets masked unless `--reveal`) | 1 |
| `wcm ls [PREFIX] [--kind K] [--tag T] [-l]` (alias `list`) | List items | 1 |
| `wcm rm <name>… [-f]` (alias `remove`) | Remove items | 1 |
| `wcm mv <old> <new> [-f]` (alias `rename`) | Rename an item | 1 |
| `wcm generate [LEN] [--no-symbols] [--words N] [--sep S] [--clip]` (alias `gen`) | Generate a password/passphrase without storing it | 0 |
| `wcm ssh add <name> [-t LIFETIME] [--ssh-add PATH]` | Load the private key into `ssh-agent` (`ssh-add -`) | 1 |
| `wcm ssh pubkey <name>` | Print the `authorized_keys` line | 1 |
| `wcm ssh remove <name>` | Remove the key from `ssh-agent` | 1 |
| `wcm run --env VAR=name[/field]… [--env-file F] -- cmd args…` | Run a command with secrets in its environment | 1 |
| `wcm export [-o FILE] [--plaintext --i-know]` | Encrypted (passphrase-only `.wcm`) or plaintext JSON export | 1 (+ export passphrase) |
| `wcm import <file> [--overwrite\|--replace -f]` | Import items from an export (`.wcm` or `.json`); `--replace` wipes the vault first and needs `-f`/a confirmation | 1 (+ export passphrase for `.wcm`) |
| `wcm recover [--no-hello] [--no-dpapi]` | Re-create the Hello slot using the recovery key / passphrase | recovery key + 2 |
| `wcm rekey` | Rotate the DEK and re-seal every slot | 1 + recovery key |
| `wcm slot ls` | List key slots (no unlock) | 0 |
| `wcm slot add --passphrase\|--hello [--label L] [--no-dpapi]` | Add a key slot | 1 |
| `wcm slot rm <label> [-f]` | Remove a key slot (the last slot — and the last passphrase/recovery slot — cannot be removed) | 1 |
| `wcm status` | Vault path, id, generation, slots — no unlock | 0 |
| `wcm doctor [--hello-selftest]` | Environment diagnostics (Hello, TPM, session, DPAPI, WSL, ssh-add) | 0 (2 with selftest) |
| `wcm completions <shell>` | Shell completions (bash, zsh, fish, powershell, elvish) | 0 |
| `wcm version`, `wcm --exit-codes` | Version / exit-code table | 0 |

Global flags: `--vault PATH` (env `WCM_VAULT`), `--json`, `--slot LABEL`
(try this slot first, e.g. `--slot recovery`), `--no-input`, `-q/--quiet`.

## Using wcm from WSL

Install the Linux build inside your distro and `wcm.exe` on Windows. The
Linux binary detects WSL (1 or 2), finds `wcm.exe` (`WCM_WINDOWS_EXE` → `PATH`
→ `/mnt/c/Users/*/AppData/Local/Programs/wcm/wcm.exe`), translates path
arguments with `wslpath -w`, and `exec`s it through interop; the Hello dialog
appears on the Windows desktop and the exit code is relayed. `wcm ssh add`
pipes the key into the **Linux** `ssh-agent`. Details, troubleshooting and
exit codes 126/127: [docs/WSL.md](docs/WSL.md).

## Exit codes

`0` ok · `2` usage/invalid · `3` not found · `4` already exists · `5` not
initialized · `6` Hello cancelled · `7` auth unavailable · `8` integrity /
wrong key · `9` locked or concurrently modified · `10` I/O · `11` helper
(clipboard/ssh-add) · `12` import/export format · `126`/`127` WSL shim ·
`130` interrupted. Full table with hints: [docs/EXIT_CODES.md](docs/EXIT_CODES.md)
or `wcm --exit-codes`.

## JSON mode

Add `--json` to any command: stdout carries exactly one JSON document, stderr
carries notices and warnings (on failure its **last** line is a single
`{"error":{code,message,hint,exit}}` envelope). Secrets are only included where
the command's purpose is to output them (`get`, `show --reveal`,
`export --plaintext`).

```bash
wcm --json status | jq '.slots[] | {label, kind}'
wcm --json ls    | jq .
wcm --json init --no-hello --passphrase | jq -r .recovery_key   # scripted setup (WCM_PASSPHRASE set)
```

## Environment variables

| Variable | Effect |
|---|---|
| `WCM_VAULT` | Vault file path (same as `--vault`). |
| `WCM_DATA_DIR` | Directory used for the default vault path (`$WCM_DATA_DIR/vault.wcm`) instead of `%LOCALAPPDATA%\wcm` / `$XDG_DATA_HOME/wcm`. Mainly for tests. |
| `WCM_PASSPHRASE` | Passphrase or recovery key used **without prompting**. ⚠️ For tests and automation only: it bypasses the interactive prompt and is visible to every process that can read your environment. Every run warns on stderr (silence it with `-q`), `wcm doctor` reports it as a problem, and child processes started by `wcm run`/`ssh add` never inherit it. |
| `WCM_EXPORT_PASSPHRASE` | Passphrase for `wcm export` / `wcm import` of encrypted exports (non-interactive). Same warning as above. |
| `WCM_NEW_PASSPHRASE` | New passphrase used by `recover`, `rekey` and `slot add` without prompting (falls back to `WCM_PASSPHRASE`). Same warning as above. |
| `WCM_CLIP_TIME` | Clipboard clear timeout in seconds for every `--clip` (default 45). |
| `WCM_CLIP_DISABLE` | When set, `--clip` is refused instead of touching the clipboard (helper error, exit 11) — for environments where the clipboard must never be used. |
| `WCM_SSH_ADD` | Path of the `ssh-add` executable (default: from `PATH`, then `C:\Windows\System32\OpenSSH\ssh-add.exe`). |
| `WCM_WINDOWS_EXE` | WSL only: explicit path of `wcm.exe` (Linux or Windows path). |
| `WCM_NO_WSL_PROXY` | WSL only: when set, do not proxy to `wcm.exe`; run the Linux binary natively (passphrase/recovery slots only). |
| `WCM_HELLO_FOCUS` | Set to `0` to disable the helper that brings the Windows Hello dialog to the foreground. |

## Roadmap

* `wcm agent` — optional, opt-in session cache over a named pipe so that a
  burst of commands needs a single Hello prompt.
* Built-in ssh-agent that signs with keys from the vault without exporting them.
* GUI (Tauri v2) reusing `wcm-core` + `wcm-hello` directly.
* Authenticode-signed release binaries; winget / scoop packages.
* Per-item access log and DPAPI-protected name index for a prompt-free `ls`.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo llvm-cov --workspace --exclude wcm-hello --fail-under-lines 80
cargo check --workspace --target x86_64-pc-windows-msvc
```

Crates: `wcm-core` (format, crypto, slots, items — portable, no unsafe),
`wcm-hello` (Windows Hello / DPAPI / focus / session; stubbed off-Windows),
`wcm-cli` (the `wcm` binary). Design notes are kept locally
(not in this repository). Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).

The passphrase generator embeds the
[EFF short wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)
(`crates/wcm-core/src/eff_short_wordlist.txt`), © Electronic Frontier
Foundation, licensed under
[CC-BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).

---

## 日本語概要

**wcm** は Windows Hello（PIN / 顔 / 指紋）と TPM で保護された、単一ファイルのクレデンシャル
マネージャ CLI です。パスワード・API トークン・SSH 秘密鍵・任意のファイル・メモを
`%LOCALAPPDATA%\wcm\vault.wcm` に暗号化して保存し、`wcm get` のたびに Windows Hello の
プロンプトが 1 回だけ表示されます。WSL1 / WSL2 からも同じコマンドで使えます（Linux 側の
`wcm` は `wcm.exe` を interop 経由で実行する薄いシムです）。

* **鍵の階層**: Hello の RSA 鍵（TPM バック）で固定チャレンジに決定的署名（RSASSA-PKCS1-v1_5/SHA-256）
  → 保存済み公開鍵で検証（不一致なら即失敗）→ HKDF-SHA256 → KEK → XChaCha20-Poly1305 で
  ラップされた DEK → DEK で本体（アイテム名も含む）を XChaCha20-Poly1305 暗号化。
* **リカバリキー必須**: `wcm init` で一度だけ表示される `WCM1-XXXX-…`（144 bit）を
  Argon2id で伸長した第 2 スロット。PIN リセット・TPM クリア・別 PC でも開けます。
  失くすと Hello 鍵が消えた時点でデータも失われます。必ず保管してください。
* **DPAPI**: Hello スロットのみ追加で DPAPI 包装（深層防御）。リカバリスロットは可搬性維持のため非適用。
* **守らないもの**: Hello プロンプトを承認させるよう仕向けるマルウェア（confused deputy）、
  管理者/SYSTEM 権限の攻撃者、TPM のない VM のソフト鍵（警告あり）。詳細は
  [docs/SECURITY.md](docs/SECURITY.md)。

```powershell
wcm init                                    # リカバリキーを必ず保存
wcm add github/token --kind token --stdin
wcm get github/token
wcm ls -l
wcm add ssh/work --file ~/.ssh/id_ed25519
wcm ssh add ssh/work                        # ssh-agent に登録
wcm run --env GITHUB_TOKEN=github/token -- gh auth status
```

インストール: GitHub Releases の zip を展開して `wcm.exe` を PATH に置くか、Windows 上で
`cargo install --path crates/wcm-cli`。macOS からは `rustup target add x86_64-pc-windows-gnu`
+ `brew install mingw-w64` + `cargo build --release --target x86_64-pc-windows-gnu` でクロスビルドできます。

ドキュメント: [docs/FORMAT.md](docs/FORMAT.md)（ファイル形式）、
[docs/SECURITY.md](docs/SECURITY.md)（脅威モデル）、[docs/WSL.md](docs/WSL.md)（WSL）、
[docs/EXIT_CODES.md](docs/EXIT_CODES.md)（終了コード）、
[docs/TESTER_CHECKLIST.md](docs/TESTER_CHECKLIST.md)（Windows 手動テスト手順）。
ライセンスは MIT、同梱の EFF short wordlist は CC-BY 3.0 US です。
