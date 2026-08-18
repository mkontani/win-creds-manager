# wcm (win-creds-manager) 設計書 v1

- 日付: 2026-08-19
- 状態: 採用（自律実装中）。ユーザー不在の自律モードで作成したため、下記「前提と判断」はユーザーが後から上書き可能。
- 元ネタ: 5 並列の技術調査 + 決定メモ（`/private/tmp/.../scratchpad/memo.md`）。本書はその要約 + 実装上の確定事項。

## 0. ゴール

Windows Hello（PIN / 生体）で保護されたクレデンシャル（パスワード、SSH 秘密鍵、トークン、任意ファイル、メモ）を
TPM バックの鍵で守り、CLI から保存・取得できるツール `wcm`。WSL1/WSL2 からも同じコマンドで使える。
将来 GUI（Tauri v2 / egui など）を同じコアで作れる構造にする。

## 1. 前提と判断（ユーザー確認なしで決めた点）

| 項目 | 判断 | 理由 |
|---|---|---|
| 言語 | **Rust**（edition 2021, MSRV 1.85+, 開発 1.89） | WinRT `KeyCredentialManager` の型付き射影は `windows` クレートのみが実用水準。Go には保守された射影がない。macOS から `cargo check --target x86_64-pc-windows-msvc` / `cargo build --target x86_64-pc-windows-gnu`（mingw-w64）が通ることをスパイクで確認済み。 |
| Hello API | `Windows.Security.Credentials.KeyCredentialManager`（`windows = "=0.62.2"`, `IAsyncOperation::join()`） | Microsoft が文書化している唯一の「ユーザー在席を強制する」鍵操作。Bitwarden / KeePassXC / WSL-Hello-sudo が同方式。 |
| 鍵階層 | Hello RSA-2048 鍵で **固定チャレンジに署名**（RSASSA-PKCS1-v1_5/SHA-256, 決定的）→ 保存済み SPKI で **検証**（fail-closed）→ HKDF-SHA256 → KEK(32B) → ランダム DEK(32B) を XChaCha20-Poly1305 でラップ → DEK で本体を XChaCha20-Poly1305 暗号化 | 署名がランダム化（PSS）されるビルドが将来出ても検証で即座に検出し、誤った KEK を導出しない。 |
| リカバリ | **必須**の第 2 スロット: Argon2id(リカバリキー or パスフレーズ) → HKDF → KEK → 同じ DEK をラップ | Hello 鍵は PIN リセット / TPM クリア / 別 PC で消える。データ喪失を防ぐ。 |
| DPAPI | Hello スロットの暗号文を追加で `CryptProtectData`（entropy=vault_id, UI_FORBIDDEN）で包む。リカバリスロットには適用しない（可搬性維持）。`--no-dpapi` で無効化可 | 深層防御。壊れてもリカバリスロットで復旧可能。 |
| Hello UX | **1 回の `wcm` 実行につき 1 回のプロンプト**。デーモン / 環境変数セッションは v1 では作らない | 単純・安全。`get a b c` / `run --env` / `ssh add` などバッチ系で回数を抑える。エージェントは v1.1。 |
| WSL | Linux 版 `wcm` は **薄いシム**: WSL を検出し、`wcm.exe` を見つけて interop 経由で `exec`（WSL1/2 同一経路） | ソケット/デーモン不要。暗号処理と Hello UI はすべて `wcm.exe` 側。 |
| ボルト | 単一ファイル `%LOCALAPPDATA%\wcm\vault.wcm`（8B magic/len + 平文 CBOR ヘッダ(=AAD) + 1 個の AEAD 本体）。**アイテム名も暗号化**（`ls` もプロンプトあり） | 名前の漏洩を防ぐ（pass 方式の批判点）。`vault_id`/`generation` のみ平文。非ローミングの LOCALAPPDATA（マシン束縛）。 |
| Export | 独自 age 依存を避け、**パスフレーズスロットのみの `.wcm` ファイル**として書き出す（同じフォーマット・同じコード）。`--plaintext --i-know` で JSON 平文も可 | 依存削減、コード再利用。他マシンでは `wcm --slot recovery` で開ける。 |
| 暗号クレート | RustCrypto digest-0.10 系で統一: sha2 0.10 / hkdf 0.12 / chacha20poly1305 0.10 / argon2 0.5 / rsa 0.9 / rand 0.8 | trait 世代の混在を避ける。 |
| 名前 | crate: `wcm-core`, `wcm-hello`, `wcm-cli`; バイナリ `wcm` | |

## 2. アーキテクチャ

```
win-creds-manager/
├─ Cargo.toml                 # workspace (resolver=2), workspace.dependencies, lints
├─ rust-toolchain.toml        # 1.89 + windows targets
├─ .cargo/config.toml         # x86_64-pc-windows-gnu linker = x86_64-w64-mingw32-gcc
├─ crates/
│  ├─ wcm-core/               # 可搬。#![forbid(unsafe_code)]。ボルト形式・暗号・スロット・アイテム・エラー/終了コード。stdin/stdout に触れない
│  ├─ wcm-hello/              # cfg(windows) のみ実体。KcmApi trait + HelloBackend + DPAPI + focus + session check。非 Windows では空
│  └─ wcm-cli/                # bin "wcm": clap derive、commands/*、human/json 出力、wsl.rs(linux)、ssh.rs、clip.rs
├─ docs/{FORMAT.md, SECURITY.md, WSL.md, EXIT_CODES.md, TESTER_CHECKLIST.md}
└─ .github/workflows/ci.yml   # ubuntu/macos: test+clippy+check msvc / windows-latest: test+build
```

依存方向: `wcm-cli` → `wcm-core`, `wcm-hello`(windows のみ)。`wcm-hello` → `wcm-core`（trait 実装）。
GUI は将来 `wcm-core`（+ `wcm-hello`）を直接リンクする。

### 2.1 wcm-core の主要ユニット

| モジュール | 役割 | 依存 |
|---|---|---|
| `crypto/aead.rs` | XChaCha20-Poly1305 seal/open（nonce 生成含む） | chacha20poly1305, rand |
| `crypto/kdf.rs` | `derive_kek(ikm, salt, label, vault_id)`, `argon2id(secret, salt, params)`, `verify_hello_signature(spki, challenge, sig)` | hkdf, sha2, argon2, rsa |
| `slot/mod.rs` | `KeySlot`, `SlotKind`, `SlotParams`, `KeySlotBackend` trait, `Envelope` trait(DPAPI 抽象), `seal_slot`/`open_slot` | |
| `slot/passphrase.rs` | `PassphraseBackend`（全 OS） | |
| `slot/mock.rs` | `MockBackend`（feature `test-util`） | |
| `vault/header.rs` | ヘッダ構造体 + CBOR (de)serialize + magic/len | ciborium, serde |
| `vault/body.rs` | `VaultBody { items, settings }`、アイテム CRUD（不変更新: 新しい Body を返す） | |
| `vault/file.rs` | 読み書き（tempfile + fsync + persist、`.bak`、fd-lock、generation チェック） | tempfile, fd-lock |
| `vault/mod.rs` | `Vault`: open(path, unlocker) → `UnlockedVault { header, body, dek }`; save | |
| `item.rs` | `Item`, `ItemKind`, `Field{value: Text|Bytes, secret}`, 名前検証、primary field 規約 | serde_bytes |
| `recovery_key.rs` | 20B → base32 `WCM1-XXXX-...`、パース/正規化 | data-encoding |
| `generate.rs` | パスワード生成（長さ/記号/単語） | rand |
| `error.rs` / `exit_code.rs` | `Error` enum と安定した終了コード（≤125） | thiserror |

### 2.2 KeySlotBackend trait

```rust
pub trait KeySlotBackend {
    fn kind(&self) -> SlotKind;
    fn availability(&self) -> Availability;   // Available | NotEnrolled | Unsupported(String) | NoInteractiveSession
    fn enroll(&self, ctx: &UnlockContext) -> Result<(SlotParams, Zeroizing<Vec<u8>>)>; // 外部状態を作り ikm を返す
    fn open(&self, ctx: &UnlockContext, params: &SlotParams) -> Result<Zeroizing<Vec<u8>>>;
    fn destroy(&self, params: &SlotParams) -> Result<()>;
}
```
バックエンドは **ikm を返すだけ**。HKDF・AEAD ラップは core が行うため、ラップ経路は macOS 上で 100% テストできる。
`Envelope` trait（`protect/unprotect`）で DPAPI を抽象化。非 Windows は identity。

### 2.3 wcm-hello

- `KcmApi` trait: `is_supported`, `open`, `create`, `sign`, `public_key`, `attest`, `delete` の 7 操作。実装 `WinRtKcm`（本物）と `FakeKcm`（テスト、macOS で実行可）。
- `HelloBackend`: open→(NotFound なら)create→open の状態機械、`sign` → core の `verify_hello_signature`、attestation で `hw_backed`。
- `focus.rs`: プロンプト中 `FindWindowA("Credential Dialog Xaml Host")` を 500ms 毎に `SetForegroundWindow`（`WCM_HELLO_FOCUS=0` で無効）。
- `session.rs`: `ProcessIdToSessionId == 0` なら `NoInteractiveSession`。
- `dpapi.rs`: `CryptProtectData/CryptUnprotectData`。
- エラー対応: UserCanceled → exit 6、NotFound/Unsupported/SecurityDeviceLocked/session0 → exit 7、TPM 一時エラー(0x8028008B 等) は 500ms 後 1 回リトライ。

### 2.4 wcm-cli

- clap derive。グローバル: `--vault PATH`(env `WCM_VAULT`), `--json`, `--slot LABEL`, `--no-input`, `-q`, `--no-color`。
- 秘密入力: `WCM_PASSPHRASE` env（テスト/自動化用、警告付き）→ `--stdin` → TTY で rpassword。
- 出力: 人間向け（stderr にヒント）/ `--json`（stdout に 1 JSON、エラーは stderr に `{"error":{code,message,hint,exit}}`）。バイナリを TTY に出さない。
- `wsl.rs`(linux): 検出（`WSL_INTEROP` → WSL2、`/proc/version` に "microsoft" → WSL1/2）、`wcm.exe` 探索（`WCM_WINDOWS_EXE` → PATH → `/mnt/*/Users/*/AppData/Local/Programs/wcm/wcm.exe`）、パス引数の `wslpath -w` 変換、`exec`。`ssh add/remove` は spawn して Linux 側の `ssh-add -` へ流す。exit 126/127 予約。
- `ssh.rs`: `ssh-add -` を子プロセスで起動し生バイトを stdin へ。
- `clip.rs`: arboard（`exclude_from_monitoring`）+ 分離プロセス `wcm unclip --timeout N --hash H`。

## 3. ボルト形式 v1（詳細は docs/FORMAT.md）

```
0      magic  b"WCM\x01"
4      header_len u32 LE
8      header CBOR map { v:1, vault_id:bstr16, created:tstr, generation:uint, slots:[KeySlot..], body_cipher:"xchacha20poly1305", body_nonce:bstr24 }
8+len  body_ct = XChaCha20-Poly1305(DEK, body_nonce, aad=file[0..8+len]) over CBOR { items:[Item..], settings:{...} }
```
KeySlot: `{ id:u8, kind:1|2, label, salt:bstr32, nonce:bstr24, ct:bstr, params: Hello{cred_name, challenge:bstr32, spki_der:bstr, dpapi:bool, hw_backed:bool} | Passphrase{argon2:{m_kib,t,p}} }`
スロット AAD = `"wcm/v1/slot" || vault_id || id || kind`。
KEK info = `"wcm/v1/kek/hello"` または `"wcm/v1/kek/passphrase"` `|| vault_id`。
Argon2id 既定: m=65536 KiB, t=3, p=1（スロットに保存、テストでは小さく）。
書き込み: 同ディレクトリ tempfile → sync → 旧を `.bak` に → persist。`vault.lock` で排他。generation 不一致は exit 9。

## 4. コマンド v1

| コマンド | 主なフラグ | Hello 回数 |
|---|---|---|
| `init` | `--passphrase`(リカバリキー生成の代わりに/加えてパスフレーズスロット), `--no-hello`, `--no-dpapi` | 2 + リカバリキー表示 |
| `add <name>` | `--kind`, `--field k=v`…, `--stdin`, `--file P`, `--generate [LEN]`, `--no-symbols`, `--words N`, `--notes`, `--tag`, `-f`, `--clip` | 1 |
| `set <name> <field>` | `--stdin`, `--value`, `--generate`, `--file` | 1 |
| `get <name>…` | `--field`, `--raw`, `-n`, `--clip [--clip-timeout]`, `--out-file`, `--json` | 1 |
| `show <name>` | `--json`, `--reveal` | 1 |
| `ls [PREFIX]` | `--kind`, `--tag`, `-l`, `--json` | 1 |
| `rm <name>…`, `mv <old> <new>` | `-f` | 1 |
| `generate [LEN]` | `--no-symbols`, `--words N`, `--sep`, `--clip` | 0 |
| `ssh add|remove|pubkey <name>` | `-t`, `--agent-socket` | 1 |
| `run --env VAR=name[/field]… -- cmd` | `--env-file`, `--no-masking` | 1 |
| `export [-o FILE]` / `import FILE` | `--merge|--replace`, `--plaintext --i-know` | 1 (+パスフレーズ) |
| `recover` | | リカバリキー + 2 |
| `rekey` | | 1 + リカバリキー |
| `slot ls|add|rm` | `--passphrase` | 1 |
| `status`, `doctor` | `--json`, `--hello-selftest` | 0 |
| `unclip`(内部), `completions`, `version`, `--exit-codes` | | 0 |

終了コード: 0 ok / 1 general / 2 usage / 3 not found / 4 exists / 5 not initialized / 6 auth cancelled / 7 auth unavailable / 8 integrity / 9 locked-or-modified / 10 io / 11 helper(clip/ssh-add) / 12 import-export format / 126,127 (WSL シム) / 130 interrupted。

## 5. 脅威モデル（要約、詳細は docs/SECURITY.md）

守る: ボルトファイルの複製（バックアップ/同期/他ユーザー/別マシン）、ユーザー不在時の同一ユーザーマルウェア（Hello プロンプトなしには復号不能）、ヘッダ改竄/スロット差し替え、署名方式の無断変更。
守らない: ユーザーを騙して Hello を承認させるマルウェア（Microsoft も confused deputy と明記）、管理者/SYSTEM によるプロセス注入、TPM のない VM のソフト鍵（`hw_backed=false` 警告）、クリップボードマネージャ。

## 6. テスト戦略

- `wcm-core`: 単体（暗号 round-trip、HKDF ベクタ固定、RSA PKCS1v15 検証成功/PSS 失敗、スロット seal/open、ヘッダ AAD 改竄検出、アイテム CRUD 不変性、リカバリキー往復、名前検証）+ ゴールデンベクタ `tests/vectors/v1/*.wcm`。
- `wcm-hello`: `FakeKcm` で状態機械/エラーマップを macOS でテスト。実 WinRT は `#[ignore]`。
- `wcm-cli`: `assert_cmd` で全コマンドをパスフレーズバックエンド（`WCM_PASSPHRASE`）で通しテスト。WSL シム: 偽 `/proc/version`・偽 `wcm.exe`（ネイティブビルドの wcm を指す）で往復。
- カバレッジ: `cargo llvm-cov --workspace --exclude wcm-hello` で 80% 以上。
- CI: ubuntu/macos で test+clippy+`cargo check --target x86_64-pc-windows-msvc`、windows-latest で test+build。

## 7. ロードマップ（v1 範囲外）

`wcm agent`（named pipe セッションキャッシュ）、組み込み ssh-agent、DPAPI 保護の名前インデックスキャッシュ、GUI（Tauri v2）、Authenticode 署名、winget/scoop 配布。
