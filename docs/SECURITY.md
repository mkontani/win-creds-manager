# Security model

This page explains what `wcm` protects, what it deliberately does **not**
protect, and the reasoning behind the main design decisions. Read it before
trusting the tool with anything important. The on-disk details are in
[FORMAT.md](FORMAT.md).

## 1. Summary

* The vault is a single file (`%LOCALAPPDATA%\wcm\vault.wcm`, non-roaming)
  whose body — **including item names** — is encrypted with
  XChaCha20-Poly1305 under a random 256-bit data encryption key (DEK).
* The DEK is wrapped by one or more *key slots*:
  * **Windows Hello slot** — a `KeyCredentialManager` RSA-2048 key (TPM-backed
    when the platform has one) signs a fixed per-vault challenge with
    RSASSA-PKCS1-v1_5/SHA-256. The signature is deterministic; it is verified
    against the public key stored in the header, then fed to HKDF-SHA256 to
    derive the key-encryption key (KEK). Every unlock shows the Windows Hello
    prompt (PIN, face or fingerprint) — by design, once per `wcm` invocation.
  * **Recovery slot (mandatory)** — a 144-bit random recovery key
    (`WCM1-XXXX-…`) run through Argon2id (64 MiB, t=3) then HKDF. Shown once at
    `wcm init`. This is the only way back in after a PIN reset, TPM clear,
    re-imaged machine, or when using the vault on another OS.
  * **Passphrase slot (optional)** — same as the recovery slot with a
    user-chosen passphrase (`wcm init --passphrase`, `wcm slot add --passphrase`).
* The Hello slot's wrapped DEK is additionally wrapped with **DPAPI**
  (`CryptProtectData`, user scope, vault id as entropy, UI forbidden) unless
  `--no-dpapi`. Recovery/passphrase slots are never DPAPI-wrapped so they stay
  portable.
* The header (slots, public key, challenge, Argon2 parameters, nonces) is
  plaintext but is the AEAD *associated data* of the body: any tampering
  breaks decryption. Slots are bound to the vault id, slot id and slot kind.
* `wcm-core` (format + crypto) is `#![forbid(unsafe_code)]`; all secrets are
  held in `Zeroizing`/`SecretString` buffers and never written to logs.

## 2. Threat model

### What wcm protects against

| Threat | How |
|---|---|
| **Copy of the vault file** — backups, cloud sync, another user on the machine, a stolen disk, a different PC | The body is AEAD-encrypted under a random DEK. Without a Hello signature from *this* machine's TPM key or the recovery key/passphrase the file is opaque; item names are encrypted too. |
| **Same-user malware while you are away** (no interactive approval) | The Hello key never leaves the TPM/credential store and every signature requires a Windows Hello gesture. A process cannot silently sign the challenge, so it cannot derive the KEK. There is no daemon, session cache or environment-variable unlock in v1 that could be harvested. |
| **Header / slot tampering** — swapping the stored public key, challenge, Argon2 parameters, slot ids, cipher id | The header is the body's AAD; slots carry their own AAD (`vault_id ‖ id ‖ kind`). Any change fails closed with exit 8 (`INTEGRITY`). |
| **Silent change of the signature scheme** (e.g. a future Windows build returning RSA-PSS, which is randomized) | The signature is verified against the stored SPKI with PKCS#1 v1.5 *before* it touches the KDF. Anything else is rejected; a wrong KEK is never derived and never used to overwrite the vault. |
| **Weak or reused passphrase material** | Argon2id 64 MiB/3 passes per slot, 32-byte random salt per slot, HKDF domain separation per slot kind and vault id. The recovery key is 144 random bits. |
| **Partial writes / crashes during save** | Temp file + fsync (file *and* directory on unix) + atomic rename; the previous generation is kept as `vault.wcm.bak` (see [The `.bak` file](#the-bak-file)). |
| **Two wcm processes racing** | Advisory lock on `vault.wcm.lock` plus a generation check: the second writer gets exit 9 (`LOCKED`) instead of clobbering. |
| **Secrets in terminal scrollback / logs** | Secret values are masked in `show` (use `--reveal`), never printed by `ls`, never included in stderr diagnostics or JSON error envelopes. `--clip` clears the clipboard after a timeout. Binary values are refused on a TTY (`--out-file`). |

### What wcm does NOT protect against

| Threat | Why / mitigation |
|---|---|
| **Malware that tricks you into approving a Hello prompt** (the *confused deputy*). Any process running as your user can call `KeyCredentialManager` with your vault's credential name and trigger the *same* Windows Hello dialog. If you type your PIN into a prompt you did not initiate, that process obtains a valid signature → KEK → DEK. | Microsoft documents this limitation of `KeyCredentialManager` (the prompt shows the app's *display name*, not a verified identity). wcm prints a notice on stderr *before* each prompt (`Windows Hello: waiting for your PIN/biometric…`) so an unexpected dialog is recognisable. Only approve prompts that appear right after you ran a `wcm` command. |
| **Administrator / SYSTEM / kernel-level attackers** on the same machine | They can inject into your process, read memory after unlock, or subvert the credential store. No user-mode password manager defends against this. |
| **A running, already-unlocked `wcm` process** (memory scraping) | Keys live in memory for the duration of one command and are zeroized on drop; a debugger attached during that window wins. |
| **Software-backed Hello keys** (VMs without a vTPM, some older hardware) | The key is then protected by Windows only, not by a TPM. `wcm init` warns `not hardware (TPM) backed` and records `hw_backed=false` in the slot; check with `wcm status`. |
| **Theft of the recovery key** | Anyone with the recovery key (or passphrase) can open the vault *without* Hello, on any machine. Treat it like the master password of a password manager. |
| **Clipboard managers / history tools** | `--clip` uses `exclude_from_monitoring` hints and clears after `WCM_CLIP_TIME` seconds, but third-party clipboard history may still capture the value. |
| **Secrets you hand to other programs** (`wcm run`, `wcm ssh add`, `wcm get | …`) | Once a secret leaves wcm it is the other program's responsibility (environment variables are visible to same-user processes via `/proc`/Process Explorer; `ssh-agent` holds the key until removed). |
| **`WCM_PASSPHRASE` in the environment** | Exists for tests and automation only. It bypasses prompts and is visible to every process with access to your environment. `wcm doctor` flags it as a problem. |
| **Keyloggers, shoulder surfing, coerced unlock** | Out of scope. |

## 3. Design decisions (decision memo summary)

* **Why Windows Hello `KeyCredentialManager` and not DPAPI/Credential Manager
  alone?** DPAPI and the Windows Credential Manager decrypt silently for any
  process running as the user; `KeyCredentialManager` is the only documented
  Windows API whose private-key operations *require user presence* and can be
  TPM-backed. Bitwarden, KeePassXC and WSL-Hello-sudo use the same mechanism.
* **Why "sign a fixed challenge" instead of an encrypt/decrypt key?** Hello
  keys only sign. RSASSA-PKCS1-v1_5 is deterministic, so the signature is a
  stable secret derived from the hardware key; HKDF turns it into a KEK. The
  stored SPKI + fail-closed verification guards against the one thing that
  could go wrong (a different padding or key returning a different value).
* **Why a mandatory recovery slot?** The Hello key disappears on PIN reset,
  TPM clear, profile recreation and on any other PC. Without a second slot the
  data would be gone. The recovery key is generated (not chosen) so it is
  strong and unique; it is shown once and never stored by wcm.
* **Why DPAPI on top?** Defense in depth: even if an attacker obtains a Hello
  signature (confused deputy) *and* the file, without your DPAPI master key
  (tied to your Windows password/profile) the Hello slot's wrapped DEK is still
  opaque. It costs nothing on the normal path and cannot lock you out because
  the recovery slot is not DPAPI-wrapped.
* **Why one prompt per invocation and no agent?** Simplicity and auditability
  in v1. Batch commands (`get a b c`, `run --env …`, `ssh add`) keep the number
  of prompts low. A session cache (`wcm agent`) is on the roadmap and will
  widen the window during which memory scraping matters; it will be opt-in.
* **Why encrypt item names?** Names leak intent ("bank/…", "prod-db/…").
  Listing therefore requires an unlock; this is a conscious usability trade-off.
* **Why a thin WSL shim?** All crypto and UI happens in `wcm.exe`; the Linux
  binary only locates it and `exec`s through interop. No socket, no daemon, no
  secrets crossing the WSL boundary except on stdout, exactly as with a native
  Windows tool. See [WSL.md](WSL.md).

## 4. Operational guidance

* Store the recovery key offline or in a *different* password manager. Do not
  keep it next to the vault file.
* Prefer `--stdin`, `--file` or the interactive prompt over the hidden
  `--value` flag (command-line arguments are visible in process listings).
* Back up `vault.wcm` freely; it is useless without a key slot secret. Keep
  `vault.wcm.bak` as well if you want one generation of history — but read
  [The `.bak` file](#the-bak-file) first.
* On a shared machine, set `WCM_HELLO_FOCUS=0` only if the focus helper
  misbehaves; it exists so the Hello dialog is not hidden behind other windows
  when wcm is launched from WSL or a background terminal.
* After a PIN reset or TPM clear run `wcm recover` (recovery key → new Hello
  key). After a suspected compromise of the recovery key run `wcm rekey`
  (fresh DEK, all slots re-sealed) and `wcm slot rm`/`slot add` to replace it.
* Use `wcm doctor` to confirm `hw_backed=true`, an interactive session, and
  that `WCM_PASSPHRASE` is not set.

### The `.bak` file

Every write copies the previous generation of the vault to `vault.wcm.bak`
before the new file is put in place. That copy is a **complete vault**: it is
encrypted, but it opens with the key material that was valid *at the time it
was written* — the old recovery key, the old passphrase, the old Hello slot.

Consequences:

* After `wcm rekey`, `wcm recover` or `wcm slot rm`, a `.bak` written by an
  earlier command would still open with the key material you just revoked.
  Those three commands therefore **delete `vault.wcm.bak`** after they have
  saved successfully; the next ordinary write creates a fresh one under the
  new key material.
* Items removed with `wcm rm` are still readable in the `.bak` until the next
  write replaces it. Delete the file yourself if that matters.
* Treat `.bak` exactly like `vault.wcm` when copying, syncing or shredding.

## 5. Reporting a vulnerability

Please **do not** open a public issue for security problems.

* Use GitHub's private vulnerability reporting on
  https://github.com/mkontani/win-creds-manager/security/advisories/new, or
* e-mail the maintainer listed in `Cargo.toml` / the GitHub profile.

Include the `wcm version` output, `wcm doctor --json` (redact paths if you
like), reproduction steps and, if applicable, a vault file created with test
data. We aim to acknowledge reports within 7 days and to publish a fix and
advisory (with credit, if desired) once a patched release is available.
Cryptographic or format changes that affect compatibility will be announced in
[CHANGELOG.md](../CHANGELOG.md).
