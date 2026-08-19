# Exit codes

`wcm` uses a small, stable set of process exit codes so that scripts can branch
on *why* a command failed. The table below is generated from
`wcm_core::Error::table()` (`crates/wcm-core/src/error.rs`) and is also
printed by `wcm --exit-codes` (add `--json` for a machine-readable array).

All codes are `<= 125` except the reserved shim/interrupt codes, because the
WSL interop relay truncates exit statuses to 8 bits and 126/127 have the
conventional "cannot execute" / "not found" meaning in POSIX shells.

| Exit | Code               | Meaning                                               | Typical cause / fix |
|-----:|--------------------|-------------------------------------------------------|---------------------|
| 0    | `OK`               | success                                               | |
| 1    | `GENERAL`          | unexpected error                                      | Anything not covered below; read the message. |
| 2    | `USAGE`            | usage / invalid input                                 | clap usage errors, bad item names, malformed recovery key, wrong flags. `INVALID_INPUT` in JSON envelopes. |
| 3    | `NOT_FOUND`        | item not found                                        | `wcm get`, `set`, `rm`, `mv`, `show`, `ssh *` on an unknown item or field. Run `wcm ls`. |
| 4    | `ALREADY_EXISTS`   | item already exists                                   | `wcm add` / `mv` onto an existing name (use `-f`), or `wcm init` on an existing vault file. |
| 5    | `NOT_INITIALIZED`  | vault not initialized                                 | No vault file at the resolved path. Run `wcm init` or set `--vault`/`WCM_VAULT`. |
| 6    | `AUTH_CANCELLED`   | Windows Hello prompt cancelled                        | The user dismissed the Hello dialog (or chose "use password"). |
| 7    | `AUTH_UNAVAILABLE` | no usable key slot / Hello unavailable                | Hello key gone (PIN reset), no interactive session (SSH into Windows, session 0), TPM locked, `--no-input` but a prompt is required, or no backend for any slot. Use `wcm recover` or `--slot recovery`. |
| 8    | `INTEGRITY`        | vault integrity or decryption failure                 | Wrong passphrase / recovery key, tampered or truncated vault file, bad magic, unexpected Hello signature. Previous generation is in `vault.wcm.bak`. |
| 9    | `LOCKED`           | vault locked or concurrently modified                 | Another `wcm` process wrote the vault between your unlock and save. Retry. |
| 10   | `IO`               | file system error                                     | Permission denied, disk full, unreadable path. |
| 11   | `HELPER`           | clipboard / ssh-add helper failure                    | `ssh-add` missing or failed, clipboard unavailable (headless CI), `wcm unclip` spawn failed. |
| 12   | `FORMAT`           | import/export format error                            | Unreadable export file, unsupported export version. |
| 126  | `WSL_INTEROP_BROKEN` | WSL interop cannot launch Windows executables       | `Exec format error` from WSL; check `/proc/sys/fs/binfmt_misc/WSLInterop` or `[interop] enabled=true` in `/etc/wsl.conf`. |
| 127  | `WSL_EXE_NOT_FOUND`  | `wcm.exe` not found from WSL                        | Set `WCM_WINDOWS_EXE` or put `wcm.exe` on the Windows `PATH`. See [WSL.md](WSL.md). |
| 130  | `INTERRUPTED`      | interrupted                                           | Ctrl+C. |

## JSON error envelope

With `--json`, errors are written to **stderr** as a single JSON object and the
process still exits with the code above:

```json
{"error":{"code":"NOT_FOUND","message":"item not found: github/token","hint":"run `wcm ls` to list stored items","exit":3}}
```

`hint` is omitted when there is none. stdout stays empty on error, so
`wcm --json ... | jq` never sees a partial document.

## Mapping to `wcm_core::Error`

| Variant                | Exit |
|------------------------|-----:|
| `Error::Other`         | 1 |
| `Error::Invalid`       | 2 |
| `Error::NotFound`      | 3 |
| `Error::AlreadyExists` | 4 |
| `Error::NotInitialized`| 5 |
| `Error::AuthCancelled` | 6 |
| `Error::AuthUnavailable` | 7 |
| `Error::Integrity`     | 8 |
| `Error::Locked`        | 9 |
| `Error::Io`            | 10 |
| `Error::Helper`        | 11 |
| `Error::Format`        | 12 |

Clap usage errors (unknown flag, missing argument) also exit 2; `--help` and
`--version` exit 0.
