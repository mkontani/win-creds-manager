# Using wcm from WSL

`wcm` stores the vault, does all the cryptography and shows the Windows Hello
prompt on the **Windows side only** (`wcm-hello` is `cfg(windows)`). The
Linux build of `wcm` is a thin shim (`crates/wcm-cli/src/wsl.rs`,
`crates/wcm-cli/src/wsl_core.rs`) that detects WSL, finds `wcm.exe`,
translates a handful of path arguments and hands the whole invocation to it.
No daemon, no socket, no secret ever exists on the Linux side except a
private key momentarily piped into `ssh-add` (see below).

## How interop works

Windows registers a `binfmt_misc` handler (`WSLInterop`, or
`WSLInterop-late` on distros where it registers after `WSLInterop` is
already taken) that recognizes PE (`MZ`-prefixed) binaries and routes their
execution through `/init` to the Windows side, where the real Win32 process
is launched **in your interactive Windows session** — the desktop that owns
the console `wsl.exe`/Windows Terminal is attached to. That's why the Hello
dialog pops up on your Windows desktop, not inside the WSL terminal.
**WSL1 and WSL2 use the exact same path** — the only difference is how
`wcm` detects which one it's running under; `wcm doctor` reports `WSL1` or
`WSL2` purely for diagnostics.

For a plain command, the Linux shim `exec()`s `wcm.exe`, replacing its own
process image, so the exit code you see is exactly what `wcm.exe` returned
(capped at 125 in normal use, since it's relayed through an 8-bit process
exit status — see [Exit codes](#exit-codes)). `wcm ssh add`/`ssh remove` are
the one exception: they *spawn* `wcm.exe` instead of exec'ing it, to capture
its stdout (see below).

## Installing `wcm.exe` (needed either way)

`wcm.exe` must live on the **Windows filesystem** (not a WSL-only path) —
either:

* the zip from GitHub Releases, unpacked to
  `%LOCALAPPDATA%\Programs\wcm\wcm.exe`, or
* `cargo install --path crates/wcm-cli` run **on Windows**, which puts it in
  `~\.cargo\bin\wcm.exe` (i.e. `%USERPROFILE%\.cargo\bin\wcm.exe`).

These two exact locations are what the shim's `/mnt/*/Users/*/…` fallback
search checks (see [Locating `wcm.exe`](#locating-wcmexe)), so installing to
either one means no extra configuration on the WSL side. Putting the
directory on your **Windows** `PATH` also works, because WSL imports the
Windows `PATH` into its own `$PATH` by default (`interop.appendWindowsPath`
in `/etc/wsl.conf`, on by default).

## Two ways to invoke it from WSL

### Option A — install the Linux build of `wcm` (recommended)

Build or install the `x86_64-unknown-linux-gnu` `wcm` binary inside your
distro (`cargo build -p wcm-cli`, or the release tarball) and put it on
`$PATH`, e.g. `/usr/local/bin/wcm`. This is the shim described in the rest
of this document: it detects WSL automatically, locates `wcm.exe`,
translates `--vault`/`--file`/etc. with `wslpath`, injects `$WCM_VAULT`, and
routes `ssh add`/`ssh remove` into the **WSL** ssh-agent.

### Option B — symlink straight to `wcm.exe`

```bash
ln -s /mnt/c/Users/<you>/AppData/Local/Programs/wcm/wcm.exe /usr/local/bin/wcm
```

Works too — `binfmt_misc` interop launches any PE binary you exec by path,
shim or not — but **none of the shim logic runs**: pass Windows-style paths
yourself (e.g. `--vault C:\Users\you\...\vault.wcm`), no `$WCM_VAULT`
injection, and `wcm ssh add` runs as `wcm.exe`'s own subcommand, landing the
key in the **Windows** `ssh-agent` service, not WSL's. Prefer Option A
unless you specifically want that.

## What the shim does to each invocation

### Detection (`wsl_core::detect`)

In order:

1. `WCM_FORCE_WSL` truthy (`1`/`true`/`yes`/`on`, case-insensitive) → `WSL2`
   (test hook, not needed in normal use).
2. `$WSL_INTEROP` present in the environment → `WSL2` (WSL2 sets this).
3. Otherwise `/proc/version`, lowercased: no `"microsoft"` → not WSL at all
   (the shim runs the Linux binary natively); contains `"wsl2"` or
   `"microsoft-standard"` → `WSL2`; any other `"microsoft"` string → `WSL1`.

### Locating `wcm.exe`

1. `$WCM_WINDOWS_EXE`, if it points at a file that exists.
2. `wcm.exe` in every directory on `$PATH`.
3. `/mnt/<drive>/Users/<user>/AppData/Local/Programs/wcm/wcm.exe`, then
   `/mnt/<drive>/Users/<user>/.cargo/bin/wcm.exe`, for every drive under
   `/mnt` and every user directory under it, both sorted alphabetically for
   determinism.

If nothing is found, `wcm` exits **127** (`WSL_EXE_NOT_FOUND`) and the hint
lists exactly what it checked.

### Path translation

Before exec'ing `wcm.exe`, the shim rewrites the *values* of these options
(both `--opt value` and `--opt=value` forms) with `wslpath -w`:

| Option(s) | Translated |
|---|---|
| `--vault`, `--file`, `--out-file`, `--env-file`, `-o` / `--out` | value |
| `import <FILE>` (first positional after the subcommand) | value |
| `--slot` | **not** translated — it's a label, not a path |
| everything after a literal `--` | **not** translated (passed through verbatim, e.g. `wcm run -- cmd --vault /etc/passwd`) |

A value is left untouched if it is `-` (stdin/stdout marker), empty, already
looks like a Windows path (`C:\...`, `c:/...`, `\\server\share`,
`\\wsl$\...`), or if `wslpath -w` fails/returns nothing (translation
"impossible" — original spelling kept so the error message still makes
sense). For a path that doesn't exist yet (an output file), the parent
directory is translated and the file name appended, so `wcm get x
--out-file /tmp/new.txt` still works.

### `--vault` / `WCM_VAULT`

If no `--vault` was given (before any `--`) and `$WCM_VAULT` is set, the
shim prepends `--vault <translated $WCM_VAULT>` to the argument list —
Windows processes don't inherit your WSL environment, so this is the only
way `$WCM_VAULT` reaches `wcm.exe`. An explicit `--vault`/`--vault=` always
wins and is translated in place instead.

### `ssh add` / `ssh remove`

These are recognized and handled specially — the key must land in the
**Linux** ssh-agent (`$SSH_AUTH_SOCK` in WSL), so `wcm.exe` is spawned (not
exec'd) purely to produce key material on stdout:

* `wcm ssh add <name> [-t LIFETIME] [--ssh-add PATH]` → runs `wcm.exe …
  get <name> --field private_key --raw`, then pipes the bytes into
  `ssh-add [-t LIFETIME] -`.
* `wcm ssh remove <name>` → runs `wcm.exe … ssh pubkey <name>` (the
  *public* key line, since `ssh-add -d` removes by public key), then pipes
  it into `ssh-add -d -`.
* `ssh-add` is located via `--ssh-add PATH` → `$WCM_SSH_ADD` → the first
  `ssh-add` on `$PATH`. Not found, non-zero exit, or `wcm.exe` returning
  only whitespace → exit **11** (`HELPER`), with its own exit code and
  stderr relayed unchanged if `wcm.exe` itself failed.
* `wcm ssh pubkey <name>` is **not** intercepted; it proxies like any other
  command and prints on stdout normally.
* Any other shape (missing name, `--help`, an unrecognized flag, an extra
  positional) is deliberately **not** matched, so it falls through to the
  normal proxy path and `wcm.exe` produces its own usage error or help text.

### Environment variable passthrough (`WSLENV`)

Only variables listed in `$WSLENV` cross the WSL↔Windows interop boundary;
the rest of your WSL environment is invisible to `wcm.exe`. The shim
appends `WCM_LAUNCHED_FROM_WSL/w:WCM_PASSPHRASE/w:WCM_EXPORT_PASSPHRASE/w`
to your existing `$WSLENV` (idempotently — it won't double up across
re-runs). The `/w` flag means "forward as-is, WSL → Win32 only", so:

* If you `export WCM_PASSPHRASE=...` (or `WCM_EXPORT_PASSPHRASE`) in your
  WSL shell before running `wcm`, `wcm.exe` sees it too — no extra config
  needed for scripted/CI use.
* `WCM_LAUNCHED_FROM_WSL=1` is set by the shim on every proxied call and
  forwarded the same way; the shim also checks for it on its own way in and
  skips proxying if it's already set, as a double-proxy guard.
* **`WCM_HELLO_FOCUS` is not on this list.** It's read by `wcm-hello`
  (Windows-only) and is *not* auto-forwarded. Set it as a real Windows
  environment variable, or add it to `$WSLENV` yourself (`export
  WSLENV=$WSLENV:WCM_HELLO_FOCUS/w`) if you want to control it from WSL.

### Clipboard

`--clip` is handled entirely inside `wcm.exe` (`crates/wcm-cli/src/clip.rs`,
`arboard`) once the proxied invocation reaches the Windows side — it writes
to the **Windows** clipboard and schedules `wcm.exe unclip` to clear it,
exactly as it would for a native Windows invocation. There is no WSL-side
clipboard code path.

### Exit codes

`0`–`12` and `130` are `wcm.exe`'s own codes, relayed unchanged (see
[EXIT_CODES.md](EXIT_CODES.md)). Two codes are reserved for the shim itself
and never produced by `wcm.exe`:

| Exit | Meaning | When |
|-----:|---|---|
| 126 | `WSL_INTEROP_BROKEN` | The target is a Windows PE but interop can't launch it: binfmt_misc's `WSLInterop`/`WSLInterop-late` entry is disabled, the file is an unrecognized format, or the OS refused to exec it (permissions, `ENOEXEC`). |
| 127 | `WSL_EXE_NOT_FOUND` | `wcm.exe` wasn't found by any of the [lookup steps](#locating-wcmexe) above. |

## Troubleshooting

**"WSL interop cannot launch Windows executables" / exit 126**

```bash
cat /proc/sys/fs/binfmt_misc/WSLInterop     # should print "enabled"
```
If it says `disabled` or the file is missing, add `[interop]
enabled=true` to `/etc/wsl.conf` and run `wsl --shutdown` from Windows
PowerShell. If some distros' `systemd-binfmt.service` keeps clearing the
entry at boot, mask it: `sudo systemctl mask systemd-binfmt.service`.

**"wcm.exe not found from WSL" / exit 127**

Check `$WCM_WINDOWS_EXE` (must point at an existing file if set), `wcm.exe`
on `$PATH`, and the two [installation](#installing-wcmexe-needed-either-way)
locations under `/mnt/*/Users/*/…`. `wcm doctor` prints the resolved path
(or `not found`) alongside WSL detection.

**SSH'd into the Windows machine itself**

Interop launches `wcm.exe` in *your* interactive Windows session — that
falls apart if you SSH'd directly into the Windows OpenSSH server (not into
WSL) and run `wcm`/`wsl.exe` from there: that's "session 0" or a
non-interactive session, and Windows Hello cannot show a prompt. Exit **7**
(`AUTH_UNAVAILABLE`); `wcm doctor` reports the session as `(NOT
interactive)`. Not specific to the WSL shim, but common in the same kind of
remote-access setups.

**Hello dialog hidden behind the terminal**

By default `wcm-hello`'s focus helper polls for the Hello dialog window
(`FindWindowA("Credential Dialog Xaml Host")`) and brings it to the
foreground every 500ms while a prompt is open, specifically so it isn't
left behind other windows when `wcm` is launched from WSL. If it still gets
buried, or the helper misbehaves (fighting focus with something else),
disable it with `WCM_HELLO_FOCUS=0` — set as a Windows environment
variable, or forwarded via `$WSLENV` as described above.

**Passphrase / recovery key without a prompt**

`WCM_PASSPHRASE` and `WCM_EXPORT_PASSPHRASE` set in your WSL shell are
forwarded to `wcm.exe` automatically (see [WSLENV
passthrough](#environment-variable-passthrough-wslenv)) — useful for scripts
and CI, but both bypass the interactive prompt and are visible to anything
that can read your environment; `wcm doctor` flags `WCM_PASSPHRASE` as a
problem when set.

## FAQ

**Do I need different setup for WSL1 vs WSL2?** No. Detection differs
(`WSL_INTEROP` env var vs. `/proc/version` parsing), but the interop
mechanism, argument handling and installation options are identical —
`wcm doctor` just tells you which one it detected.

**Can I use `wcm` on Linux without any Windows machine at all?** Yes:
`WCM_NO_WSL_PROXY=1` (or running the Linux binary outside WSL) skips the
proxy and runs the Linux build natively. Since `wcm-hello` is Windows-only,
only the passphrase/recovery key slots work — useful for opening a
passphrase-only vault or an encrypted export on Linux/macOS directly.

**Where does the vault actually live?** On the Windows filesystem, same as
a native install — by default `%LOCALAPPDATA%\wcm\vault.wcm`. `--vault`/
`$WCM_VAULT` can point anywhere; the shim translates a Linux-style value to
a Windows path for you (see [above](#--vault--wcm_vault)).

**Which `ssh-agent` does `wcm ssh add` use from WSL?** The **WSL** one
(`$SSH_AUTH_SOCK` inside your distro) — the whole point of piping the key
through the Linux `ssh-add` instead of just proxying the command (see
[Option B](#option-b--symlink-straight-to-wcmexe) for the one setup where
that's *not* true).

**Multiple Windows drives or user accounts?** All `/mnt/<drive>/Users/*`
combinations are searched, sorted, so `wcm.exe` is found regardless of
drive/account — `$WCM_WINDOWS_EXE` is the reliable override if you have
more than one and want a specific one.
