# Manual tester checklist (Windows)

wcm is developed and unit/integration-tested on macOS with a passphrase
backend; **the Windows Hello, DPAPI, TPM and WSL paths can only be verified on
a real Windows machine.** This script walks a tester through everything that
CI cannot cover. Please run it on as many of the combinations below as you
can and paste the results (especially the `wcm doctor --json` outputs) into
the tracking issue.

Target matrix — tick what you covered:

| | Windows 10 22H2 | Windows 11 |
|---|---|---|
| Windows Terminal | ☐ | ☐ |
| conhost (cmd.exe / legacy PowerShell window) | ☐ | ☐ |
| WSL1 distro | ☐ | ☐ |
| WSL2 distro | ☐ | ☐ |
| Hello PIN | ☐ | ☐ |
| Hello face | ☐ | ☐ |
| Hello fingerprint | ☐ | ☐ |
| mingw cross-built `wcm.exe` (`x86_64-pc-windows-gnu`) | ☐ | ☐ |
| MSVC `wcm.exe` (`x86_64-pc-windows-msvc`, from CI/release) | ☐ | ☐ |

Expected exit codes are listed in [EXIT_CODES.md](EXIT_CODES.md). Check them
with `echo $LASTEXITCODE` (PowerShell), `echo %ERRORLEVEL%` (cmd) or
`echo $?` (WSL/bash).

**Use a throw-away vault for all tests:** every command below passes
`--vault C:\wcm-test\vault.wcm` (PowerShell: `$env:WCM_VAULT = 'C:\wcm-test\vault.wcm'`
once, then omit the flag). Delete `C:\wcm-test` when done.

---

## A. Setup and diagnostics

1. Put `wcm.exe` somewhere on `PATH` (e.g. `%LOCALAPPDATA%\Programs\wcm\wcm.exe`).
   Record which build you use (mingw vs MSVC; keep them in separate folders —
   `wcm version` does not distinguish them). Both builds must pass the whole
   script.
2. `wcm version` → prints `wcm 0.x.y (windows, hello=true)`. ☐
3. `wcm doctor` → `hello: available`, `session: N (interactive)`,
   `dpapi: available`, `problems: none` (or only `ssh-add not found`). ☐
4. `wcm doctor --hello-selftest` → a Windows Hello prompt appears **in the
   foreground**; after approval the line
   `hello selftest: OK — create + sign + PKCS#1 v1.5 verify succeeded (tpm=true)`.
   Note whether `tpm=` is `true` or `false` (false = no TPM / VM; report the
   machine model). ☐ mingw ☐ MSVC
5. `wcm doctor --json` → **paste the full JSON into your report** (one per
   build, one per terminal type). ☐
6. `wcm --exit-codes` prints the table. ☐

## B. Init (twice) and the recovery key

7. `wcm init` → Hello prompt to *create* the key (notice on stderr first),
   then a second Hello prompt to sign; the recovery key `WCM1-…` is shown
   once; you are asked to type `yes`. Save the key — you need it in §E. ☐
8. `wcm status` → two slots: `[1] hello  hello  tpm=true dpapi=true`,
   `[2] recovery  passphrase`; `generation: 1`. ☐
9. `wcm init` **again** on the same path → exit **4** (`ALREADY_EXISTS`),
   vault unchanged. ☐
10. `wcm init --no-hello --vault C:\wcm-test\other.wcm` → no Hello prompt, a
    warning that the vault can only be opened with the recovery key; exit 0.
    Delete `other.wcm` afterwards. ☐
11. `wcm init --no-dpapi --vault C:\wcm-test\nodpapi.wcm` → `wcm status`
    shows `dpapi=false` for the Hello slot. Delete afterwards. ☐

## C. Items (one Hello prompt per command)

12. `wcm add demo/pw --generate 20` → exactly **one** Hello prompt; prints the
    generated password (or copies with `--clip`). ☐
13. `echo hunter2| wcm add demo/login --kind login --stdin --field username=alice --tag test`
    → exit 0. (PowerShell: `"hunter2" | wcm add … --stdin`.) ☐
14. `wcm add demo/login --stdin` again → exit **4**. `-f` variant overwrites. ☐
15. `wcm get demo/login` → prints `hunter2`. `wcm get demo/login --field username` → `alice`. ☐
16. `wcm get demo/login demo/pw` → **one** prompt, two lines. ☐
17. `wcm get nope` → exit **3**, message `item not found`. ☐
18. `wcm show demo/login` → password masked (`••••••`); `--reveal` shows it. ☐
19. `wcm ls` → one prompt, lists `demo/login`, `demo/pw`; `wcm ls -l`,
    `wcm ls --tag test`, `wcm ls --json`. ☐
20. `wcm set demo/login url --value https://example.com --public`; `wcm show
    demo/login` displays the url unmasked. ☐
21. `wcm mv demo/pw demo/pw2`; `wcm rm demo/pw2 -f`; `wcm ls` no longer lists it. ☐
22. Binary round-trip: `wcm add demo/blob --file C:\Windows\System32\notepad.exe`
    then `wcm get demo/blob --out-file C:\wcm-test\np.exe` and
    `fc /b C:\Windows\System32\notepad.exe C:\wcm-test\np.exe` → identical.
    `wcm get demo/blob` on a TTY → refuses to dump binary to the terminal and
    points to `--out-file` (non-zero exit, no garbage on screen). ☐
23. Cancel: `wcm get demo/login`, press **Cancel** in the Hello dialog → exit
    **6**, nothing printed. ☐
24. Clipboard: `wcm get demo/login --clip --clip-timeout 10` → value in
    clipboard; after ~10 s it is cleared (paste into Notepad before/after).
    Then `wcm generate --clip` similarly. ☐
25. Focus: run step 15 from a **WSL** shell and from a Windows Terminal tab
    that is *behind* another window → the Hello dialog comes to the front.
    Repeat with `WCM_HELLO_FOCUS=0` and note the difference. ☐

## D. Concurrency (two terminals)

26. Open two terminals. In **both** run `wcm add race-N --generate` but only
    approve the Hello prompt in terminal 1 first; let it finish (exit 0), then
    approve terminal 2. Terminal 2 must exit **9** (`LOCKED`, "modified
    concurrently") without corrupting the vault. `wcm ls` afterwards shows
    `race-1` only; `vault.wcm.bak` exists. ☐
27. Re-run terminal 2's command → succeeds (exit 0). ☐

## E. PIN reset and `wcm recover`

28. Settings → Accounts → Sign-in options → **remove the PIN** (and
    face/fingerprint), reboot if asked, then set a **new PIN**. ☐
29. `wcm get demo/login` → Hello slot unusable: notice
    `key slot 'hello' unavailable: Windows Hello key for this vault is gone…`,
    falls through to the recovery slot: prompt `Passphrase / recovery key:`
    — type the recovery key from step 7 (lowercase / without dashes is OK) →
    prints `hunter2`. ☐
30. `wcm recover` → asks for the recovery key, creates a new Hello key (two
    prompts), `wcm status` shows a fresh `hello` slot, `generation` +1. ☐
31. `wcm get demo/login` → Hello prompt again, works. ☐
32. Wrong recovery key: `wcm --slot recovery get demo/login` and type garbage
    → exit **2** (malformed) or **8** (well-formed but wrong). ☐
33. `wcm rekey` → works, items still readable afterwards. ☐
34. `wcm slot add --passphrase` (choose a passphrase) → `wcm --slot
    passphrase get demo/login` opens without Hello. `wcm slot rm passphrase -f`
    removes it; `wcm slot rm recovery -f` while it is the last slot → error. ☐

## F. Export / import

35. `wcm export -o C:\wcm-test\backup.wcm` (set `WCM_EXPORT_PASSPHRASE` or
    type one) → file created. ☐
36. `wcm --vault C:\wcm-test\backup.wcm ls` → opens with the export
    passphrase only, no Hello. ☐
37. `wcm import C:\wcm-test\backup.wcm` into the main vault → `skipped`
    counts equal the number of items; `--overwrite` / `--replace` variants. ☐
38. `wcm export --plaintext --i-know -o C:\wcm-test\plain.json` → readable
    JSON; `wcm export --plaintext` without `--i-know` → refused (exit 2). ☐

## G. SSH

39. `ssh-keygen -t ed25519 -f C:\wcm-test\id_test -N ""`;
    `wcm add ssh/test --file C:\wcm-test\id_test` → kind auto-detected as
    `ssh-key`; `wcm show ssh/test` lists `public_key` and `fingerprint`. ☐
40. `wcm ssh pubkey ssh/test` equals the content of `id_test.pub`. ☐
41. Start the `ssh-agent` service (`Get-Service ssh-agent | Set-Service
    -StartupType Manual; Start-Service ssh-agent`), then `wcm ssh add ssh/test`
    → `ssh-add -l` lists the fingerprint; `wcm ssh remove ssh/test` removes it. ☐
42. Stop the service, `wcm ssh add ssh/test` → exit **11** (`HELPER`). ☐
43. **SSH into the Windows machine** (OpenSSH server, session 0) and run
    `wcm get demo/login` there → exit **7** with
    `no interactive Windows desktop session`. `wcm doctor` in that session
    reports `(NOT interactive)` and lists the problem. ☐

## H. `wcm run`

44. `wcm run --env PW=demo/login --env USER=demo/login/username -- cmd /c "echo %USER%"`
    → prints `alice`; with `powershell -c 'echo $env:PW'` → `hunter2`. ☐
45. `wcm run --env X=nope -- cmd /c echo hi` → exit **3**, command not run. ☐

## I. WSL (see [WSL.md](WSL.md))

Do this in **both** a WSL1 and a WSL2 distro. Build or copy the Linux `wcm`
binary into the distro (`cargo build -p wcm-cli` inside WSL, or the
`x86_64-unknown-linux-musl` release tarball).

46. `wcm doctor` from WSL → `wsl: WSL2 (wcm.exe: /mnt/c/…/wcm.exe)` (or WSL1);
    the output otherwise matches the Windows one (it was produced by `wcm.exe`). ☐
47. `wcm get demo/login` from WSL → Hello prompt on the Windows desktop,
    prints `hunter2`, exit 0; `wcm get nope` → exit 3 (exit code relayed). ☐
48. `wcm add wsl/file --file ./some-linux-file` → works (path translated with
    `wslpath`); `wcm get wsl/file --out-file /tmp/x` → identical file. ☐
49. `WCM_WINDOWS_EXE=/nonexistent wcm ls` → exit **127**;
    `WCM_NO_WSL_PROXY=1 wcm status` → runs the Linux binary natively (exit 5
    unless a Linux vault exists). ☐
50. `wcm ssh add ssh/test` from WSL → key lands in the **Linux** `ssh-agent`
    (`ssh-add -l` in WSL lists it). ☐
51. Break interop (`echo 0 | sudo tee /proc/sys/fs/binfmt_misc/WSLInterop`,
    or `[interop] enabled=false` in `/etc/wsl.conf` + `wsl --shutdown`) →
    `wcm ls` exits **126** with a clear message. Restore interop afterwards. ☐

## J. Session cache (`wcm agent`, see [AGENT.md](AGENT.md))

52. `wcm agent start --idle 2m` → `agent started (pid N, idle 2m, ttl 1h)`;
    `wcm agent status` → `agent:    running (pid N)` and an endpoint
    `\\.\pipe\wcm-agent-<32 hex>`. ☐
53. `wcm get demo/login` → **one** Hello prompt, prints `hunter2`;
    `wcm get demo/login` again within 2 minutes → **no prompt**, same output;
    `wcm status` → `agent:      running, cached for this vault (…)`. ☐
54. Close the console/terminal that ran `wcm agent start`, then from a **new**
    window: `wcm agent status` still shows it running (same pid) and
    `wcm get demo/login` still needs no prompt. No console window flashed when
    the agent started and none is left behind for it. ☐
55. `wcm agent lock` → the next `wcm get demo/login` prompts again. Wait > 2
    minutes without using wcm → the next `get` prompts again (idle expiry). ☐
56. From a **different Windows user** on the same machine (or `runas`):
    `wcm agent status` → `not running` (their own state), and connecting to
    your pipe name with e.g. PowerShell
    `[System.IO.Pipes.NamedPipeClientStream]::new('.', 'wcm-agent-<hex>').Connect(1000)`
    fails with *access denied*. ☐
57. From WSL: `wcm agent start` returns immediately (the Linux shell is not
    blocked), `wcm agent status` from WSL and from PowerShell show the same pid,
    `wcm get demo/login` from WSL prompts once and then not. `wcm agent stop`
    → `tasklist | findstr wcm` shows no `wcm.exe` left. ☐

## K. Cleanup and report

58. `Remove-Item -Recurse C:\wcm-test`; remove the test Hello credential if
    you want (`wcm recover`/`init` create `wcm-v1-<id>` credentials; they are
    harmless). ☐
59. Report: Windows version/build, hardware (TPM yes/no), terminal, Hello
    method, which build (mingw/MSVC), the `wcm doctor --json` outputs, and
    every step whose result differed from the expectation above (with the
    exact stderr text and exit code).

Thank you!
