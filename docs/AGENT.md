# Session cache: `wcm agent`

By default every `wcm` command that needs the vault key shows one Windows
Hello prompt. `wcm agent` is an **optional, explicitly started** helper that
keeps the vault's data key (DEK) in memory for a bounded time, so a burst of
commands (`wcm get a && wcm get b && wcm run …`) needs a single prompt.

It is off unless you start it. Read [SECURITY.md](SECURITY.md#session-cache)
before enabling it on a machine you share.

## Usage

```bash
wcm agent start                      # background agent: idle 10m, ttl 1h
wcm agent start --idle 5m --ttl 30m  # forget keys 5 min after last use, 30 min after caching
wcm agent start --max-uses 3         # …or after 3 uses
wcm agent status                     # running? which vaults are cached, for how long
wcm agent lock                       # forget every key now (agent keeps running)
wcm agent stop                       # forget every key and exit
```

Durations accept `s`, `m`, `h` and combinations (`90s`, `10m`, `1h30m`).
`start` is idempotent: if an agent already runs it says so and exits 0 (stop
it first to change the policy). `stop` and `lock` are no-ops when nothing runs.

Once the agent runs, every command uses it automatically:

1. the command asks the agent for the key of the vault it is about to open;
2. on a hit it opens the vault without prompting (also with `--no-input`);
3. on a miss it unlocks as usual (Hello / passphrase) and hands the key to the
   agent for the next command.

`wcm status` shows whether the current vault is cached; `wcm doctor` shows the
agent's pid and endpoint.

## Opting out per command

* `--no-agent` (global flag) or `WCM_NO_AGENT=1`: neither read from nor write
  to the agent for this invocation.

## Expiry

A key is forgotten when the first of these happens:

| Option | Default | Meaning |
|---|---|---|
| `--idle` | `10m` | time since the key was last handed out |
| `--ttl` | `1h` | time since the key was cached, regardless of use |
| `--max-uses` | unlimited | number of times the key was handed out |

Expired keys are zeroized by a sweeper every second; `lock` and `stop` wipe
immediately. The agent does not react to screen lock or sleep in this version.

## Where it lives

| | Windows | Linux / macOS |
|---|---|---|
| endpoint | `\\.\pipe\wcm-agent-<random>` with an owner-only DACL | `$XDG_RUNTIME_DIR/wcm/agent.sock` (else `<data dir>/run/agent.sock`), directory `0700` |
| state file | `%LOCALAPPDATA%\wcm\agent.json` | `~/.local/share/wcm/agent.json` (macOS: `~/Library/Application Support/wcm/agent.json`) |

`agent.json` records the endpoint, pid, start time and version — no secrets.
Clients only connect to the endpoint written there, so another user cannot
plant a fake agent under a predictable name. `WCM_DATA_DIR` moves the state
file; `WCM_AGENT_ENDPOINT` overrides the endpoint (tests).

If the agent is killed (`taskkill`, `kill -9`, logoff) the stale `agent.json`
and socket file are cleaned up by the next command / `wcm agent start`.

## From WSL

The Linux `wcm` hands every command to `wcm.exe`, so `wcm agent start` from
WSL starts the agent **on the Windows side** and every later command from
WSL, PowerShell or cmd shares it.

## Threats

While the agent holds a key, any process running as your user can ask for it —
the Hello gesture is no longer required until the key expires. Someone who
obtains the DEK can read the vault file until you run `wcm rekey`. Keep
`--idle` short on shared machines, `wcm agent lock` before you walk away, and
use `--no-agent` for sensitive one-offs. See [SECURITY.md](SECURITY.md).
