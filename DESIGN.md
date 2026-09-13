# buckle — Design

buckle audits macOS Seatbelt sandbox execution. It watches `sandbox-exec` runs (including those launched by third-party tools such as Claude Code), records that a sandbox was applied and with which profile, and attributes kernel Sandbox denials to those runs. Records go to a local SQLite database.

Status: design confirmed 2026-09-12. Development started 2026-09-13. The report server demo was confirmed 2026-09-13 (§11, [spec](docs/superpowers/specs/2026-09-13-buckle-report-server-design.md)).

> **macOS upgrades are paused (2026-09-13).** Until they resume, the effective target is **macOS 14.2 (arm64)**, where the §2 facts were verified. The §10 checklist is deferred until an upgrade happens; don't adopt APIs or behavior newer than 14.2.

---

## 1. Goals and scope

| Decision | Choice |
|---|---|
| Purpose | Audit your own sandboxed workloads: what each run was, and what got blocked |
| Deployment | Your own dev Macs, run by hand. They can optionally ship data to a report server (§11). |
| macOS support | Latest macOS only |
| Sandbox kinds | `/usr/bin/sandbox-exec` runs from any launcher, plus in-process `sandbox_init()` users that pass the filter in §4.4 |
| Out of scope | App Sandbox apps, Apple platform daemons, allowed-operation tracing, tamper resistance / hostile-host threat model, always-on daemon mode |
| Events recorded | Sandbox applied; denials |

## 2. Verified platform facts

These were checked on macOS 14.2 (arm64, SIP on). **Re-verify all of them after upgrading to the latest macOS** (see §10).

### Unified log
- Denials come from the kernel (`processID` 0, `processImagePath` `/kernel`, `senderImagePath` `.../Sandbox.kext/...`). You can read them **without root** via `log show` or `log stream --predicate 'sender == "Sandbox"'`.
- Message format: `Sandbox: <name>(<pid>) deny(<n>) <operation> <target>`. Examples:
  - `Sandbox: cat(9854) deny(1) file-read-data /private/etc/hosts`
  - `Sandbox: curl(9859) deny(1) network-outbound remote:*:80`
- There is **no profile name, audit token, or per-process UUID**. The only process identity is the `name(pid)` text. `machTimestamp` is available for ordering.
- Children report their own name and pid (e.g. `cat(10080)`, `head(10081)` under `sh`).
- `(deny ... (with message "TAG"))` appends `\nTAG` to `eventMessage`, and children inherit it.
- Repeats get collapsed into `N duplicate reports for Sandbox: ...` (singular form: `1 duplicate report for Sandbox: ...`).
- **Denial logging is lossy for non-platform binaries (verified 2026-09-13, 14.2).** The same denial (`file-read-data /private/etc/hosts`, `sandbox-exec -p`) logged 30/30 times from platform `/bin/cat`, but only 14/30 from an ad-hoc-signed C binary: 10/18 alternating with `cat`, 4/6 back-to-back, and 0/6 with a `with message` tag. `log show` misses the same pids, so the kernel suppresses them. No `duplicate reports` line is emitted for the dropped ones. Startup denials from non-platform binaries (e.g. `sysctl-read` in libSystem init) do log, and so does a `sandbox_init()` process at least sometimes. Treat recorded denials as a **lower bound**, especially for non-platform processes.
- `sender == "Sandbox"` also matches `System Policy: <name>(<pid>) deny(1) ...` lines (e.g. `eslogger(…) deny(1) system-privilege 1016` when eslogger lacks FDA). Only `Sandbox:` lines are denials.
- `log stream --style ndjson` prints a non-JSON `Filtering the log data using ...` banner first, and a `{"count":N,"finished":1}` trailer on exit.
- `/bin/sh` reports as `bash(<pid>)`.
- Paths are logged fully resolved (`/private/etc/hosts`). SBPL `literal` rules must also use the resolved path.
- `(allow ... (with report))` logs `allow` lines at Default level. `(deny ... (with report))` is rejected by `sandbox-exec`.
- In zsh, `log` is a builtin, so always invoke `/usr/bin/log`.

### sandbox-exec
- Present but marked DEPRECATED in its man page. It still works.
- It **exec()s into the target**, so the sandboxed process keeps sandbox-exec's pid. After the exec, argv no longer shows `-p`, `-f`, or `-D`, so the profile can't be recovered by inspecting the process afterwards.
- Short-lived commands finish in well under a polling interval, so polling `ps` doesn't work.

### eslogger / Endpoint Security
- Requires root, and the responsible process (your terminal) needs Full Disk Access.
- Its man page says it is "NOT API", so its JSON structure isn't guaranteed. JSON mirrors `es_message_t` (e.g. `.process.audit_token.pid`, `.event.exec.target.executable.path`) and includes `schema_version` and `version`.
- **No event type relates to sandboxing**, and ES structs have **no entitlement or sandbox fields**.
- The useful `es_process_t` fields are `audit_token` (pid + pidversion), `ppid`, `original_ppid`, `parent_audit_token`, `responsible_audit_token`, `is_platform_binary`, `codesigning_flags`, `signing_id`, `team_id`, `cdhash`, `executable`, and `start_time`. Exec events also include args.
- There is no system-wide process-creation notification without ES.
- **exec bumps pidversion** (verified 2026-09-13, fixture `testdata/fixtures/macos14.2`). In an exec event, `process.audit_token` is the old image and `event.exec.target.audit_token` is the new one, so each exec'd image has its own token. `/bin/sh` execs `/bin/bash` on the same pid.
- Background grandchildren are reparented (`ppid 1` by the time they exec). Tree membership therefore has to follow fork/exec edges, not `ppid`.
- sandbox-exec's getopt string is `D:de:f:n:p:t:`, and attached (`-pTEXT`) and `--` forms work.
- eslogger JSON on 14.2: `schema_version` 1, `version` 7. The event kind is the single key under `event`.

### Other
- `sandbox_check(pid, NULL, 0)` works without root on any pid. It's not needed in v1 (and would need cgo).
- `codesign -d --entitlements - --xml <binary>` takes about 0.01–0.28s.
- **Claude Code** (2.1.270) runs `sandbox-exec -p <profile> <shell> -c <cmd>`. The profile starts with `(version 1)`, `(deny default (with message "<TAG>"))`, and `; LogTag: <TAG>`. The tag is `CMD64_<base64(payload)>_END_<suffix>`, where `<suffix>` is `_<9 random base36 chars>_SBX` and stays fixed for one Claude process.
- **Correction (buckle live test, 2026-09-13, `claude -p` headless with `sandbox.enabled`):** the base64 payload decoded to the **tool_use ID** (`toolu_01…`), not the command. buckle's `tag_command` column therefore holds that ID. The real command is in the run's argv: `/bin/zsh -c "source <shell snapshot> && … eval '<command>' …"`. Interactive sessions are unverified. The same test found other details:
  - The profile is about 23KB. It starts with `(deny default (with message TAG))`, and the tag repeats on each deny rule.
  - One `sandbox-exec` run per Bash tool call. The sandbox-exec image execs `/bin/zsh`, which runs the command as child processes.
  - Every zsh logs a tagged `mach-lookup com.apple.diagnosticd` denial, and curl logs dozens of them.
  - Denied writes from Homebrew `python3` and `node` (non-platform) produced no log lines at all, while `touch`, `sh`/`bash` and `curl` did.

## 3. Architecture

```
sudo buckle watch
 ├── eslogger exec fork exit  (JSON) ──┐
 │                                     ├──► correlator ──► SQLite (SUDO_USER's DB)
 └── /usr/bin/log stream               │     (process table, run/session
     --predicate 'sender == "Sandbox"' │      tracking, denial buffer,
     --style ndjson           (ndjson)─┘      codesign cache)

buckle query / report  (reads SQLite; needs sudo while watch/ship hold the DB, §6)

sudo buckle ship ──HTTP JSON──► buckle serve ──► server.db ──► web UI   (§11)
```

- Language: **Go**, current arm64 toolchain, **no cgo**.
- Build and distribution: local `go build`. No signing or packaging.
- Mode: **on-demand foreground CLI**. No daemon.

## 4. Watch behavior

### 4.1 Startup
1. Must run under `sudo`. Resolve `SUDO_USER` to locate that user's database.
2. Open or create the DB, then **prune** runs older than 30 days (§6).
3. Spawn both source subprocesses. If eslogger fails to start (e.g. missing FDA), exit non-zero with an actionable message such as "grant Full Disk Access to <terminal>".

### 4.2 Runs and processes
- A **run** is a process tree rooted at an exec of `/usr/bin/sandbox-exec`, together with all of its descendants.
- Processes are keyed by **audit token (pid + pidversion)** to handle pid reuse. The tree is built from eslogger `exec`, `fork`, and `exit` events.
- Every process in a run is stored as its own row: pid, pidversion, parent, exec path, args, start time, and exit time.
- "Sandbox applied" is the exec event of `sandbox-exec`.

### 4.3 Profile capture
Profiles are parsed from the `sandbox-exec` exec args:
- `-p <text>`: full profile text.
- `-f <path>`: read the file **as soon as the exec event arrives**. If it can't be read, store the path and mark the contents missing. Only regular files up to 1 MiB are read. `/dev/fd/N` and `/dev/stdin` (process substitution) are recorded as "passed by file descriptor; contents unavailable", because opening them as root would read buckle's own descriptors. Other devices and FIFOs are refused so they can't block the watcher.
- `-n <name>`: store the name.
- `-D key=value`: always stored.
- Profile text is **deduplicated by hash**.

### 4.4 sandbox_init() candidates
A process outside any sandbox-exec tree is a candidate only if **all** of these are true:
- buckle saw its exec during this watch,
- it is **not** a platform binary (`is_platform_binary`), and
- it does **not** have `com.apple.security.app-sandbox`.

The entitlement check is **lazy**. It runs `/usr/bin/codesign` when the candidate's first denial arrives, and results are cached by cdhash. Candidates get a run with **profile unknown**.

This filter never applies to sandbox-exec trees, which are tracked regardless (sandbox-exec is itself a platform binary).

### 4.5 Sessions
- A session exists **only** when a known tag format is recognized. v1 hardcodes **Claude Code's** tag.
- The tag is read from the profile text at exec time (`with message` / `; LogTag:`), which means runs with no denials still get their session. It is also read from denial lines.
- Session id is the tag suffix (`_<random>_SBX`). The command is decoded from `CMD64_<base64>_END`.
- Untagged runs have no session.

### 4.6 Denials
- Parse `eventMessage` into process name, pid, deny count, operation, target, and optional trailing tag.
- `N duplicate reports for Sandbox: ...` lines add to a **count column** on the matching denial row instead of creating new rows.
- Allow lines are ignored.
- **Attribution:** match pid to a live tracked process (sandbox-exec run or candidate). Use timing to make sure the denial belongs to the right pidversion.
- **Storage policy:** only attributed denials are stored, with the orphan exception below.
- **Completeness (decided 2026-09-13):** the kernel drops many denial lines from non-platform binaries (§2), and there is no other unprivileged source. v1 accepts this: stored denials are a **lower bound**. Every process row records `is_platform_binary` from eslogger, so reports can show which counts may be incomplete. §4.4 candidates stay in scope even though their denials are the least reliable.

### 4.7 Races and unmatched denials
The two streams arrive independently, so a denial can show up before its exec/fork event, or after the process has exited.
- Unmatched denials wait in a **buffer** (default ~5s, configurable by flag), and matching is retried during that time.
- A denial is decided only after **both** the buffer window has passed **and** the eslogger stream has reported events past the denial's timestamp. Otherwise a lagging eslogger would make a real sandbox-exec child look pre-existing or like a `sandbox_init` user. If eslogger stays behind for 10× the buffer, the denial is decided anyway, but only by attribution or orphaning (no adoption or candidate run), and buckle prints a warning.
- Duplicate-report lines add to the earlier row only while the pid still refers to the same process (the same image or one it exec'd into). Otherwise they follow that pid's orphan row, or start a new denial.
- After the window expires:
  - If the pid appeared in **any** eslogger exec/fork event during this watch, the denial goes into the **orphan** table.
  - Otherwise it is dropped (system noise).

### 4.8 Pre-existing runs
Runs already in progress when `watch` starts produce no exec event. A run like that is **adopted partially** only when a denial carries a **recognized tag**. It is marked "started before watch", with the profile unknown. Untagged pre-existing processes are ignored.

### 4.9 Failure and shutdown
- **eslogger schema drift:** parse only the needed fields and warn when they're missing. Don't exit on that alone.
- **A source subprocess dies:** flush, then exit non-zero with a clear error. No restarts, no degraded mode.
- **Ctrl-C / SIGTERM:** drain the buffer (match or orphan), then close open runs and processes with end time unknown and status `watch stopped`. A later watch never resumes them.

## 5. Query / report

`buckle query` / `buckle report` run against the user's DB. They work without sudo unless a root process (`watch` or `ship`) holds the WAL files, in which case they ask for sudo (§6).

v1 features:
- **List sessions and runs**, filterable by time range, session, command substring, and has-denials.
- **Run detail**: profile text, process tree, and denials.
- **Denial aggregates**: grouped by operation and target across runs (e.g. top blocked paths).

Output formats: **JSON / JSONL** and **CSV**.

Run detail and denial aggregates include each process's platform/non-platform flag, and a note that non-platform denial counts are lower bounds (§4.6).

There's no orphan command in v1. Inspect orphans with `sqlite3` directly.

## 6. Storage

- **SQLite** via `modernc.org/sqlite` (pure Go).
- Location: `SUDO_USER`'s `~/Library/Application Support/buckle/buckle.db`, **owned by that user** even though `watch` writes it as root.
- Retention: every `watch` start **prunes runs older than 30 days**. Pruning cascades to their processes, denials, and orphans, and removes profiles nothing references any more.

Main entities: `sessions`, `runs`, `processes`, `profiles` (by hash), `denials`, `orphans`. Columns get finalized in the implementation plan.

**Schema v2 (2026-09-13):**
- **Change tracking:** every table gets a `rev` column. Triggers stamp it from a global counter on each insert and update.
- **`meta.db_instance`:** a random UUID identifying this DB.
- **Journal mode** is WAL.
- **Upgrading:** existing v1 DBs are refused until `buckle migrate`, run without sudo, upgrades them. New DBs start at v2.
- **Privileges:** WAL files created by root `watch` are root-owned, so `ship` always needs sudo, and `query`/`report` need sudo while those files exist. This reverses the v1 plan's DELETE-mode choice, so that readers don't block `watch`.

Details are in the [server spec](docs/superpowers/specs/2026-09-13-buckle-report-server-design.md) §2.

## 7. Testing

- **Recorded fixtures:** capture real eslogger JSON and `log stream` ndjson once, then replay them in unit tests covering parsing, tree building, attribution, buffering, and duplicates.
- **Local integration (opt-in, sudo):** an end-to-end test that runs real `sandbox-exec` workloads (including multi-process trees and tagged profiles) on this Mac and checks the DB contents.

## 8. Explicit non-goals (v1)

- `buckle run` wrapper, and profile authoring or suggestion helpers.
- Always-on launchd daemon. `ship` and `serve` are foreground commands too.
- Sessions for untagged launchers, or configurable tag formats.
- Allowed-operation tracing.
- Native Endpoint Security client (entitlement, system extension).
- Signed or notarized distribution.
- Tamper resistance.

## 9. Operational prerequisites

- Latest macOS and matching Xcode/SDK. Upgrades are paused, so this is currently 14.2 with the 14.2 SDK.
- Current arm64 Go toolchain: go1.27.1 darwin/arm64 at `~/sdk/go1.27.1` (the old 1.20.1 amd64 at `/usr/local/go` is too old for modernc.org/sqlite, which needs ≥1.25).
- Full Disk Access for the terminal app that runs `sudo buckle watch`.

## 10. Re-verify after macOS upgrade

- [ ] `/usr/bin/sandbox-exec` still exists and still execs into the target.
- [ ] `Sandbox:` denial line format, `with message` tag placement, and duplicate-report format.
- [ ] `log stream --style ndjson` fields, and that no root is required.
- [ ] `eslogger --list-events` still has `exec`, `fork`, `exit`, and the exec JSON still includes args, audit tokens, `is_platform_binary`, `cdhash`.
- [ ] Claude Code's sandbox profile and tag format (`CMD64_..._END__..._SBX`).
- [ ] `ioreg -rd1 -c IOPlatformExpertDevice` still reports `IOPlatformUUID`.

## 11. Report server (demo)

Confirmed 2026-09-13. This is a deliberate scope change: v1 was local-only. The full design is in [docs/superpowers/specs/2026-09-13-buckle-report-server-design.md](docs/superpowers/specs/2026-09-13-buckle-report-server-design.md).

- **Topology:** designed for a central server with a few Macs. The demo has one Mac reporting to a server on loopback, with no auth and no TLS.
- **`sudo buckle ship`:** a foreground loop (every 10s by default) that sends rows changed since the server's cursor. Host identity is `IOPlatformUUID` plus the hostname. On network or 5xx errors it retries with backoff; on a 4xx it exits.
- **`buckle serve`:** mirrors endpoint rows into `server.db`, keyed by host, DB instance and local id. It ignores endpoint pruning and keeps history forever.
- **UI:** server-rendered pages with no JS. A hosts page lists Claude sessions and "Untagged runs". A run detail page shows the raw argv, the profile, and a timeline of process events and denials. Times are shown in UTC and in the server's local time.
