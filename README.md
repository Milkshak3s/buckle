# buckle

buckle audits macOS Seatbelt sandboxes. While `sudo buckle watch` runs, it records every `sandbox-exec` run, including runs launched by tools such as Claude Code: the profile, the process tree, and the kernel Sandbox denials attributed to that run. It also records non-platform processes that sandbox themselves with `sandbox_init()`. Everything goes into a SQLite database in your home directory. See [DESIGN.md](DESIGN.md).

Target: macOS 14.2 on Apple silicon.

## Build

```sh
~/sdk/go1.27.1/bin/go build ./cmd/buckle
```

This is pure Go (no cgo), and the only dependency is `modernc.org/sqlite`.

## Watch

The terminal app you run buckle from needs **Full Disk Access** (System Settings → Privacy & Security → Full Disk Access), because `eslogger` requires it.

```sh
sudo ./buckle watch            # Ctrl-C to stop
sudo ./buckle watch --buffer 10s
```

The database is `~/Library/Application Support/buckle/buckle.db`. It belongs to your user even though `watch` runs as root. Each `watch` start deletes runs older than 30 days.

## Upgrading an existing database

Databases created before the report server use schema v1. Upgrade once, without sudo, while `watch` isn't running:

```sh
./buckle migrate
```

## Report server (demo)

Ship your local data to a web UI running on the same Mac:

```sh
./buckle serve                  # http://127.0.0.1:8080, no auth; data in ~/Library/Application Support/buckle/server.db
sudo ./buckle watch             # in a second terminal
sudo ./buckle ship              # in a third; sends changes every 10s to http://127.0.0.1:8080
```

Open http://127.0.0.1:8080 to see hosts and their Claude sessions, plus an "Untagged runs" group. Each run page shows the command, the profile, and a timeline of processes and denials. `serve` flags: `--addr`, `--db`, `--refresh 10s` (0 disables auto-refresh). `ship` flags: `--server`, `--interval`, `--db`.

The server keeps its own history. Pruning on the endpoint never removes anything from the server.

## Query

These commands don't need sudo, unless `watch` or `ship` is running: those root processes own the database's WAL files, so the query commands then ask you to re-run with sudo.

```sh
./buckle query sessions
./buckle query runs --since 24h --has-denials
./buckle query runs --session _k3j9x0q2m_SBX --format csv
./buckle query run 42                       # profile text, process tree, denials
./buckle report denials --by target --top 20
```

Output is `--format json` (the default), `jsonl`, or `csv`. Orphan denials aren't shown by any command, so read them with `sqlite3`:

```sh
sqlite3 ~/Library/Application\ Support/buckle/buckle.db 'select * from orphans order by time desc limit 20'
```

## Caveats

- **Denial counts are lower bounds.** The kernel drops many denial log lines, most of them from non-platform binaries such as Homebrew tools, node, Go programs, and your own builds. Every process row has `is_platform_binary`, and the reports include a `nonplatform_count` column.
- Sessions exist only for Claude Code's sandbox tag (`CMD64_…_END__…_SBX`).
- A tagged run that started before `watch` is adopted when it logs a tagged denial. It gets `started_before_watch` and an unknown profile.
- `eslogger` output is not a stable API. If its schema changes, buckle warns and keeps going on a best-effort basis.

## Tests

```sh
~/sdk/go1.27.1/bin/go test ./...
```

Unit tests replay the fixture captured on macOS 14.2 in `testdata/fixtures/macos14.2`. To record a new one (needs sudo and Full Disk Access):

```sh
sudo ./scripts/capture-fixtures.sh testdata/fixtures/<name>
```

The end-to-end test runs real sandboxes. Build it as your user, then run it with sudo:

```sh
~/sdk/go1.27.1/bin/go test -c -tags integration -o /tmp/buckle-itest ./integration
sudo /tmp/buckle-itest -test.v
```
