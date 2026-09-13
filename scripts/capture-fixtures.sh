#!/bin/bash
# Capture correlated eslogger + unified-log fixtures for buckle replay tests.
#
# Usage (from a terminal with Full Disk Access):
#   sudo ./scripts/capture-fixtures.sh [outdir]
#
# Both sources run concurrently so pids line up between es.jsonl and log.ndjson.
# Job control (set -m) puts eslogger in its own process group; eslogger suppresses
# events from its own group, so without it the workloads below would be invisible.
set -euo pipefail
set -m

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" ]]; then
  echo "run with sudo" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/testdata/fixtures/capture-$(date +%Y%m%d-%H%M%S)}"
WORK="$(sudo -u "$SUDO_USER" mktemp -d /private/tmp/buckle-capture.XXXXXX)"
mkdir -p "$OUT"
MANIFEST="$OUT/manifest.txt"
: >"$MANIFEST"

as_user() { sudo -u "$SUDO_USER" "$@"; }
mark() { echo "$(perl -MTime::HiRes=time -MPOSIX=strftime -e '$t=time; printf "%s.%06d", strftime("%Y-%m-%dT%H:%M:%S", localtime $t), ($t-int $t)*1e6') $*" | tee -a "$MANIFEST"; }

TAG_CMD='cat /etc/hosts | head -1'
TAG="CMD64_$(printf '%s' "$TAG_CMD" | base64)_END__k3j9x0q2m_SBX"
TAGGED_PROFILE="(version 1)
(allow default)
; LogTag: $TAG
(deny file-read-data (literal \"/private/etc/hosts\") (with message \"$TAG\"))"

as_user cc -Wno-deprecated-declarations -o "$WORK/sbinit" "$ROOT/testdata/sbinit/sbinit.c"
printf '(version 1)\n(allow default)\n(deny file-write* (subpath (param "OUT")))\n' >"$WORK/param.sb"
chown "$SUDO_USER" "$WORK/param.sb"

# Scenario: pre-existing tagged run, started before the sources.
mark "preexisting: start (before sources)"
as_user /usr/bin/sandbox-exec -p "$TAGGED_PROFILE" /bin/sh -c 'sleep 6; cat /etc/hosts >/dev/null' 2>/dev/null &
PRE=$!

/usr/bin/eslogger exec fork exit >"$OUT/es.jsonl" 2>"$OUT/eslogger.stderr" &
ES=$!
/usr/bin/log stream --predicate 'sender == "Sandbox"' --style ndjson >"$OUT/log.ndjson" 2>"$OUT/log.stderr" &
LOG=$!
sleep 3
if ! kill -0 "$ES" 2>/dev/null; then
  echo "eslogger exited early:" >&2
  cat "$OUT/eslogger.stderr" >&2
  echo "grant Full Disk Access to the terminal app running this script, then retry" >&2
  kill "$LOG" "$PRE" 2>/dev/null || true
  chown -R "$SUDO_USER" "$ROOT/testdata"
  exit 1
fi
mark "sources started es=$ES log=$LOG"

mark "p_single: sandbox-exec -p, cat denied /private/etc/hosts"
as_user /usr/bin/sandbox-exec -p '(version 1)(allow default)(deny file-read-data (literal "/private/etc/hosts"))' /bin/cat /etc/hosts || true

mark "f_param: sandbox-exec -f file -D OUT=/private/tmp, touch denied"
as_user /usr/bin/sandbox-exec -f "$WORK/param.sb" -D OUT=/private/tmp /usr/bin/touch /private/tmp/buckle_capture_probe || true

mark "f_unreadable: sandbox-exec -f on a root-only file (as root), then file removed"
printf '(version 1)(allow default)(deny network-outbound)\n' >"$WORK/rootonly.sb"
chmod 600 "$WORK/rootonly.sb"
/usr/bin/sandbox-exec -f "$WORK/rootonly.sb" /usr/bin/true || true
rm -f "$WORK/rootonly.sb"

mark "n_named: sandbox-exec -n no-network curl"
as_user /usr/bin/sandbox-exec -n no-network /usr/bin/curl -s -m 2 http://1.1.1.1/ || true

mark "tagged_tree: Claude-style tagged profile, sh -> cat|head + background cat"
as_user /usr/bin/sandbox-exec -p "$TAGGED_PROFILE" /bin/sh -c 'cat /etc/hosts | head -1; (cat /etc/hosts &); wait' || true

mark "dup: one sh pid reads /etc/hosts 40 times (duplicate reports)"
as_user /usr/bin/sandbox-exec -p '(version 1)(allow default)(deny file-read-data (literal "/private/etc/hosts"))' /bin/sh -c 'for i in $(seq 1 40); do : </etc/hosts; done 2>/dev/null' || true

mark "sbinit: non-platform binary calling sandbox_init(no-write)"
as_user "$WORK/sbinit" || true

wait "$PRE" || true
mark "preexisting: exited"

sleep 5
mark "stopping sources"
kill -INT "$ES" "$LOG" 2>/dev/null || true
wait "$ES" "$LOG" 2>/dev/null || true

sw_vers >"$OUT/sw_vers.txt"
chown -R "$SUDO_USER" "$ROOT/testdata"
rm -rf "$WORK"
echo "fixtures written to $OUT"
wc -l "$OUT/es.jsonl" "$OUT/log.ndjson"
