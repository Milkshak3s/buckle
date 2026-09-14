#!/bin/bash
# Capture an eslogger + unified-log fixture of a sandboxed cursor-agent session.
#
# Usage (from a terminal with Full Disk Access):
#   sudo ./scripts/capture-cursor-fixture.sh [outdir]
#
# The script starts both sources and waits. Drive cursor-agent as your own user in another
# terminal, for example:
#   cd /private/tmp/buckle-cc-test && cursor-agent -p --trust --sandbox enabled "..."
# then stop the capture with:
#   touch /private/tmp/buckle-cursor-capture.stop
#
# eslogger records the whole Mac, including every exec's full environment. The raw capture stays
# in a root-only temp directory. The fixture keeps only cursorsandbox process trees and their
# denials, and only the environment variables buckle's session detectors declare.
set -euo pipefail
set -m

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" ]]; then
  echo "run with sudo" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/testdata/fixtures/macos14.2-cursor}"
USER_HOME="$(eval echo "~$SUDO_USER")"
GO="${GO:-$USER_HOME/sdk/go1.27.1/bin/go}"
STOP=/private/tmp/buckle-cursor-capture.stop
RAW="$(mktemp -d /private/tmp/buckle-cursor-raw.XXXXXX)"
chmod 700 "$RAW"
WORK="$(sudo -u "$SUDO_USER" mktemp -d /private/tmp/buckle-cursor-work.XXXXXX)"
rm -f "$STOP"

as_user() { sudo -u "$SUDO_USER" "$@"; }
cleanup() { rm -rf "$RAW" "$WORK" "$STOP"; }
trap cleanup EXIT

# Build the filters first so a broken toolchain fails before anything sensitive is recorded.
(cd "$ROOT" && as_user "$GO" build -o "$WORK/stripenv" ./scripts/stripenv && as_user "$GO" build -o "$WORK/trimtree" ./scripts/trimtree)

mkdir -p "$OUT"
MANIFEST="$OUT/manifest.txt"
: >"$MANIFEST"
mark() { echo "$(perl -MTime::HiRes=time -MPOSIX=strftime -e '$t=time; printf "%s.%06d", strftime("%Y-%m-%dT%H:%M:%S", localtime $t), ($t-int $t)*1e6') $*" | tee -a "$MANIFEST"; }

/usr/bin/eslogger exec fork exit >"$RAW/es.jsonl" 2>"$OUT/eslogger.stderr" &
ES=$!
/usr/bin/log stream --predicate 'sender == "Sandbox"' --style ndjson >"$RAW/log.ndjson" 2>"$OUT/log.stderr" &
LOG=$!
sleep 3
if ! kill -0 "$ES" 2>/dev/null; then
  echo "eslogger exited early:" >&2
  cat "$OUT/eslogger.stderr" >&2
  echo "grant Full Disk Access to the terminal app running this script, then retry" >&2
  kill "$LOG" 2>/dev/null || true
  chown -R "$SUDO_USER" "$OUT"
  exit 1
fi
mark "sources started es=$ES log=$LOG"
echo "capturing; drive cursor-agent now, then: touch $STOP"
while [[ ! -e "$STOP" ]]; do sleep 1; done
mark "stop requested"

sleep 5 # late denial lines
mark "stopping sources"
kill -INT "$ES" "$LOG" 2>/dev/null || true
wait "$ES" "$LOG" 2>/dev/null || true

"$WORK/stripenv" <"$RAW/es.jsonl" >"$RAW/es.stripped.jsonl"
"$WORK/trimtree" -root cursorsandbox -es "$RAW/es.stripped.jsonl" -log "$RAW/log.ndjson" -out "$OUT"
sw_vers >"$OUT/sw_vers.txt"
as_user "$USER_HOME/.local/bin/cursor-agent" --version >>"$MANIFEST" 2>/dev/null || true
chown -R "$SUDO_USER" "$OUT"
echo "fixture written to $OUT"
wc -l "$OUT/es.jsonl" "$OUT/log.ndjson"
