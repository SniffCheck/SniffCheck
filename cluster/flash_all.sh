#!/usr/bin/env bash
set -u
IDF_HOME="${IDF_HOME:-$HOME/esp/esp-idf}"
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE="$HOME/.cache"; LOG_DIR="$CACHE/cluster-logs"; STAMP="$(date +%Y%m%d-%H%M%S)"
PORT_MASTER="${PORT_MASTER:-/dev/ttyACM0}"
PORT_BRAIN="${PORT_BRAIN:-/dev/ttyACM3}"
PORT_ARM1="${PORT_ARM1:-/dev/ttyACM1}"
PORT_ARM2="${PORT_ARM2:-/dev/ttyACM2}"

proj()  { case "$1" in master) echo master;; brain) echo brain;; arm1|arm2) echo arm;; esac; }
bdir()  { echo "$CACHE/cluster-$1-build"; }
port()  { case "$1" in master) echo "$PORT_MASTER";; brain) echo "$PORT_BRAIN";; arm1) echo "$PORT_ARM1";; arm2) echo "$PORT_ARM2";; esac; }
dargs() { case "$1" in arm1) echo "-DARM_INDEX=1";; arm2) echo "-DARM_INDEX=2";; *) echo "";; esac; }
ROLES=(master brain arm1 arm2)

MODE="${1:-all}"
if ! command -v idf.py >/dev/null 2>&1; then
    mkdir -p "$LOG_DIR"
    # shellcheck disable=SC1091
    source "$IDF_HOME/export.sh" >"$LOG_DIR/$STAMP-idf-export.log" 2>&1 \
        || { echo "FAIL: could not source $IDF_HOME/export.sh"; exit 1; }
fi
mkdir -p "$LOG_DIR"

if [ "$MODE" = "clean" ]; then
    for r in "${ROLES[@]}"; do rm -rf "$(bdir "$r")" && echo "removed $(bdir "$r")"; done; exit 0
fi
if [ "$MODE" = "monitor" ]; then
    R="${2:-master}"; exec idf.py -B "$(bdir "$R")" -p "$(port "$R")" monitor
fi

run() {
    local label="$1" slug="$2"; shift 2
    local log="$LOG_DIR/$STAMP-$slug.log"; printf '  %-22s ' "$label"
    local t0 t1 rc; t0=$(date +%s); "$@" >"$log" 2>&1; rc=$?; t1=$(date +%s)
    if [ $rc -eq 0 ]; then echo "OK   ($((t1-t0))s)"
    else echo "FAIL ($((t1-t0))s, exit $rc)"; echo "  -- tail $log --"; tail -n 25 "$log"; exit $rc; fi
}

for r in "${ROLES[@]}"; do
    P="$(cd "$PROJ_DIR/$(proj "$r")" && pwd)"; BD="$(bdir "$r")"; D="$(dargs "$r")"
    echo "[$r]  proj $(proj "$r")  build $BD  port $(port "$r")"
    cd "$P" || { echo "FAIL: no project at $P"; exit 1; }
    if [ ! -f "$BD/sdkconfig" ]; then
        run "set-target esp32c5" "$r-settarget" idf.py -B "$BD" --preview $D set-target esp32c5
    fi
    run "build" "$r-build" idf.py -B "$BD" $D build
    [ "$MODE" = "build" ] && continue
    run "flash ($(port "$r"))" "$r-flash" idf.py -B "$BD" -p "$(port "$r")" flash
done
echo "$([ "$MODE" = build ] && echo built || echo flashed) all three. monitor: ./flash_all.sh monitor master|arm1|arm2"
