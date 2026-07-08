#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$HOME/.cache/sniffcheck-build}"
OUT="$ROOT/docs/webflasher"
FW="$OUT/firmware"
ARGS="$BUILD/flasher_args.json"
EUI="$ROOT/data/eui.bin"
EUI_OFFSET=0x310000

[ -f "$ARGS" ] || { echo "error: no $ARGS — run 'idf.py build' first" >&2; exit 1; }
[ -f "$EUI" ]  || { echo "error: no $EUI" >&2; exit 1; }
command -v esptool.py >/dev/null \
  || { echo "error: esptool.py not on PATH — run '. \$HOME/esp/esp-idf/export.sh'" >&2; exit 1; }

mkdir -p "$FW"

read -r CHIP FLASH_MODE FLASH_SIZE FLASH_FREQ < <(python3 - "$ARGS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
wf = d.get("write_flash_args", [])
def opt(name, default):
    return wf[wf.index(name) + 1] if name in wf else default
chip = d.get("extra_esptool_args", {}).get("chip", "esp32c5")
print(chip, opt("--flash_mode", "dio"), opt("--flash_size", "16MB"), opt("--flash_freq", "80m"))
PY
)

mapfile -t PARTS < <(python3 - "$ARGS" "$BUILD" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1])); build = sys.argv[2]
for off, f in d["flash_files"].items():
    print(off)
    print(os.path.join(build, f))
PY
)

MERGED="$FW/sniffcheck-merged.bin"
echo "merging: chip=$CHIP mode=$FLASH_MODE size=$FLASH_SIZE freq=$FLASH_FREQ"
esptool.py --chip "$CHIP" merge_bin \
  --flash_mode "$FLASH_MODE" --flash_size "$FLASH_SIZE" --flash_freq "$FLASH_FREQ" \
  -o "$MERGED" \
  "${PARTS[@]}" \
  "$EUI_OFFSET" "$EUI"

VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"

cat > "$OUT/manifest.json" <<EOF
{
  "name": "SniffCheck",
  "version": "$VERSION",
  "new_install_prompt_erase": true,
  "builds": [
    {
      "chipFamily": "ESP32-C5",
      "parts": [
        { "path": "firmware/sniffcheck-merged.bin", "offset": 0 }
      ]
    }
  ]
}
EOF

echo "merged:   $MERGED ($(du -h "$MERGED" | cut -f1))"
echo "manifest: $OUT/manifest.json (version $VERSION)"
