#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

py=tools/img2rgb565.py
img=images/newImages

python3 "$py" "$img/Logo01.PNG" main/sniffcheck_logo_1.h  sniffcheck_logo_1  160x80 --trim
python3 "$py" "$img/Logo02.PNG" main/sniffcheck_logo_2.h  sniffcheck_logo_2  160x80 --trim
python3 "$py" "$img/Logo03.PNG" main/sniffcheck_logo_3.h  sniffcheck_logo_3  160x80 --trim
python3 "$py" "$img/Logo04.PNG" main/sniffcheck_logo_4.h  sniffcheck_logo_4  160x80 --trim
python3 "$py" "$img/Logo05.PNG" main/sniffcheck_logo_5.h  sniffcheck_logo_5  160x80 --trim
python3 "$py" "$img/Logo06.PNG" main/sniffcheck_logo_6.h  sniffcheck_logo_6  160x80 --trim
python3 "$py" "$img/Logo07.PNG" main/sniffcheck_logo_7.h  sniffcheck_logo_7  160x80 --trim
python3 "$py" "$img/Logo08.PNG" main/sniffcheck_logo_8.h  sniffcheck_logo_8  160x80 --trim
python3 "$py" "$img/Logo09.PNG" main/sniffcheck_logo_9.h  sniffcheck_logo_9  160x80 --trim
python3 "$py" "$img/Logo10.PNG" main/sniffcheck_logo_10.h sniffcheck_logo_10 160x80 --trim

python3 "$py" "$img/Standing01.PNG" main/sniffcheck_standing.h sniffcheck_standing 60x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_sitting.h  sniffcheck_sitting  60x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_safe.h     sniffcheck_safe     18x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_ok.h       sniffcheck_ok       18x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_caution.h  sniffcheck_caution  18x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_avoid.h    sniffcheck_avoid    18x20 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_safe_lg.h    sniffcheck_safe_lg    35x40 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_ok_lg.h      sniffcheck_ok_lg      35x40 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_caution_lg.h sniffcheck_caution_lg 35x40 --trim
python3 "$py" "$img/Sitting01.PNG"  main/sniffcheck_avoid_lg.h   sniffcheck_avoid_lg   35x40 --trim

python3 "$py" "$img/Sniffing01.PNG" main/sniffcheck_sniff_r1.h sniffcheck_sniff_r1 100x36 --trim
python3 "$py" "$img/Sniffing02.PNG" main/sniffcheck_sniff_r2.h sniffcheck_sniff_r2 100x36 --trim
python3 "$py" "$img/Sniffing03.PNG" main/sniffcheck_sniff_l1.h sniffcheck_sniff_l1 100x36 --trim
python3 "$py" "$img/Sniffing04.PNG" main/sniffcheck_sniff_l2.h sniffcheck_sniff_l2 100x36 --trim

python3 "$py" "$img/Dig01.PNG" main/sniffcheck_dig_1.h SNIFFCHECK_DIG_1 120x36 --trim
python3 "$py" "$img/Dig02.PNG" main/sniffcheck_dig_2.h SNIFFCHECK_DIG_2 120x36 --trim
python3 "$py" "$img/Dig03.PNG" main/sniffcheck_dig_3.h SNIFFCHECK_DIG_3 120x36 --trim

im=${MAGICK:-$(command -v magick || command -v convert)}
if [[ -z "$im" ]]; then
    echo "ImageMagick not found (need magick or convert on PATH)" >&2
    exit 1
fi
"$im" "$img/Logo10.PNG" -fuzz 15% -trim +repage -background none \
    -filter Lanczos -resize 284x96 -gravity center -extent 284x96 \
    main/webap_logo.png
"$im" "$img/Logo10.PNG" -fuzz 15% -trim +repage -background none \
    -filter Lanczos -resize 64x64 -gravity center -extent 64x64 \
    main/webap_favicon.png
"$im" "$img/Sitting01.PNG" -fuzz 15% -trim +repage -background none \
    -filter Lanczos -resize x140 \
    main/webap_pup.png

echo "assets regenerated."
