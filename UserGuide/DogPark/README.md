# Dog Park user guide

Dog Park is the multi-board SniffCheck cluster. Several boards share one Qwiic/I2C bus so a pack of scanners covers more RF than a single dongle, and one board hosts a web app you open from your phone. Scan data stays on the cluster — no router and no internet are required.

Dog Park is listen-only. It does **not** deauth, jam, connect to, pair with, or attack nearby devices.

This guide replaces the older x4 / single-master orchestrator docs. Cluster roles today are **brain**, **arm**, and **S3 node** (the legacy `cluster/master` project is pre-Phase-115 and is no longer flashed).

Related docs in the repo root:

- [`DogPark.md`](../../DogPark.md) — short overview
- [`DogParkUserGuide.md`](../../DogParkUserGuide.md) — longer walkthrough
- [`DogParkClusterS3.md`](../../DogParkClusterS3.md) — brain + S3 architecture
- [`cluster/README.md`](../../cluster/README.md) — build, flash, arm pool details

---

## Firmware family

| Role | Board | ESP-IDF target | Prebuilt image (`firmware/`) | Job |
|------|-------|----------------|------------------------------|-----|
| **brain** | LilyGO T-Dongle-C5 | `esp32c5` | `sniffcheck-cluster-brain-merged.bin` | I2C bus master, aggregates/scores arm results, SoftAP + web app host (PSRAM live report) |
| **arm** | ESP32-C5 (T-Dongle-C5 works) | `esp32c5` | `sniffcheck-cluster-arm-merged.bin` | Headless Wi-Fi + BLE scanner; one image for every arm |
| **S3 node** | LilyGO T-Dongle-S3 | `esp32s3` | `sniffcheck-cluster-s3node-merged.bin` | microSD durable archive, sentinel watchlist, local LCD |
| *(legacy)* `master` | ESP32-C5 | `esp32c5` | — | Pre-Phase-115 single-head master; **not flashed any more** |

Source trees:

- `cluster/brain`, `cluster/arm`, `cluster/head-s3` — active roles
- `cluster/common` — wire protocol (`cluster_proto`), sentinel matcher, pin map
- `cluster/master` — legacy; `flash_all.sh` still lives here as the pack flasher helper
- Shared drivers / web UI are pulled from the main tree (`main/`, `dogpark-node/`, `components/`)

Standalone SniffCheck (`sniffcheck-merged.bin`) is a separate single-dongle firmware. A Dog Park board runs a cluster role instead.

### How the pack fits together

```text
[ arm C5 ] --\
              >-- Qwiic / I2C --> [ brain C5 ] --Wi-Fi SoftAP--> [ your phone ]
[ arm C5 ] --/                        |              http://192.168.4.1/
                                      +--> [ S3 node ] --> microSD + sentinel + LCD
```

- **Bus:** flat Qwiic I2C. Pins from `cluster/common/cluster_pins.h`: SDA GPIO 11, SCL GPIO 12, 100 kHz. Brain address `0x10`. S3 node fixed at `0x13`. Arms claim a free slot from the pool `{0x11, 0x12, 0x14, 0x15, 0x16, 0x17}` at boot and keep it in NVS.
- **Spectrum split:** the brain divides the channel union across arms that answer and re-divides when one joins or drops. One arm sweeps everything; two take half each; three take a third each.
- **Data flow:** arms report scansets each window → brain merges, de-duplicates, scores, updates place learning → pushes the merged verdict to the S3 node, which tees every record to microSD and runs the sentinel.
- **Web app:** only the brain talks to your phone. Arms and the S3 node stay on the wired bus.

---

## Install (flash)

### Option A — web flasher (easiest)

1. Open the flasher in **desktop Chrome or Edge**: https://sniffcheck.github.io/SniffCheck/ (or local `index.html`). Web Serial is required; Firefox, Safari, and phones cannot flash.
2. Pick, in order: **brand → device → firmware family → firmware**.
   - Brand: **LilyGo**
   - Device: **ESP32-C5** for brain/arm, **ESP32-S3** for the S3 node
   - Family: **Dog Park cluster**
   - Firmware: **brain**, **arm**, or **S3 node**
3. Plug in **one board at a time**, click Install, choose the serial port, wait.
4. The flasher checks chip id (C5 vs S3) against the picked image before writing, so a wrong pick is refused rather than bricked.
5. If the port is missing: unplug, hold **BOOT**, plug back in while holding, release, Install again.

Merged images under `firmware/` already include bootloader, partition table, app, and bundled data. The arm merged image includes the vendor/device-type database, so scanned devices resolve to real vendors with no extra flash step. SHA-256 sums are in `firmware/checksums.txt`.

### Option B — build and flash from source

Needs **ESP-IDF v5.5** (root README calls out v5.5.0) on your PATH.

Each role is its own out-of-tree project with its own build cache (this tree blocks in-tree symlinks):

```sh
# brain (esp32c5)
cd cluster/brain
idf.py -B ~/.cache/sc-brain-build --preview set-target esp32c5 build
idf.py -B ~/.cache/sc-brain-build -p PORT flash

# arm (esp32c5) — same image on every arm board
cd cluster/arm
idf.py -B ~/.cache/sc-cluster-arm-build --preview set-target esp32c5 build
idf.py -B ~/.cache/sc-cluster-arm-build -p PORT flash
# vendor DB is a separate partition — required or every device is "unknown"
python -m esptool --chip esp32c5 -p PORT --baud 460800 \
    write_flash --flash_size 16MB 0x310000 ../../data/eui.bin

# S3 node (esp32s3)
cd cluster/head-s3
idf.py -B ~/.cache/sc-s3-build set-target esp32s3 build
idf.py -B ~/.cache/sc-s3-build -p PORT flash
```

Pack helper (default ports `PORT_BRAIN=/dev/ttyACM0`, `PORT_ARM1=/dev/ttyACM1`, `PORT_ARM2=/dev/ttyACM2`, `PORT_S3=/dev/ttyACM3`):

```sh
cd cluster/master
./flash_all.sh build                 # build only
./flash_all.sh                       # build + flash brain, arm1, arm2, s3
ARMS="brain arm1 s3" ./flash_all.sh  # one-arm pack
./flash_all.sh monitor brain         # serial monitor on a role
```

`flash_all.sh` writes `data/eui.bin` to `0x310000` on every arm automatically.

---

## First boot and wiring

1. Wire every board on one shared I2C bus: **SDA, SCL, and GND common** (Qwiic works). Power all boards.
2. Insert a **FAT32** microSD card in the S3 node if you want durable history and the sentinel.
3. The brain brings up SoftAP and starts polling the arm pool; the S3 node mounts microSD.
4. Brain LCD shows host status and how many arms have linked. Arm screens show the spectrum share the brain assigned (e.g. `2.4+5 full/BLE` alone, or `2.4+5 1/2 BLE` / `2.4+5 2/2 BLE` in a two-arm pack).

---

## Use

1. On your phone or laptop, **join the brain's Wi-Fi access point**.
2. Open **`http://192.168.4.1/`** (also shown on the brain LCD / QR).
3. Live results stream as arms scan. Each row can show type (Wi-Fi AP, BLE, tracker, drone), vendor/name when resolved, signal, and last-seen time.
4. The browser accumulates results across a long session so you keep climbing past what the brain's memory alone holds. **Refresh** pulls the latest and briefly pauses/dims live cards so the board's few sockets are not contended.

### Controls (web app)

- **Adv rescan** — deeper Wi-Fi + BLE audit on every arm once.
- **Start walk / Stop walk** — continuous coordinated sweep (wardriving-style coverage as you move).
- **Flag** — add a device from a live result to the sentinel watchlist.

### Sentinel (S3 node)

Owned by the S3 node. Arm/disarm from the web app, add devices by MAC or name, review flagged hits with timestamps. The S3 LCD button cycles status / SD / Guard Dog pages and keeps working even if the brain is offline.

### Environments (place memory)

The brain learns places from **stable** Wi-Fi landmarks (not every transient broadcast). Mesh/multi-SSID boxes count once per physical router; carrier hotspots and gear you carry are down-weighted. In **Environments** you can inspect landmarks, pin/remove them, rename or forget a place, or run **Learn this place** (several scans; optional pause between them so fixtures separate from passers-by). Place memory lives on the brain and survives reboot until a full erase or a new firmware flash.

### microSD record store

Full session history lives on the S3 node's card. Brain RAM and the browser are the live/working views; the card is the durable log.

---

## Troubleshoot

| Symptom | What to try |
|---------|-------------|
| Board not found in web flasher | Desktop Chrome/Edge only. Unplug, hold **BOOT**, replug while holding, release, Install again. |
| Wrong image / refused flash | Flasher matches chip (C5 vs S3) to the selected role — pick the matching firmware. |
| Web app won't load | Join the **brain** SoftAP, then open `http://192.168.4.1/`. Refresh if a control feels stuck. |
| Arm doesn't link | Check shared SDA/SCL/GND, power, and that the board runs **arm** firmware. Brain LCD shows linked arm count. |
| Two arms on one I2C slot | Brain detects duplicate identity on one address and tells that address to re-claim; both boards pick fresh pool slots. |
| All devices "unknown" vendor/class | Arm vendor DB partition empty. Web-flasher arm image includes it; from source flash `data/eui.bin` → `0x310000` (or use `flash_all.sh`). |
| S3 node has no history | FAT32 microSD seated; confirm S3 node firmware (not brain/arm). |
| Build fails / missing sources | Build each role from its own `cluster/<role>` dir with `-B` out-of-tree cache; shared code is pulled from sibling `main/`, `dogpark-node/`, `components/`. |
| `cluster/master` image confusion | Do not flash legacy master. Brain is the I2C master and WebAP host now. |

---

## Limits (honest)

- **Listen-only** — observes RF others already broadcast or leak; never forces a response.
- **Local bus, not a mesh** — arms/brain/S3 coordinate over wired I2C only.
- **Identity is a guess** — vendor, device type, and place recognition are confidence-based estimates, not proof.
- **Still early** — feature set and caps (including per-arm result walls) still move; see open issues for current numbers.

---

## Privacy

- Scan data stays on the cluster. The browser talks only to the brain SoftAP.
- No hard-coded router credentials: the brain hosts its own AP.
- Location does not leave the device until you explicitly open a maps link.