# SniffCheck Cluster (Dog Park)

The cluster turns several ESP32 boards into one cooperating Dog Park scanner: a set
of headless scanning **arms**, a **brain** that masters the bus and hosts the web app,
and an **S3 node** that owns the microSD archive and the flagged-signature sentinel.

Each role is a standalone ESP-IDF project built out-of-tree (the shared driver and
web-app sources live in the main firmware tree and are pulled in by relative path).

## Roles

| Role      | Board            | Target   | Job                                                         |
|-----------|------------------|----------|-------------------------------------------------------------|
| `brain`   | LilyGO T-Dongle-C5 | esp32c5 | I2C master of the Qwiic bus + SoftAP/WebAP host (PSRAM report) |
| `head-s3` | LilyGO T-Dongle-S3 | esp32s3 | I2C slave service node: microSD durable store + sentinel + LCD |
| `arm`     | ESP32-C5         | esp32c5  | Headless scanner; reports its scanset to the master over I2C |
| `master`  | ESP32-C5         | esp32c5  | Legacy single-head cluster master + WebAP host              |

`common/` holds the wire protocol (`cluster_proto`), the sentinel matcher, and the
shared pin map. Arms attach to the flat Qwiic bus (SDA/SCL) and are polled by whichever
role masters the bus.

## Build & flash

The build pulls shared sources from the sibling `main/`, `dogpark-node/`, and
`components/` trees, so build each role from its own directory into its own cache
(this repo lives on a filesystem that blocks in-tree symlinks):

```sh
# brain (esp32c5)
cd brain    && idf.py -B ~/.cache/cluster-brain-build --preview set-target esp32c5 build flash

# S3 node (esp32s3)
cd head-s3  && idf.py -B ~/.cache/head-s3-build set-target esp32s3 build flash

# arm (esp32c5) — ARM_INDEX selects the I2C address
cd arm      && idf.py -B ~/.cache/cluster-arm-build -DARM_INDEX=1 --preview set-target esp32c5 build flash
```

`flash_all.sh` wires the C5 roles (master, brain, two arms) together in one pass; the
S3 node is built separately because it targets esp32s3.

Pre-built images for all roles are on the web flasher (`docs/webflasher/`), including
merged one-shot images and app-only update images.
