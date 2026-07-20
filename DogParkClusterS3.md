# Dog Park Cluster — Brain + S3 Node

This is the larger Dog Park cluster layout: instead of a single master stick doing
everything, the work is split across three kinds of board. It is still the same
listen-only SniffCheck — nothing here deauths, jams, connects to, pairs with, or
attacks anything nearby.

- A **brain** (LilyGO T-Dongle-C5) masters the Qwiic/I2C bus, aggregates and scores
  what the arms find, and hosts the web app. It has PSRAM, so the live report lives on
  the brain.
- An **S3 node** (LilyGO T-Dongle-S3) is a service node hanging off the same bus. It
  owns the microSD card (the uncapped durable archive of every record) and runs the
  flagged-signature **sentinel**, and it shows status on its small LCD.
- One or more **arms** (ESP32-C5) scan headless and hand their scansets to the brain.

The brain is the only board your phone talks to; the S3 node and the arms never touch
Wi-Fi as a server — they sit on the wired I2C bus.

---

## What you need

- **1 brain** board (ESP32-C5) running the Dog Park **brain** firmware.
- **1 S3 node** board (ESP32-S3, e.g. T-Dongle-S3) running the **S3 node** firmware,
  with a FAT32-formatted microSD card inserted.
- **1 or more arm** boards (ESP32-C5) running the Dog Park **arm** firmware.
- **A phone or laptop** with a browser to open the brain's web app.

The boards are wired together on a shared Qwiic/I2C bus. The brain brings up its own
Wi-Fi access point, so no external router is required for the cluster itself.

---

## How it fits together

```text
[ arm C5 ] --\
              >-- Qwiic / I2C --> [ brain C5 ] --Wi-Fi (SoftAP)--> [ your phone ]
[ arm C5 ] --/                        |
                                      +--> [ S3 node ] --> microSD archive + sentinel + LCD
```

- **Bus:** flat Qwiic I2C, SDA/SCL shared by every board. The brain is the bus master;
  the arms and the S3 node are slaves at fixed addresses (the S3 node at `0x13`).
- **Data flow:** each window the arms report their scansets to the brain; the brain
  merges and de-duplicates them, scores the result, updates the on-device learning
  model, and pushes the merged verdict down to the S3 node, which tees every record to
  the microSD and runs the sentinel over it.
- **Web app:** served by the brain over its access point. It shows the live results,
  the learning summary, the arm/health status, and the sentinel watchlist. Results
  accumulate in the browser so nothing is lost if the brain's memory fills.

---

## Flashing

Use the [web flasher](./index.html) and pick the matching firmware for each board:

- **Dog Park cluster — brain (ESP32-C5)**
- **Dog Park cluster — S3 node (ESP32-S3)**
- **Dog Park cluster — arm (ESP32-C5)** — one per arm

Plug in one board at a time, choose its firmware, and click Install. The flasher checks
that the firmware matches the chip (C5 vs S3) before writing, so a wrong pick is
refused rather than bricked. If a board isn't detected, hold **BOOT** while replugging
to force download mode.

To build from source instead, see [`cluster/README.md`](./cluster/README.md).

---

## Using it

1. Power the brain, the S3 node, and the arms on the shared bus.
2. Join the brain's Wi-Fi access point from your phone and open the web app.
3. Watch results stream in as the arms scan. Use the controls to start a walk or run a
   deeper rescan; flag devices into the sentinel watchlist from any live result.
4. The full record history is always on the S3 node's microSD, independent of what the
   browser or the brain's memory is holding.
