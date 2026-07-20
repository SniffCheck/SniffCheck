// SniffCheck web flasher glue.
//
// Drives the vendored Adafruit/CodeHedge WebSerial ESPTool engine
// (esptool/index.js), which flashes the ESP32-C5 board without the
// esptool-js stub path that times out in esp-web-tools 10.2.1
// (see esphome/esp-web-tools#687).
//
// Each firmware is one merged image (bootloader + partition table + app + data)
// flashed at offset 0x0. The user picks a firmware, plugs in the matching board,
// and clicks Install; the chip is checked against the picked firmware first.

import { connect } from "./esptool/index.js";

// id -> firmware metadata used for chip gating and pre-erase image validation.
const TARGETS = {
  "sniffcheck-c5": {
    label: "SniffCheck (T-Dongle C5)",
    url: "firmware/sniffcheck-merged.bin",
    chip: /c5/i,
    chipName: "ESP32-C5",
    imageChipId: 23,
    bootloaderOffset: 0x2000,
    appOffset: 0x10000,
    offset: 0x0,
  },
  "node-c5": {
    label: "SniffCheck Node (ESP32-C5)",
    url: "firmware/sniffcheck-node-c5.bin",
    chip: /c5/i,
    chipName: "ESP32-C5",
    imageChipId: 23,
    bootloaderOffset: 0x2000,
    appOffset: 0x10000,
    offset: 0x0,
  },
  "cluster-master": {
    label: "Dog Park cluster — master (ESP32-C5)",
    url: "firmware/sniffcheck-cluster-master-merged.bin",
    chip: /c5/i,
    chipName: "ESP32-C5",
    imageChipId: 23,
    bootloaderOffset: 0x2000,
    appOffset: 0x10000,
    offset: 0x0,
  },
  "cluster-arm": {
    label: "Dog Park cluster — arm (ESP32-C5)",
    url: "firmware/sniffcheck-cluster-arm-merged.bin",
    chip: /c5/i,
    chipName: "ESP32-C5",
    imageChipId: 23,
    bootloaderOffset: 0x2000,
    appOffset: 0x10000,
    offset: 0x0,
  },
  "cluster-brain": {
    label: "Dog Park cluster — brain (ESP32-C5)",
    url: "firmware/sniffcheck-cluster-brain-merged.bin",
    chip: /c5/i,
    chipName: "ESP32-C5",
    imageChipId: 23,
    bootloaderOffset: 0x2000,
    appOffset: 0x10000,
    offset: 0x0,
  },
  "cluster-s3node": {
    label: "Dog Park cluster — S3 node (ESP32-S3)",
    url: "firmware/sniffcheck-cluster-s3node-merged.bin",
    chip: /s3/i,
    chipName: "ESP32-S3",
    imageChipId: 9,
    bootloaderOffset: 0x0,
    appOffset: 0x10000,
    offset: 0x0,
  },
};
const DEFAULT_TARGET = "sniffcheck-c5";

const installBtn = document.getElementById("install");
const targetSel = document.getElementById("target");
const logEl = document.getElementById("log");
const barEl = document.getElementById("bar");
const barFill = document.getElementById("barfill");

function log(line) {
  logEl.style.display = "block";
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

function setProgress(done, total) {
  barEl.style.display = "block";
  const pct = total ? Math.min((done / total) * 100, 100) : 0;
  barFill.style.width = pct.toFixed(1) + "%";
}

function formatMac(mac) {
  return mac.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(":");
}

function currentTarget() {
  return TARGETS[targetSel && targetSel.value] || TARGETS[DEFAULT_TARGET];
}

function validateImageHeader(firmware, offset, expectedChipId, description) {
  const headerLength = 24;
  if (firmware.length < offset + headerLength) {
    throw new Error(`Downloaded firmware is truncated before the ${description} header.`);
  }

  if (firmware[offset] !== 0xE9) {
    throw new Error(
      `Downloaded firmware does not contain a valid ESP image at 0x${offset.toString(16)}.`
    );
  }

  const segmentCount = firmware[offset + 1];
  if (segmentCount < 1 || segmentCount > 16) {
    throw new Error(`Downloaded firmware has an invalid ${description} segment count.`);
  }

  const imageChipId = firmware[offset + 12] | (firmware[offset + 13] << 8);
  if (imageChipId !== expectedChipId) {
    throw new Error(
      `Downloaded firmware is for chip ID ${imageChipId}, expected ${expectedChipId}.`
    );
  }
}

function validateFirmware(buf, target) {
  const firmware = new Uint8Array(buf);

  validateImageHeader(
    firmware,
    target.bootloaderOffset,
    target.imageChipId,
    "bootloader"
  );

  const partitionOffset = 0x8000;
  if (
    firmware.length < partitionOffset + 2 ||
    firmware[partitionOffset] !== 0xAA ||
    firmware[partitionOffset + 1] !== 0x50
  ) {
    throw new Error("Downloaded firmware does not contain a valid partition table at 0x8000.");
  }

  validateImageHeader(
    firmware,
    target.appOffset,
    target.imageChipId,
    "application"
  );
}

// Web Serial gate.
if (!("serial" in navigator)) {
  installBtn.disabled = true;
  const u = document.getElementById("unsupported");
  if (u) u.style.display = "block";
}

let busy = false;

installBtn.addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  installBtn.disabled = true;
  if (targetSel) targetSel.disabled = true;
  logEl.textContent = "";
  barFill.style.width = "0";

  const target = currentTarget();

  let esploader;
  let stub;
  try {
    esploader = await connect({ log, debug: () => {}, error: log });
    await esploader.initialize();
    log(`Selected firmware: ${target.label}`);
    log(`Connected to ${esploader.chipName}`);
    log(`MAC: ${formatMac(esploader.macAddr())}`);

    if (esploader.chipName && !target.chip.test(esploader.chipName)) {
      log(`WARNING: this firmware needs an ${target.chipName}, got ${esploader.chipName}. Aborting.`);
      throw new Error(`Wrong chip — "${target.label}" is for the ${target.chipName}.`);
    }

    log("Downloading firmware…");
    const response = await fetch(target.url);
    if (!response.ok) {
      throw new Error(`firmware fetch failed: ${response.status}`);
    }

    const buf = await response.arrayBuffer();
    validateFirmware(buf, target);
    log("Firmware image structure validated.");

    stub = await esploader.runStub();

    log("Erasing flash…");
    await stub.eraseFlash();

    log(`Writing ${(buf.byteLength / 1048576).toFixed(2)} MB at 0x0…`);

    await stub.flashData(buf, (written) => setProgress(written, buf.byteLength), target.offset);
    setProgress(1, 1);

    log("Done. Unplug and replug the board to start it.");
  } catch (err) {
    log(`ERROR: ${err.message || err}`);
    log("Try: unplug, hold BOOT, replug while holding, release, then Install again.");
  } finally {
    // Release the port so a retry can reopen it cleanly.
    try {
      if (stub) {
        await stub.disconnect();
        await stub.port.close();
      } else if (esploader) {
        await esploader.disconnect();
      }
    } catch (_) { /* ignore close races */ }
    installBtn.disabled = !("serial" in navigator);
    if (targetSel) targetSel.disabled = false;
    busy = false;
  }
});
