// SniffCheck web flasher glue.
//
// Drives the vendored Adafruit/CodeHedge WebSerial ESPTool engine
// (esptool/index.js), which flashes the ESP32-C5 and ESP32-C3 boards without the
// esptool-js stub path that times out in esp-web-tools 10.2.1
// (see esphome/esp-web-tools#687).
//
// Each firmware is one merged image (bootloader + partition table + app + data)
// flashed at offset 0x0. The user picks a firmware, plugs in the matching board,
// and clicks Install; the chip is checked against the picked firmware first.

import { connect } from "./esptool/index.js";

// id -> { label, image path, chip-name gate regex, human chip name, flash offset }.
const TARGETS = {
  "sniffcheck-c5": {
    label: "SniffCheck (T-Dongle C5)",
    url: "firmware/sniffcheck-merged.bin",
    chip: /c5/i, chipName: "ESP32-C5", offset: 0x0,
  },
  "node-c5": {
    label: "SniffCheck Node (ESP32-C5)",
    url: "firmware/sniffcheck-node-c5.bin",
    chip: /c5/i, chipName: "ESP32-C5", offset: 0x0,
  },
  "dogpark-x4": {
    label: "Dog Park X4 orchestrator (Xteink X4, ESP32-C3)",
    url: "firmware/dogpark-x4-c3.bin",
    chip: /c3/i, chipName: "ESP32-C3", offset: 0x0,
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

    stub = await esploader.runStub();

    log("Erasing flash…");
    await stub.eraseFlash();

    log("Downloading firmware…");
    const buf = await fetch(target.url).then((r) => {
      if (!r.ok) throw new Error(`firmware fetch failed: ${r.status}`);
      return r.arrayBuffer();
    });
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
