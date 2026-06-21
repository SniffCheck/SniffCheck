// SniffCheck web flasher glue.
//
// Drives the vendored Adafruit/CodeHedge WebSerial ESPTool engine
// (esptool/index.js), which flashes the ESP32-C5 without the esptool-js stub
// path that times out in esp-web-tools 10.2.1 (see esphome/esp-web-tools#687).
//
// The firmware is one merged image (bootloader + partition table + app + vendor
// DB) produced by tools/make-webflasher.sh and flashed at offset 0x0.

import { connect } from "./esptool/index.js";

const FIRMWARE_URL = "firmware/sniffcheck-merged.bin";
const FLASH_OFFSET = 0x0;

const installBtn = document.getElementById("install");
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

// Web Serial gate — match the message shown by the old esp-web-tools page.
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
  logEl.textContent = "";
  barFill.style.width = "0";

  let esploader;
  let stub;
  try {
    esploader = await connect({ log, debug: () => {}, error: log });
    await esploader.initialize();
    log(`Connected to ${esploader.chipName}`);
    log(`MAC: ${formatMac(esploader.macAddr())}`);

    if (esploader.chipName && !/c5/i.test(esploader.chipName)) {
      log(`WARNING: expected an ESP32-C5, got ${esploader.chipName}. Aborting.`);
      throw new Error("Wrong chip — this image is for the ESP32-C5 only.");
    }

    stub = await esploader.runStub();

    log("Erasing flash…");
    await stub.eraseFlash();

    log("Downloading firmware…");
    const buf = await fetch(FIRMWARE_URL).then((r) => {
      if (!r.ok) throw new Error(`firmware fetch failed: ${r.status}`);
      return r.arrayBuffer();
    });
    log(`Writing ${(buf.byteLength / 1048576).toFixed(2)} MB at 0x0…`);

    await stub.flashData(buf, (written) => setProgress(written, buf.byteLength), FLASH_OFFSET);
    setProgress(1, 1);

    log("Done. Unplug and replug the dongle to start SniffCheck.");
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
    busy = false;
  }
});
