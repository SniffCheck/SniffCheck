# Dog Park — User Guide

Dog Park is the multi-device (cluster) way to run SniffCheck. One **master** stick
runs the show and one or more **arm** sticks do the scanning. You control the whole
cluster from a web app in your browser — no app store, no account. The scan data
never leaves your local network.

Like the rest of SniffCheck, Dog Park only listens. It does not deauth, jam,
connect to, pair with, or attack anything nearby.

---

## What you need

- **1 master** board (ESP32-C5) running the Dog Park **master** firmware.
- **1 or more arm** boards (ESP32-C5) running the Dog Park **arm** firmware.
- **Any Wi-Fi router or access point.** This is the important part: it does **not**
  have to be a GL.iNet travel router. Anything that hands out a Wi-Fi LAN works:
  - a home/office router,
  - a travel router (GL.iNet or similar),
  - your **phone's hotspot**,
  - even **another ESP32** set up to run as an access point/router.

  The only requirement is that the master and your phone/laptop can join the
  **same** network so the browser can reach the master.
- **A phone or laptop** with a browser. For the live control panel, use
  **Chrome or Edge 142+** (desktop or Android). Other browsers still work in a
  reduced, file-based mode — see [Browser support](#browser-support).

You do **not** need the master and the arms to have internet. Only the phone/laptop
needs internet to load the web app the first time (after that it is installable and
opens offline).

---

## How it fits together

```text
[ arm C5 ] --\
              >-- Qwiic/I2C --> [ master C5 ] --Wi-Fi--> [ your router/AP ] <--Wi-Fi-- [ your phone ]
[ arm C5 ] --/                    sniffcheck.local                                     web app in browser
```

- The arms scan and hand their results to the master over the short Qwiic cable.
- The master joins **your** router and answers on the name **`sniffcheck.local`**.
- Your phone joins the **same** router and opens the web app. The app talks
  directly to the master over the LAN. Nothing about your scans goes to the
  internet.

---

## One-time setup

You only do this once per master (or after a factory reset).

### 1. Flash the boards

Open the SniffCheck web flasher on a **computer** (Web Serial is desktop-only):

> https://sniffcheck.github.io/SniffCheck/

Plug in each board over USB and flash it:

- the **master** board with the **Dog Park master** firmware,
- each **arm** board with the **Dog Park arm** firmware.

Wire the arms to the master with the Qwiic/I2C cable(s), then power everything on.

### 2. Tell the master which router to join

The very first time it boots, the master has no Wi-Fi credentials, so it puts up a
temporary **setup** Wi-Fi network and shows a QR code on its screen.

1. On your phone, scan the QR code (or join the master's setup Wi-Fi and open
   `http://192.168.4.1/provision`).
2. Enter the **name (SSID) and password of your router** — the same network your
   phone will use. This can be your home router, a travel router, a phone hotspot,
   or another ESP32 access point.
3. Save. The master stores the credentials, drops the setup network, and reboots.

No Wi-Fi passwords are ever built into the firmware — you type in your own, and they
stay on the device.

### 3. Confirm it joined

After it reboots, the master's screen shows **`sniffcheck.local`** and the IP address
your router gave it. That means it is on your network and ready.

If it can't join (wrong password, router out of range), it falls back to the setup
screen so you can try again — no reflashing needed.

---

## Everyday use at the park

1. **Power on** the master and arms.
2. On your phone, **join the same router/network** the master is on.
   - If that network has no internet of its own (for example a bare travel router or
     an ESP32 AP), keep your phone's **mobile data on** so the app can still load.
     Your phone can use Wi-Fi for the LAN and cellular for the internet at the same
     time.
3. Open the web app: **https://sniffcheck.github.io/SniffCheck/**
   (install it to your home screen once and it opens like an app).
4. Go to the **Dog Park** tab. The app finds the master at `sniffcheck.local`.
   - On Chrome/Edge 142+, the browser shows a one-time **"allow local network"**
     prompt. Tap allow. This is normal and only happens once.
   - If the name doesn't resolve on your network, type the master's **IP address**
     (shown on its screen) into the connection bar instead.
5. Use the controls:
   - **Rescan** — take a fresh scan of the area.
   - **Walk** — a longer moving capture while you walk the park.
   - **Live waterfall** — devices stream in as they're seen.
   - **GPS** — on a phone the app uses your real location (with your permission) and
     stamps records. Coordinates show as text with an **"open in maps"** link; no map
     is embedded and nothing is sent anywhere until you tap that link.

Everything you capture is also saved into an **on-phone archive**, so you can review
past walks later — offline, in any browser, with no device connected.

---

## The Viewer

The **Viewer** tab is the full analyzer. It reads from three places:

- the **live** device (Chrome/Edge 142+),
- your **on-phone archive** (any browser, offline),
- a **capture file** you drop in (`.jsonl`) — this works in **every** browser.

It gives you the RF summary, Wi-Fi/BLE/tracker/drone breakdowns, clusters,
notifications, a watchlist, and exports (JSON / CSV / WiGLE). Analysis is identical to
the standalone SniffCheck viewer.

---

## Browser support

| Browser | Live control panel | Flash tab | Fallback |
|---|---|---|---|
| Chrome / Edge 142+ **desktop** | Yes (allow-local-network prompt) | Yes | — |
| Chrome / Edge **Android** | Yes (allow-local-network prompt) | No (no Web Serial on phones) | Dog Park is the phone tab |
| **iOS / Safari** | No | No | Viewer file-drop only |
| **Firefox** | No | No | Viewer file-drop only |

So: **flash from a laptop, then use Dog Park on your phone at the park.** On a browser
without live support, you can still save a capture to a `.jsonl` file and open it in
the Viewer.

---

## Privacy

- **Scan data stays on your local network.** The browser talks straight to the master
  over the LAN. The website itself (hosted on GitHub Pages) only serves the app's
  HTML/JS — it never sees your captures.
- **No hard-coded Wi-Fi credentials.** You enter your own router details once; they
  live only on the device.
- **Location never leaves the device** until you explicitly tap an "open in maps"
  link, which hands off to your chosen maps app.

---

## Troubleshooting

- **App can't find the device.** Make sure the phone and the master are on the same
  network. Type the master's IP (from its screen) into the connection bar.
- **No "allow local network" prompt / it fails.** You need Chrome or Edge 142+.
  On other browsers, use the Viewer's file-drop mode.
- **Master keeps showing the setup screen.** The router name/password was wrong or the
  router was unreachable. Re-enter them via the setup QR.
- **Want to move to a different router.** Re-provision the master (factory reset or the
  re-provision option) and enter the new network's details.
- **Flash tab is greyed out.** You're on a phone or an unsupported browser. Flashing
  needs desktop Chrome/Edge over USB.
