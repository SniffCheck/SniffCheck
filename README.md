# SniffCheck

A USB stick that helps you decide whether nearby Wi-Fi and Bluetooth activity looks safe.

Plug it in, read the screen, and decide whether to connect your phone to a nearby network. No app, no account, and nothing leaves the device.

This repo is a public demo of SniffCheck.

## Note from the author

SniffCheck started as a quick way to do an RF check before connecting to Wi-Fi at places like coffee shops. It lived as a Python script on my Lenovo for months before I started thinking about putting it on a microcontroller.

Up front: there will be no crowdfunding. At some point, I plan to make a self-funded custom PCB, and I may try to sell that hardware, but the source code will stay available for anyone who wants to build it themselves.

Right now, this is just a demo. Some parts were built with help from friends and AI along the way. Shout out to DCS, Dead Coder Society. Check it out, open issues if you find problems or have questions, and take a look at the credits. Hopefully this turns into something cool.

## Pertinent Files

[Credits & References](https://github.com/SniffCheck/SniffCheck/blob/main/CREDITS.md)
[NOTICE](https://github.com/SniffCheck/SniffCheck/blob/main/NOTICE)
[UserGuide](https://github.com/SniffCheck/SniffCheck/blob/main/UserGuide.md)

## Flash it from your browser

Open the web flasher: https://sniffcheck.github.io/SniffCheck/ or open `index.html` from this folder in Chrome or Edge on a desktop.

1. Pick a firmware (SniffCheck, SniffCheck Node, or Dog Park X4 orchestrator).
2. Plug the matching board into a USB port.
3. Click Install, pick the serial port, and wait.

No toolchain, no Python, and no drivers are needed.

Web Serial is required, so Firefox, Safari, and phones cannot flash the device.

If the dongle is not found, unplug it, hold the BOOT button, plug it back in while still holding BOOT, then release the button and click Install again.

Each image under `firmware/` is one merged build (bootloader, partition table, firmware, and any bundled data), so the board works on first boot:

* `sniffcheck-merged.bin` — SniffCheck, the standalone RF audit tool (T-Dongle C5).
* `sniffcheck-node-c5.bin` — SniffCheck Node, a scanner that reports to a Dog Park orchestrator (ESP32-C5).
* `dogpark-x4-c3.bin` — Dog Park X4 orchestrator with the e-ink UI (Xteink X4, ESP32-C3).

`firmware/checksums.txt` lists the SHA-256 of each image.

## What it does

SniffCheck listens to nearby Wi-Fi and Bluetooth activity, scores what it sees, and shows a verdict on its screen.

It only listens. It does not connect to networks, transmit at other devices, or send data anywhere.

If SniffCheck marks a network as safe, you can choose to connect your phone to that SSID. If everything looks risky, use cellular.

## Roadmap notes

Dog Park connects multiple SniffCheck devices into one coordinated session. An orchestrator (the Dog Park X4, running on an Xteink X4 e-ink device) admits scanner nodes, assigns them Wi-Fi channels for coordinated wardriving (Walk mode), and can put them into perimeter watch (Guard Dog mode). The orchestrator and node firmwares are in the web flasher now.

This is still a demo. It is not a final product. The hardware is bulky, the artwork is still rough, and the feature set is still changing.

I have been using the LilyGO T-Dongle C5 for firmware prototyping and debugging, but I plan to make a custom PCB later. I have also had a few friends review and discuss nearly every idea along the way. They will be listed as contributors and invited as collaborators on the repo.

## ePup

SniffCheck has the beginnings of an ePup mascot. Everything in the project is dog centered.

The current avatar is modeled after my yellow lab, Suz. Eventually, there may be a larger ePup ecosystem, but for now it is mostly cosmetic.

## Hardware

SniffCheck currently runs on the LilyGO T-Dongle C5.

Hardware details:

* ESP32-C5HR8
* 16 MB flash
* 8 MB PSRAM
* Dual-band Wi-Fi 6
* BLE 6.0
* ST7735 LCD
* Single pixel APA102 LED
* microSD slot
* USB-A

Product page: https://lilygo.cc/en-us/products/t-dongle-c5

The Dog Park firmwares run on two more boards:

* **SniffCheck Node** — any ESP32-C5 board (the T-Dongle C5 works); a headless scanner that reports to an orchestrator.
* **Dog Park X4 orchestrator** — the Xteink X4 (ESP32-C3, 4.26" 800x480 e-ink, 7 buttons, microSD). It runs the session UI, channel scheduler, and SD/WiGLE export.

As I keep prototyping, I plan to work toward a custom PCB that people can order and build themselves.

## Using the device

1. Plug SniffCheck into any USB power source.
2. The T-Dongle C5 boots through the logo and author splashes, starts in Adv mode, and runs a scan automatically.
3. Read the verdict on the environment summary splash.
4. Use the BOOT button to move around:
   * One click (`[1]`): open the Main menu from the summary, or move to the next row/item in selector screens.
   * Two quick clicks (`[2]`): open the highlighted item, or open Pup from the summary.
   * Hold for about 1.5 seconds (`[hold]`): rescan from the summary, or go back from most menus.

The Main menu is a `>` selector with **Results**, **Settings**, and **Rescan**.
Results opens the current Lite or Adv result panes. Settings includes Mode and,
in Adv mode, Launch AP.

Some splashes do not have room to show the buttons. When a one is missing,
`[hold]` still always backs out to the previous splash.

Connect your phone to an SSID only if SniffCheck marks it safe.  *<- just joking this isn't a end all be all RF Audit but hopefully this helps people understand the environment around them and make safe RF decisions*

SniffCheck has two modes: Lite and Adv.

Lite mode is the original idea: a standalone RF audit tool that doesnt need a
app or phone. Adv mode adds deeper Wi-Fi, BLE, probe, report, export, capture,
and surfaces the webAP. For more indepth guide check out ['UserGuide.md'](UserGuide.md)

## Updating

There is no over the air update by design.

SniffCheck does not phone home. To update it, flash it again.

## AI use

AI tools were used during prototyping, debugging, and reading ESP-IDF example code. The design and final code are the author's own.

## License

Apache 2.0. See `LICENSE`.

Copyright 2026 Michael Pabst (@jLaHire).

The projects and sources that inspired SniffCheck are listed in `CREDITS.md`, which is part of `NOTICE`.

No source code was copied from those projects. Web flashing uses esp-web-tools.
