# SniffCheck
```text
Disclaimer: This project has nothing in it that hasn't been done before. There are tons of amazing developers out there who have innovated and broke ground in this space well before the idea of SniffCheck was inspired. There was a good amount of AI use in the development of this project and that's not for everyone, please go and support the projects listed in CREDITS.md, they've got great communities around them and really are the ones making a difference in educating the normies on RF awareness. SniffCheck is just our twist and we like it and have learned a ton making it. The goal isn't to steal credit or pretend to be a developer. When I decided to take `B4YC` from being a python program to being a firmware on a microcontroller I reached out to some buddies and used the tools I had to help me make that idea a reality.
```
A USB stick that helps you understand whether nearby Wi-Fi and Bluetooth activity seems safe.

Plug it in, read the screen, and decide whether to connect your phone to a nearby network. No app, no account, and nothing leaves the device. There is a Wigle integration(very minimal, barely enhances the results of a scan) and we were trying to work on WDGwars integration but moved on from that for the moment. There is still some stale references in the webui that will be cleaned up eventually. 

## Note from the author

SniffCheck started as a quick way to do an RF check before connecting to Wi-Fi at places like coffee shops. It lived as a Python script on my Lenovo for months before I started thinking about putting it on a microcontroller.

Up front: there will be no crowdfunding. At some point, I plan to make a self-funded custom PCB, and I will be open sourcing the pcb files once they're done(easyeda is kicking my butt), this project will always be open source.

Some parts of SniffCheck were built with help from friends and AI along the way. Shout out to DCS, Dead Coder Society. Open issues if you find problems or have questions, and take a look at the [Credits](CREDITS.md). The devs listed there are the GOATS of the RF microcontroller world who inspired this project through their work.

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

## Build it yourself

If you would rather build it than flash the prebuilt image, the T-Dongle C5 firmware source is in this repo. You need ESP-IDF v5.5.0 and an ESP32-C5 target.

```
. $IDF_PATH/export.sh
idf.py set-target esp32c5
idf.py build
idf.py -p PORT flash monitor
```

The vendor database lives in its own flash partition and is not part of the app build, so flash it once:

```
esptool.py -p PORT write_flash 0x310000 data/eui.bin
```

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

THIS IS CURRENTLY BEING WORKED ON. Fingers crossed :D

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
2. Let it boot and scan on its own.
3. Read the verdict at the top of the screen.
4. Press the BOOT button to move around:
       After booting
   * One click: Results
   * Two clicks: Settings
   * Hold about 1.5 seconds: Rescan
   From there everything is 1, 2, or hold. Some splashes don't have room for all 3 options so if you don't see hold as an option its because I ran out of room on the screen, it still likely takes you to the previous or main splash. 

5. Connect your phone to an SSID only if SniffCheck marks it safe.

SniffCheck has two modes: Lite and Adv.

Lite mode is the original idea: a standalone RF audit tool that does not need an app or phone. Advanced mode has more features. If you want to try the more interactive parts of the demo, open Settings, look for the Launch AP option, and use the QR codes to connect your phone. The pathing is still being worked on so it's a little bit of a maze.

## Updating

There is no over the air update by design.

SniffCheck does not phone home. To update it, flash it again.

## AI use

AI tools were used during prototyping, debugging, and reading ESP-IDF example code, as well as assisting in learning how to write firmware. The design is the author's own.

## License

Apache 2.0. See `LICENSE`.

Copyright 2026 Michael Pabst (@jLaHire).

The projects and sources that inspired SniffCheck are listed in `CREDITS.md`, which is part of `NOTICE`.

No source code was copied from those projects. Web flashing uses esp-web-tools.
