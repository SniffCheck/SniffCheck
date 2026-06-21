# SniffCheck

A USB stick that helps you decide whether nearby Wi-Fi and Bluetooth activity looks safe.

Plug it in, read the screen, and decide whether to connect your phone to a nearby network. No app, no account, and nothing leaves the device.

This repo is a public demo of SniffCheck.

## Note from the author

SniffCheck started as a quick way to do an RF check before connecting to Wi-Fi at places like coffee shops. It lived as a Python script on my Lenovo for months before I started thinking about putting it on a microcontroller.

Up front: there will be no crowdfunding. At some point, I plan to make a self-funded custom PCB, and I may try to sell that hardware, but the source code will stay available for anyone who wants to build it themselves.

Right now, this is just a demo. Some parts were built with help from friends and AI along the way. Shout out to DCS, Dead Coder Society. Check it out, open issues if you find problems or have questions, and take a look at the credits. Hopefully this turns into something cool.

## Flash it from your browser

Open the GitHub Pages site for this repo, or open `index.html` from this folder in Chrome or Edge on a desktop.

1. Plug a LilyGO T-Dongle C5 into a USB port.
2. Click Install.
3. Pick the serial port and wait.

No toolchain, no Python, and no drivers are needed.

Web Serial is required, so Firefox, Safari, and phones cannot flash the device.

If the dongle is not found, unplug it, hold the BOOT button, plug it back in while still holding BOOT, then release the button and click Install again.

The image at `firmware/sniffcheck-merged.bin` is one merged build. It includes the bootloader, partition table, firmware, and vendor database, so the dongle works on first boot.

## What it does

SniffCheck listens to nearby Wi-Fi and Bluetooth activity, scores what it sees, and shows a verdict on its screen.

It only listens. It does not connect to networks, transmit at other devices, or send data anywhere.

If SniffCheck marks a network as safe, you can choose to connect your phone to that SSID. If everything looks risky, use cellular.

## Roadmap notes

There is a planned feature called Dog Park that will connect multiple SniffCheck devices together. Another planned feature, Guard Dog, will build on that idea.

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

For now, this is the only board SniffCheck supports. As I keep prototyping, I plan to work toward a custom PCB that people can order and build themselves.

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

AI tools were used during prototyping, debugging, and reading ESP-IDF example code. The design and final code are the author's own.

## License

Apache 2.0. See `LICENSE`.

Copyright 2026 Michael Pabst (@jLaHire).

The projects and sources that inspired SniffCheck are listed in `CREDITS.md`, which is part of `NOTICE`.

No source code was copied from those projects. Web flashing uses esp-web-tools.
