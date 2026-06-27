# Credits and references

SniffCheck is licensed under the Apache License, Version 2.0 (see LICENSE).
Copyright 2026 Michael Pabst (@jLaHire).

This file lists the projects, datasets, standards, and research that inspired and
motivated SniffCheck. It is part of NOTICE by reference.

I wrote SniffCheck's own code from scratch. The firmware image also bundles two
small third-party libraries, both under the Apache License 2.0, listed under
"Bundled in the firmware" below. The web flasher also vendors one MIT library.
Everything else in the lists below gave no source code — those projects are here
because they inspired me, motivated a feature, or are planned interoperability
references.

Note on facts. Lists of facts such as IEEE OUI prefixes, Bluetooth company IDs,
and device name tokens are not copyrightable. Where SniffCheck uses such data it
still names the source that first surfaced it.

## Bundled in the firmware

* Open Drone ID Core C Library, by Intel and the Open Drone ID project
  contributors. Apache 2.0. Used for ASTM F3411 Remote ID decode.
  https://github.com/opendroneid/opendroneid-core-c
* esp_lcd ST7735 panel driver, by Espressif Systems. Apache 2.0. Drives the LCD.
  https://github.com/espressif/esp-bsp


## Dog Park X4 orchestrator firmware

The Dog Park X4 image (`firmware/dogpark-x4-c3.bin`) is a separate SniffCheck
firmware flavor for the Xteink X4 (ESP32-C3). Alongside SniffCheck's own code it
bundles or references:

* font8x8 by Daniel Hepper. Public domain (based on Marcel Sondaar / IBM
  public-domain VGA fonts). Bundled for e-ink text rendering.
  https://github.com/dhepper/font8x8
* SSD1677 e-ink command sequence, re-implemented from the controller datasheet
  and cross-checked against GxEPD2 by Jean-Marc Zingg. Hardware and protocol
  facts only; no source was copied. https://github.com/ZinggJM/GxEPD2
* Xteink X4 "open-x4" community SDK, used as the board pin-map reference.

## Bundled in the web flasher

* Adafruit WebSerial ESPTool (with ESP32-C5 support). MIT, Copyright Nabu Casa
  and Adafruit Industries. See esptool/LICENSE.md.
  https://github.com/adafruit/Adafruit_WebSerial_ESPTool

## Inspiration

* DeFlock and DeflockJoplin: https://github.com/DeflockJoplin/flock-you, https://deflock.me
* oui-spy-unified-blue by colonelpanichacks: https://github.com/colonelpanichacks/oui-spy-unified-blue
* flock-you by wgreenberg: https://github.com/wgreenberg/flock-you
* ESP32DualBandWardriver by justcallmekoko: https://github.com/justcallmekoko/ESP32DualBandWardriver
* ESP32Marauder by justcallmekoko: https://github.com/justcallmekoko/ESP32Marauder
* piglet by Hamspiced: https://github.com/Hamspiced/piglet
* Biscuit DIY: https://biscuitshop.us/products/biscuit-pro, https://github.com/CodeHedge/biscuit_flasher
* Biscuit (Xteink X4 firmware) by yattsu, with its CrossPoint-Reader upstream:
  the approach there inspired the Dog Park X4 orchestrator port to the Xteink X4.
  https://github.com/yattsu/biscuit, https://github.com/crosspoint-reader/crosspoint-reader

Creators whose videos inspired me to build SniffCheck:

* Valley Tech Solutions: https://www.youtube.com/@Valleytechsolutions
* Ghost Strats: https://www.youtube.com/@GhostStrats
* Techcifer: https://www.youtube.com/@techcifer

## Public data and standards

* Espressif ESP-IDF: https://github.com/espressif/esp-idf
* IEEE OUI registry: https://standards-oui.ieee.org/
* Bluetooth SIG Assigned Numbers: https://www.bluetooth.com/specifications/assigned-numbers/
* Apple Continuity identifiers, from community reverse engineering — primarily
  furiousMAC's Continuity corpus and Wireshark dissector
  (https://github.com/furiousMAC/continuity) and the Celosia/Cunche paper below.
* Google Fast Pair model IDs, from Google's public Fast Pair spec:
  https://developers.google.com/nearby/fast-pair
* Drone (UAS) manufacturer codes — ANSI/CTA-2063-A manufacturer code registry
  (administered by ICAO) and FAA Remote ID Declaration-of-Compliance lists.
* ASTM F3411 Remote ID: https://www.astm.org/f3411-22a.html
* FCC ID database: https://www.fcc.gov/oet/ea/fccid

### Dataset notices

This firmware contains a static snapshot of the Organizationally Unique
Identifier (OUI) dataset, utilized under compliance with the IEEE Registration
Authority. All copyrights to the underlying organization mappings belong to
their respective owners and the IEEE.

This firmware contains a static snapshot of the Bluetooth SIG Assigned Numbers
(company identifiers and service/characteristic UUIDs), utilized under
compliance with the Bluetooth Special Interest Group. All copyrights to the
underlying assignments belong to their respective owners and the Bluetooth SIG.
The Bluetooth® word mark and logos are registered trademarks owned by
Bluetooth SIG, Inc.

## Research

* Fenske, Brown, Martin, Mayberry, Ryan, Rye. "Three Years Later: A Study of MAC
  Address Randomization in Mobile Devices and When It Succeeds." PoPETs 2021. DOI
  10.2478/popets-2021-0042
* Celosia, Cunche. "Discontinued Privacy: Personal Data Leaks in Apple Bluetooth
  Low Energy Continuity Protocols." PoPETs 2020. DOI 10.2478/popets-2020-0003
* Mayberry, Fenske, Brown, Martin, Fossaceca, Rye, Teplov, Foppe. "Who Tracks the
  Trackers? Circumventing Apple's Anti Tracking Alerts in the Find My Network."
  WPES 2021. DOI 10.1145/3463676.3485616
* furiousMAC. "Reverse Engineering Apple's BLE Continuity Protocol." ShmooCon 2020.
  https://github.com/furiousMAC/continuity
* Wi-Fi security: IEEE 802.11i, IEEE 802.11-2020, Wi-Fi Alliance WPA3
* Bluetooth address types: Bluetooth Core Spec, Vol 6, Part B
* WiGLE CSV format: https://wigle.net
* Kismet log format: https://www.kismetwireless.net

## AI use

AI tools were used during prototyping, and to help with debugging and reading
ESP-IDF example code. The design, the decisions, and the final code are my own.
