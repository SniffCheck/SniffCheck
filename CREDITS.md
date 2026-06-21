# Credits and references

SniffCheck is licensed under the Apache License, Version 2.0 (see LICENSE).

This file lists the projects, datasets, standards, and research that inspired and
motivated SniffCheck. It is part of NOTICE by reference.

None of the projects below gave source code to SniffCheck. Nothing was copied.
They are listed because they inspired the me or motivated a feature. All of
the code was written from scratch.

Note on facts. Lists of facts such as IEEE OUI prefixes, Bluetooth company IDs,
and device name tokens are not copyrightable. Where SniffCheck uses such data it
still names the source that first surfaced it.

## Inspiration

* DeFlock and DeflockJoplin: https://github.com/DeflockJoplin/flock-you, https://deflock.me
* oui-spy-unified-blue by colonelpanichacks: https://github.com/colonelpanichacks/oui-spy-unified-blue
* flock-you by wgreenberg: https://github.com/wgreenberg/flock-you
* ESP32DualBandWardriver by justcallmekoko: https://github.com/justcallmekoko/ESP32DualBandWardriver
* ESP32Marauder by justcallmekoko: https://github.com/justcallmekoko/ESP32Marauder
* piglet by Hamspiced: https://github.com/Hamspiced/piglet
* Biscuit DIY: https://biscuitshop.us/products/biscuit-pro, https://github.com/CodeHedge/biscuit_flasher

## Public data and standards

* Espressif: https://github.com/espressif/esp-idf 
* IEEE OUI registry: https://standards-oui.ieee.org/
* Bluetooth SIG Assigned Numbers: https://www.bluetooth.com/specifications/assigned-numbers/
* Apple Continuity and Google Fast Pair identifiers, from community reverse engineering
* FCC ID database: https://www.fcc.gov/oet/ea/fccid

## Research

* Fenske, Brown, Martin, Mayberry, Ryan, Rye. "Three Years Later: A Study of MAC
  Address Randomization in Mobile Devices and When It Succeeds." PoPETs 2021. DOI
  10.2478/popets-2021-0042
* Celosia, Cunche. "Discontinued Privacy: Personal Data Leaks in Apple Bluetooth
  Low Energy Continuity Protocols." PoPETs 2020. DOI 10.2478/popets-2020-0003
* Mayberry, Fenske, Brown, Martin, Fossaceca, Rye, Teplov, Foppe. "Who Tracks the
  Trackers? Circumventing Apple's Anti Tracking Alerts in the Find My Network."
  WPES 2021. DOI 10.1145/3463676.3485616
* Wi-Fi security: IEEE 802.11i, IEEE 802.11-2020, Wi-Fi Alliance WPA3
* Bluetooth address types: Bluetooth Core Spec, Vol 6, Part B
* WiGLE CSV format: https://wigle.net
* Kismet log format: https://www.kismetwireless.net

## AI use

AI tools were used during prototyping, and to help with debugging and reading
ESP-IDF example code. The design, the decisions, and the final code are the
author's own.
