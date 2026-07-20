# SniffCheck Node (dogpark-node)

A slim, headless SniffCheck scanner node for the ESP32-C5. It sniffs Wi-Fi and
watches BLE ("Guard Dog": a baseline window learns the devices already present, then
alerts on new arrivals), shows status and sniff/dig animations on the small LCD, and
reports over ESP-NOW to a Dog Park orchestrator.

This is a trimmed build of the full SniffCheck firmware: the display driver and sprite
assets are the same single source of truth as the main firmware, with the
analyzer/vetter/detail screens pruned.

## Layout

| File            | Job                                                       |
|-----------------|-----------------------------------------------------------|
| `app_main.c`    | boot, Guard Dog baseline/alert loop, radio coexistence    |
| `dp_sniffer.*`  | Wi-Fi sniffer                                             |
| `dp_ble.*`      | BLE observer (NimBLE)                                     |
| `node_display.*`| LCD driver + boot splash + sniff/dig animations          |

## Build & flash (esp32c5)

```sh
idf.py -B ~/.cache/dogpark-node-build --preview set-target esp32c5
idf.py -B ~/.cache/dogpark-node-build build flash monitor
```

The build pulls a few shared sources by relative path from sibling trees:

- `../../main/led.c` and the `components/lcd_st7735` component (shared with the full
  firmware),
- `../../dogpark-x4/main/dp_espnow.*` — the shared ESP-NOW transport used to talk to
  the orchestrator.

Those sibling files must be present alongside `dogpark-node/` for the build to
resolve. A pre-built image is on the web flasher as **SniffCheck Node (ESP32-C5)**.
