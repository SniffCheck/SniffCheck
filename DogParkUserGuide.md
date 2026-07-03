# SniffCheck Dog Park User Guide

Dog Park is the multi-device SniffCheck setup.

Simple version:

```text
Dog Park X4 orchestrator = the controller / screen / scheduler / session store
SniffCheck Node          = the scanner device that reports back to the X4
```

It is still early firmware. It only listens. It does **not** deauth, jam, connect to, pair with, or attack nearby devices.

---

## What you flash

There are three different firmware images in this release family:

| Firmware | Board | What it does |
|---|---|---|
| `SniffCheck` | LilyGO T-Dongle C5 / ESP32-C5 | Normal standalone SniffCheck scanner. |
| `SniffCheck Node` | ESP32-C5 node board | Dog Park scanner node. Reports to the X4. |
| `Dog Park X4 orchestrator` | Xteink X4 / ESP32-C3 | Dog Park controller with e-ink menu, node admission, Walk, Guard Dog, Dog Sense, SD storage, and upload flow. |

The current Dog Park setup needs at least:

```text
1 Xteink X4 running Dog Park X4 orchestrator
1+ ESP32-C5 boards running SniffCheck Node
```

Best test setup:

```text
1 X4 orchestrator
3 C5 nodes
microSD card in the X4
```

---

## Flashing from the command line

From the repo root:

```sh
echo "=== X4 (ACM0) ==="; ./scripts/c3_build.sh flash 2>&1 | tail -3
```

Flash three C5 nodes:

```sh
for p in ACM1 ACM2 ACM3; do echo "=== node /dev/tty$p ==="; TARGET=esp32c5 PORT=/dev/tty$p ./scripts/node_build.sh flash 2>&1 | tail -3; done
```

If your ports are different, change `ACM0`, `ACM1`, etc.

Common layout:

```text
/dev/ttyACM0 = X4 orchestrator
/dev/ttyACM1 = node 1
/dev/ttyACM2 = node 2
/dev/ttyACM3 = node 3
```

---

## Flashing from the web flasher

Open the release web flasher and pick the matching firmware:

- **Dog Park X4 orchestrator — Xteink X4 (ESP32-C3)** for the X4.
- **SniffCheck Node — ESP32-C5** for C5 nodes.
- **SniffCheck — T-Dongle C5** for normal standalone SniffCheck.

The flasher checks the chip family before writing. Flashing erases that board and installs a clean image.

---

## X4 buttons

The X4 has seven buttons. The screen legend shows the important ones.

Basic controls:

| Button | Meaning |
|---|---|
| Back | Go back / leave service screen. |
| Select / Confirm | Open or choose the highlighted item. |
| Left / Right | Move through rows. |
| Up / Down | Move through rows. |
| Power hold | Sleep / power off the X4. Hold about `1.5s`. |

Most screens use:

```text
Back    = back
Select  = choose
< / >   = move
^ / v   = move
```

---

## First boot

1. Flash the X4 orchestrator.
2. Flash one or more C5 nodes.
3. Optional but recommended: put a microSD card in the X4.
4. Power on the X4.
5. Power on the nodes.
6. The nodes auto-start and begin asking to join.
7. On the X4, open **Nodes** and approve each pending node.

A node shows up as something like:

```text
+ sniffnode  A1B2C3
```

Select the pending node to approve it.

After approval it becomes something like:

```text
#1 sniffnode online
#2 sniffnode online
#3 sniffnode online
```

If a node disappears, it will age from online to stale/offline.

---

## What the node does

The C5 node firmware is not the full SniffCheck app. It is a Dog Park node.

It does this:

- auto-starts on boot
- broadcasts `JOIN_REQUEST` until the X4 approves it
- receives mode commands from the X4
- sends heartbeats back to the X4
- in **Walk**, passively sniffs Wi-Fi management frames
- in **Guard Dog**, passively scans BLE advertisements
- sends records back over ESP-NOW
- uses the red LED as a Guard Dog bark indicator

The node button toggles node mode:

```text
button press = stop/start node mode
```

Stopped means:

```text
no join requests
no sniffing
no Dog Park participation
```

---

## X4 main screens

### Nodes

Use this to approve or remove nodes.

- Pending nodes appear first with a `+`.
- Approved nodes appear as `#<id>`.
- Select a pending node to approve it.
- Select an approved node to forget/remove it.

### Modes

Modes has:

```text
Idle
Walk
Guard Dog
Start
Stop
```

`>` means the mode is armed.

`*` means the fleet is actually running that mode.

### Session

Session shows the current session info and actions:

```text
Connect Account
Upload to WDGWars
View Sessions
```

### Settings

Settings currently includes:

- Dark Mode toggle.
- Location status.

Location is set from the phone portal, not typed on the X4.

---

## Walk mode

Walk is coordinated wardriving.

What happens:

1. X4 assigns channels to each online node.
2. Nodes avoid overlapping work where possible.
3. Nodes passively sniff Wi-Fi devices.
4. Nodes send records to the X4.
5. X4 de-dupes records across the fleet.
6. X4 saves the run to SD when stopped.

Start Walk:

```text
Modes -> Walk -> Start
```

Stop Walk:

```text
Modes -> Stop
```

After stop, the X4 shows a run report with:

```text
Unique WiFi
Unique BLE
Records
Lifetime totals
```

Notes:

- Walk currently focuses on Wi-Fi from the nodes.
- The scheduler splits channels across online nodes.
- If a node joins or drops during Walk, the X4 can re-plan the channel assignments.

---

## Guard Dog mode

Guard Dog is the perimeter/watch mode.

Current behavior:

- Guard Dog uses passive BLE observation on the nodes.
- Nodes learn a baseline first.
- After the baseline, a new nearby BLE device can trigger a bark.
- Bark = red LED on the node and a Guard event sent to the X4.
- The X4 uses repeated RSSI reports to build the Dog Sense map.

Guard Dog has two steps:

```text
1. Calibrate Nodes
2. Start Guard
```

### Guard Dog settings

Open:

```text
Modes -> Guard Dog
```

You will see:

```text
Time
Radius
Calibrate Nodes
Start Guard
Dog Sense
```

Duration choices:

```text
5 min
10 min
15 min
20 min
30 min
Continuous
```

Radius choices:

```text
Very close
Near
In room
```

These are RSSI-based, so they are approximate. Walls, people, furniture, and node placement matter.

---

## Dog Sense

Dog Sense is the Guard Dog map view.

It is not GPS. It is not exact tracking. It is a confidence-based RF estimate.

Simple version:

```text
Dog Sense = nodes + RSSI + Guard Dog events -> rough blobs on a mini-map
```

The map shows:

| Marker | Meaning |
|---|---|
| Node square / sonar rings | A Dog Park node / anchor. The sonar rings are **cosmetic** (a fixed fraction of the map box, ~`span/3`, `/5`, `/7` by node count), not a calibrated detection radius. |
| `X4` / X marker | The X4's estimated position. |
| `#<n>` blob | A possible movement/presence blob. |
| Signal bars (next to a blob) | A 0–4 bar glyph showing the **strongest RSSI** any node hears that blob's devices at: more bars = closer to a node, fewer = far from all nodes. It changes as scans come in. |
| Small device dots | Devices associated with a focused blob. |

The screen says things like:

```text
DOG SENSE
CALIBRATING 12s...
```

or:

```text
DOG SENSE
Nodes 3  Conf medium
Blobs 2
```

### Important honesty note

A blob is **not** a confirmed person.

A blob means:

```text
nearby RF devices appear to be co-located or moving together
```

Use it as a situational hint, not a fact.

---

## Calibrating Dog Sense

Calibration lets the X4 learn the rough shape of your node layout.

Start calibration:

```text
Modes -> Guard Dog -> Calibrate Nodes
```

What to do:

1. Place nodes around the area you care about.
2. Stand near the middle with the X4.
3. Start **Calibrate Nodes**.
4. Wait for the countdown to finish.
5. The X4 locks the node geometry.
6. Start Guard.

Current calibration window is about `25 seconds`.

The map works best with:

```text
1 node  = basic sonar / alert point
2 nodes = rough side/line hint
3 nodes = rough 2D shape
4+ nodes = better perimeter shape
```

Still, it is RSSI. Treat it as fuzzy.

---

## Starting Guard Dog after calibration

After calibration finishes, the Guard screen will allow Start Guard.

```text
Modes -> Guard Dog -> Start Guard
```

The nodes keep scanning BLE. The X4 tracks:

- nearby BLE devices
- repeated RSSI changes
- rough movement blobs
- alerts/barks
- map confidence

To view the map:

```text
Modes -> Guard Dog -> Dog Sense
```

Or calibration/start may drop you into Dog Sense automatically.

On the Dog Sense map:

```text
< / > or Up / Down = pick a blob
Select             = focus / unfocus that blob
Back               = leave the map
```

When a blob is focused, the map switches to a detail view:

- It shows the blob's **highest-confidence associated device** only (instead of a
  list that ran off the screen), with the full scan data the X4 holds for it:
  the full MAC, `BLE`/`WiFi` plus its **confidence score**, a signal-bars +
  `dBm` readout, how many nodes hear it, and whether it is moving.
- If more than one device in the blob is high-confidence, it shows the strongest
  one and notes `Multiple candidate devices (N)`.

While focused, the buttons change:

```text
< / >  = scrub a marker along the blob's path trail (Path p/N)
^ (Up) = start a FOX HUNT on this blob
Select = unfocus
Back   = back to the full map
```

---

## Fox Hunt (walk to the device)

Fox Hunt turns the X4 into a homing tool: pick a device, then walk until you and
it overlap on the map. It works because the nodes triangulate **both** the
selected blob and the X4 in the same RF layout, so the distance between you and
the target is meaningful and updates as you move.

Enter it from a focused blob:

```text
Dog Sense -> Focus a blob -> ^ (Up)
```

The Fox Hunt screen shows:

- a big **smoothed distance in metres** to the target,
- a **WARMER / COLDER / STEADY** trend as you walk,
- a **proximity bar** that fills as you close in,
- a compact map with a **line from the X4 "X" to the target** — walk to shrink
  that line,
- `** ON TARGET **` when you are basically on top of it (the markers overlap,
  ~within a metre on the map).

```text
^ (from a focused blob) = start hunt
Back                    = stop hunting, return to the map
```

### Honesty note for Fox Hunt

- Distance and positions are **RSSI estimates**, not GPS. The metre number is a
  guide; the WARMER/COLDER trend stays useful even when the exact number is rough.
- The on-map line is **map-relative, not a compass bearing**. Absolute direction
  (true north) cannot be recovered from RSSI ranging alone, so navigate by
  watching the "X" close on the target, not by pointing in a fixed direction.
- If the X4 is not yet located (fewer than two nodes hear it), the screen shows
  `LOCATING X4` instead of a fake distance — move so more nodes can hear it.

---

## Account / upload portal

The X4 can open a temporary Wi-Fi portal so your phone or laptop can configure:

- home Wi-Fi name/password
- WDGWars API key
- one session location fix

Open it from:

```text
Session -> Connect Account
```

The X4 screen will show:

```text
Wi-Fi: SniffCheck-X4
Pass:  dogpark1234
URL:   https://192.168.4.1
```

Join that Wi-Fi from your phone/laptop, then open:

```text
https://192.168.4.1
```

Because this uses a self-signed HTTPS certificate, your browser may say the page is not private. That is expected for this local-only portal.

The portal uses HTTPS because phone geolocation APIs usually require a secure context.

Press **Back** on the X4 to close the portal and return to Dog Park.

### Session location

The X4 and nodes do not have GPS right now.

The portal lets your phone share one location fix for the session. That location is stamped onto records that do not have their own GPS.

Important:

```text
This is one base/park location for the session.
It is not per-node GPS.
It is not exact per-device location.
```

---

## Upload to WDGWars

After linking Wi-Fi and your WDGWars API key:

```text
Session -> Upload to WDGWars
```

The X4 will:

1. pause ESP-NOW
2. connect to your configured Wi-Fi
3. read the current session CSV from SD
4. upload it to WDGWars
5. show success or failure on the e-ink screen
6. press Back to return to Dog Park

If upload fails, common reasons are:

- no SD card
- no saved session CSV
- Wi-Fi credentials not set
- WDGWars API key not set
- home Wi-Fi unavailable

---

## SD card files

If an SD card is mounted, the X4 saves sessions under:

```text
/sd/sniffcheck-dogpark/sessions/<session-id>/
```

Each session can contain:

```text
wardrive.csv    WigleWifi-style CSV
records.jsonl   SniffCheck/BYOS-style sidecar records
summary.txt     unique Wi-Fi/BLE counts and overflow info
```

The X4 can list saved sessions:

```text
Session -> View Sessions
```

For a saved session you can:

```text
View Report
Delete
```

---

## What gets counted

The X4 tracks:

- total records received
- Guard Dog alerts
- unique Wi-Fi devices in a run
- unique BLE devices in a run
- lifetime Wi-Fi/BLE totals in NVS
- overflow count if the bounded set fills

Overflow is reported honestly. It means more devices were seen after the in-memory unique set hit its cap.

---

## Current limits

This is the important part.

### ESP-NOW is local to the Dog Park firmware family

Dog Park uses a fresh protocol, separate from the older rolled-back ENOW work.

Do not mix old ENOW firmware with this release.

### Normal SniffCheck is still separate

The normal SniffCheck C5 firmware is still the normal scanner/reporting device.

The current C5 Dog Park node image is a separate node firmware. Flashing it replaces normal SniffCheck on that board until you flash normal SniffCheck back.

### Guard Dog is BLE-focused right now

Current Guard Dog node behavior is BLE passive observation.

Walk mode uses Wi-Fi sniffing.

### Dog Sense is approximate

Dog Sense uses RSSI and repeated sightings. RSSI is noisy.

Do not treat map positions, blobs, or associated devices as exact truth.

### GL.iNet base station support is planned, not in this firmware

The planned **Dog Sense GL.iNet base station** idea is scoped separately. This current X4 firmware does not turn a GL.iNet router into a base station yet.

---

## Quick test recipe

Use this when checking the current Dog Park build.

1. Flash X4.
2. Flash 1-3 nodes.
3. Boot X4 and nodes.
4. On X4: **Nodes** -> approve each pending node.
5. On X4: **Modes** -> **Walk** -> **Start**.
6. Watch record count climb.
7. Stop Walk and check the run report.
8. Open **Modes** -> **Guard Dog**.
9. Pick radius/duration.
10. Select **Calibrate Nodes**.
11. Stand near the middle until calibration finishes.
12. Select **Start Guard**.
13. Open **Dog Sense**.
14. Move a BLE device nearby and watch for blobs/alerts.
15. Stop when done.

---

## Troubleshooting

### Node does not appear on X4

Try:

- make sure the node firmware is flashed, not normal SniffCheck
- power-cycle the node
- make sure the X4 is running the Dog Park orchestrator
- keep the node near the X4 for first admission
- reflash if the wrong firmware was selected

### X4 upload fails

Check:

- SD card inserted
- session has records
- Wi-Fi credentials saved from portal
- WDGWars key saved from portal
- router/internet reachable from the X4

### Dog Sense map looks wrong

Expected sometimes. Try:

- put nodes farther apart
- use 3+ nodes for better 2D shape
- stand in the middle during calibration
- recalibrate after moving nodes
- avoid metal shelves/walls when testing
- treat the map as a fuzzy hint, not GPS

### Browser blocks location

Use:

```text
https://192.168.4.1
```

not plain HTTP.

You may need to accept the local self-signed certificate warning.

---

## Safety / privacy posture

Dog Park is passive.

It only observes RF data that nearby devices already broadcast or leak. It does not force devices to respond. It does not connect to them. It does not identify a person with certainty.

Use the outputs as:

```text
signals
hints
confidence-based estimates
```

not as proof.
