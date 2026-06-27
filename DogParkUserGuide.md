# SniffCheck Dog Park User Guide

Dog Park is just throwing a few nodes together for cluster wardriving and our version of fox hunting, dog sense.

So I had a xteink x4 laying around so I decided to try using it as the brain for a cluster of nodes for some ideas we're trying to figure out. It is still early firmware. It doesn't do any offensive things and it doesn't have GPS added yet, again this is just a demo of some ideas we've got.

## What you flash

There are three different firmware images:

 `SniffCheck`       LilyGO T-Dongle C5/ESP32-C5  Normal standalone SniffCheck scanner
 `SniffCheck Node`  ESP32-C5 node board          Dog Park scanner node. Reports to the X4 
 `Dog Park X4`      Xteink X4/ESP32-C3           Dog Park controller with e-ink menu 

**Current Dog Park setup needs:**
*going to make a s3 version because thats the end goal anyways but for now the x4 works well enough even if the screen is super slow are updating*

- 1 Xteink X4 w/ Dog Park X4 firmware
- 1(or more) ESP32-C5(lilygo tdongle c5) w/ SniffCheck Node firmware


How i'm testing:

- 1 X4 
- 3 Lilygo Tdongle C5's(trying to work out triangulating....very hard without gps as i'm learning)
- SD card in the X4

## Flashing from the web flasher

Open the web flasher and pick a firmware:

- **Dog Park X4 — Xteink X4 (ESP32-C3)** for the X4.
- **SniffCheck Node — ESP32-C5** for C5 nodes.
- **SniffCheck — T-Dongle C5** for normal standalone SniffCheck.

## First boot

1. Flash the X4 
2. Flash some nodes
3. Throw a SD card in the X4
4. Boot X4
5. Boot nodes
6. Node broadcast to join on boot
7. Open **Nodes** and approve each pending node on the X4

A node shows up as something like:

```text
+ sniffnode  ABC123  pending
```

Select the pending node to approve it.

After approval it becomes something like:

```text
#1 sniffnode online
#2 sniffnode online
#3 sniffnode online
```

## Node

The C5 node firmware is not the full SniffCheck app. The node just does a few "simple" things and the c3 firmware does the rest. 

**after boot:**
- broadcasts `JOIN_REQUEST` until the X4 approves it
- receives commands from the X4
- sends heartbeats to the X4
**mode:**
- **Walk**, passively sniffs Wi-Fi management frames
- **Guard Dog**, passively scans BLE advertisements
**button:**
- button press = stop/start node mode

### Modes

This part is still being worked on, just needed a simple ui to test out the firmware.

```text
Idle
Walk
Guard Dog
Start
Stop
```

`>` what is staged

`*` what it currently running

### Session

Session shows the current session info and actions:

```text
Connect Account
Upload to WDGWars
View Sessions
```

Upload isn't working and gps adding isn't working yet either...well it is but its finicky so it's better just to say it isn't working...tried to do it with phone but still pretty buggy.

### Settings

Settings currently includes:

- Dark Mode toggle
- Location status **again this isn't really working**

Location is set from the phone portal, not typed on the X4.

---

## Walk mode

Walk is just cluster wardriving. It tracks life time stuff like:

```text
Unique WiFi
Unique BLE
Records
Lifetime totals
```

Notes:

- Walk currently focuses on WiFi 2.4/5GHz
- Scheduler splits channels across online nodes
- If a node joins or drops during Walk, the X4 replans the channel assignment
- BLE is next just wanted to get this demo out.

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

These are RSSI-based, so they are approximate. Walls, people, furniture, and node placement matter. Once we put GPS antennas in the mix this will get much more accurate(we think/hope), we're also looking at incorporating CSI into this for something kinda like RuView to help with the "blobbing" part of Dog Sense.

## Dog Sense

Dog Sense is the Guard Dog map view.

It is not GPS. It's a guess of whats going on in the area of the nodes.

```text
Dog Sense = nodes + RSSI + Guard Dog events -> rough blobs on a mini-map
```

The map shows:

| Marker | Meaning |
|---|---|
| Node square/sonar rings | A Dog Park node/anchor. The sonar rings are **cosmetic**, not a calibrated detection radius |
| `X4`/X marker | The X4's estimated position |
| `#<n>` blob | A possible movement/presence |
| Signal bars (next to a blob) | A 0–4 bar glyph showing the **strongest RSSI** any node hears that blob's devices at: more bars = closer to a node, fewer = far from all nodes. It changes as scans come in |
| Small device dots | Devices associated with a focused blob |

### Important honesty note

A blob is **not** a confirmed person.

A blob is just a guess that theres a device that appears to be moveing and is maybe kinda could be a person, maybe. It isn't perfect, its just a demo of an idea. 

## Calibrating Dog Sense

Calibration lets the X4 learn the rough shape of your node layout, it's kinda accurate but not super accurate. Once we add GPS antennas it'll be a lot more accurate.

1. Place nodes around the area you care about, max of 8-ish meters diameter atm...its a demo...chill
2. Stand near the middle with the X4
3. Click **Calibrate Nodes**
4. Wait for the countdown to finish
5. The X4 tries to guess the node geometry
6. Start Gaurd Dog

Current calibration window is about `25 seconds`

The map works best with:

```text
1 node  = basic sonar / alert point
2 nodes = rough side/line hint
3 nodes = rough 2D shape
4+ nodes = better perimeter shape
```

Still, it is RSSI. Treat it as like a guess-ish...kinda...its a placeholder until we figure something else out.

## Starting Guard Dog after calibration

After calibration finishes, the Guard screen will unlock Start

```text
Modes -> Guard Dog -> Start
```

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

- It shows the blob's **highest-confidence associated device** only with the full scan data the X4 holds for it:
  the full MAC, `BLE`/`WiFi` plus its **confidence score**, a signal-bars +
  `dBm` readout, how many nodes hear it, and whether it is moving.
- If more than one device in the blob is high-confidence, it shows the strongest
  one and notes `Multiple candidate devices <qty>`.

While focused, the buttons change:

```text
< / >  = see blobs "history"(place holder for when we have gps antennas..)
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
- `** ON TARGET **` when you are basically on top of it

```text
^ (from a focused blob) = start hunt
Back                    = stop hunting, return to the map
```

### Honesty note for Fox Hunt

- Distance and positions are **RSSI estimates**, not GPS. The metre number is a
  guide; the WARMER/COLDER trend stays useful even when the exact number is rough.
- The on-map line is **map-relative, not a compass bearing**. It isn't a compas, the numbers are guesses and not super accurate..just hold the x4 and walk around until the x4 is near what you're hunting. 
- you need 3 or more nodes for fox hunt, it wont work without 3+, the nodes wont find the x4.

## Account / upload portal

The X4 can open a temporary Wi-Fi portal so your phone or laptop can configure:

- home Wi-Fi name/password
- WDGWars API key
- one session location fix

Open it from:

```text
Session -> Connect Account
```

The X4 shows:

```text
Wi-Fi: SniffCheck-X4
Pass:  dogpark1234
URL:   https://192.168.4.1
```
Hop on that Wi-Fi from your phone, then open the url.

Because this uses a self-signed HTTPS certificate, your browser may say the page is not private. That is expected for this local-only portal.

The portal uses HTTPS because phone location sharing API dont always work without https......

Press **Back** on the X4 to return to Dog Park.

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
- or it just doesn't want to work because sometimes that happens
- you didn't set any GPS data(this part is tricky because you can add a single GPS location, so if you add GPS, start a walk, stop the walk, then you can upload it and it should work. But there is no continuous GPS sharing until we throw some GPS antennas into the mix)

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

### Normal SniffCheck is still separate

The normal SniffCheck C5 firmware is still the normal scanner/reporting device.

The current C5 Dog Park node image is a separate node firmware. Flashing it replaces normal SniffCheck on that board until you flash normal SniffCheck back.

### Sniffing

Gaurd Dog = BLE
Walk = Wifi

**Again this is just a demo** We will probably keep Gaurd Dog as just BLE but will be adding BLE to the Walk we just need move C5's and antennas. 

### Dog Sense is approximate

Dog Sense uses RSSI and repeated sightings. RSSI is noisy.

Do not treat map positions, blobs, or associated devices as exact truth.

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
