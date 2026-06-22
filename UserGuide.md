# SniffCheck User Guide

SniffCheck only listens. It never attacks, never sends fake stuff, never pokes other devices. It just watches the air and tells you what it sees.

This guide tells you how to push the button, read the screen, and use the phone page. *<- side note: don't push the button*

## The button

There is one button: BOOT. You do three things with it:       *<- yes two ":"'s in one sentence...*

- `[1]` = click once
- `[2]` = click twice fast (within `450 ms`)
- `[hold]` = press and hold (about `1.5 seconds`)             *<- sometimes you have to hold it longer..idk*

Rule of thumb: `[hold]` = go back. On scan screens, `[hold]` can also rescan or stop it just depends on what splash you're on...

## Turn it on

1. Plug it in.
2. Logo and the author splash
3. It starts in **Adv mode** (will change this down the road to start in Lite but since this is a demo figured it'd make more sense to show the guts up front)
4. Will always does a scan on boot (we plan to change this, right now though this is what it does..)
5. Loads env summary splash (this will probably stay the same until we add the **ap_on_boot** feature)

On the summary screen:

- `[1]` = results       *<- exactly what it sounds like, take a look on the dongle before checking out the webpage*
- `[2]` = pup           *<- this is mostly cosmetic atm, so are trophies, we will put a future plans doc in the repo sometime soon*
- `[hold]` = rescan     *<- exactly what it sounds like, BUUUT if you rescan in adv_mode you'll flag the deeper_scan which just means it'll scan for 90s instead of the typical boot scan snapshot. Good for verifying results or digging deeper into some of the threat flags.* 

## Two modes: Lite and Adv

**Adv mode** = the big mode.        *<- Really probably the only reason anyone is checking out this repo* 

All the things:     *<- so if you've read this far you passed the test and pushed a button...you're a real one*

- Deep Wi-Fi and BLE views.
- Drill-down screens (Wi-Fi, BLE, probes, and more).
- The phone page (WebUI).
- Reports, saving, exporting, importing, live capture tools.

Best if you plan to use a phone or laptop.       *<- personally I like to use my laptop and run it in monitor mode, there's a whole set of commands you can run from the monitor that allows you to quickly navigate the firmware and do testing for the sake of testing..*

**Lite mode** = the small mode.     *<- This is what SniffCheck started as. It is what I'll be pushing for the normies, "Hey look a little toy that gives you a simple maybe safe/maybe not safe verdict for the coffee shop you frequent.....yaaaay....actually yes "yay" lite mode is the quick and dirty facts, fast rf audit*

Screen only:

- Quick yes/no read.
- Simple Wi-Fi list.
- Pup.
- No phone needed.

Best if you just want a fast look on the device to see what RF threats flag from a quick snapshot. 

*The device remembers the mode after you change it*

## Change the mode

**On the device, from the Main screen:**          *<- this may change as things progress because right now every flash boots to adv mode which gives you easy access to the settings, etc. In lite_mode it's a little bit of a maze to get to the settings on purpose because originally I planned for lite to be the only mode with adv a easter egg for people who want to know more..i digress.*

1. `[2]` = Settings
2. `[1]` = Mode
   - `[1]` = Lite
   - `[2]` = Adv

If the mode changed, it does a fresh boot scan.    *<- not a reboot*

**On the phone page:**

1. Open the phone page (only in adv mode)
2. Go to the **Settings** tab
3. Pick **Lite** or **Adv**
4. It takes effect on the next scan

### Main screen

- `[1]` = Results
- `[2]` = Settings
- `[hold]` = scan again

### Lite Results

- `[1]` = Wi-Fi list
- `[2]` = Pup
- `[hold]` = scan again

In the Lite Wi-Fi list:

- `[1]` = next network
- `[2]` = open details
- `[hold]` = back to Main

In Lite Wi-Fi details:

- `[1]` = next page
- `[2]` = next network's details
- `[hold]` = back to the list

### Adv Splashes

Adv Results has panes: WiFi, BLE, Probes, Pup

**On the pane picker:**

- `[1]` = next pane
- `[2]` = open the pane
- `[hold]` = back to Main

**Adv Wi-Fi list:**

- `[1]` = next network
- `[2]` = open details
- `[hold]` = back

**Adv BLE list:**

- `[1]` = next device
- `[2]` = open details
- `[hold]` = BLE Classes

**BLE Classes:**

- `[1]` = next class
- `[2]` = open that class
- `[hold]` = back to Main

**Adv Probes:**

- Open **Probes** to see the Probe Log
- `[2]` = cycle Probe Log > Seq Link > IE Sig > ANQP Leak > back to Probe Log
- `[1]` = look at entries (this is still partially WIP)
- `[hold]` = back to Results

**Explore/Dig:**

- Explore: `[1]` = move cursor, `[2]` = open raw view, `[hold]` = back
- Dig: `[1]` = next frame, `[2]` = previous frame, `[hold]` = back to Explore

## Turn on the phone page (WebAP)

You need to be in adv mode for this

From Main:

1. `[2]` = Settings
2. In Settings: `[2]` = More
3. In More: `[2]` = Download/launch AP
4. In the confirm screen:
   - `[1]` = turn the AP on
   - `[2]` = set timer: `15`, `30`, or `60` minutes
   - `[hold]` = back

When the AP is on:

- The screen shows a QR code to join the SniffCheck Wi-Fi
- After you join, the QR shows the web address
- If nothing opens on its own, type `192.168.4.1` as a url in a broswer
- Up to 2 devices can join
- `[hold]` = turn the AP off

The AP picks a channel (1, 6, or 11) based on the last scan.

*Lite mode has no phone page.*

## The phone page (WebUI)

It lives on the SniffCheck Wi-Fi. No cloud. No account. No internet needed.    *<- we thought about making an app but we really want everything to stay on the device as much as possible because were all cyber security focused and don't really like phone apps...lot of data there going back and forth..*

**Open:** `http://192.168.4.1/`

## Tabs

### Home

**Shows status:** AP time left, record count and size, scan count, connected devices, session/firmware info

**Buttons:**

- **View report** = open the live report
- **Save report (.html)** = download a report you can open later
- **Download data (.jsonl)** = download the raw records
- **Keep awake +15 min** = add time to the AP timer
- **Start new scan** = closes the AP (scanning needs the radio). Re-open the AP from the device after
- **Close AP** = turn off the phone page
- **Clear capture** = wipe the current records

### Pup

Virtual Pup. You can: Pet, Give treat, Rename, Start Sniff Walk, Reset Pup    *<- honestly all of this is mostly cosmetic but **walk** right now its a placeholder for some future things we want to do.*

### BYOS

BYOS = bring your own scan. Drop in a file: `.json`, `.jsonl`, `.csv`, `.txt`, or `.log`  *<- we tried to make the 'parse' button work with the common upload types from wigle and kismet but its buggy sometimes. We will keep working on it but its a low priority atm*

Your browser reads it. You can download a device list, or send the records into SniffCheck to view as a report *<- this is the scaffold for our Dog Park feature thats in the works...more on that later probably*

### Settings

- Mode: Lite or Adv (next scan)
- Brightness: `25%`, `50%`, `75%`, `100%`
- LED: On or Off      *<- does not really work....it dims the light but because we redraw each splash for some reason it inits a led flash on redraw...we have a issues open with espressif to try and figure this out but honestly it may come down to just the Lilygo Tdongle C5 not appreciating our attempt at animation.....*
- AP timer: `15`, `30`, or `60` minutes    *<- realistitcally you don't need to keep the ap open once you open the summary. Normally I'll launch the ap, connect, go to the page, open **View Report** or save the report as html, and then disconnect or do more scans while I check out the results.*

## Reports

From Home, tap **View report** for the live report

Tap **Save report (.html)** to keep a copy for later

**Report tabs:** Summary, Wi-Fi, BLE, Clusters, Trackers, Alerts, Privacy, Channels, Raw, and Drones (if any drones were seen otherwise it won't show up)   *<- clusters are finicky...lot of logic there to combine scanned results and say, with confidence, "yeah this is probably the same router" we're trying to get there but it's taking time*

You can filter and search: by kind, vendor, device type, grade, threat, band, channel. There are quick buttons too: Phones, Cameras, Wearables, Drones, Trackers, Cars, Enterprise APs, Consumer APs, High threat.  *<- we have a smart filter feature that runs but if you're scanning the same areas you'll never really see a difference..also this smart filter feature is part of a future addition*

*a saved report opens later but can't run live tools. Live tools only work on the live report while joined to the SniffCheck AP*

## Scan again from the phone

1. Join the SniffCheck AP
2. Open `http://192.168.4.1/`
3. On Home, tap **Start new scan**
4. The AP closes (the radio is busy scanning)
5. When it's done, open the AP from the device to see new results

## Sniff Walk

A Sniff Walk scans Wi-Fi and BLE while you walk around carrying the device. At the end it saves walk records, gives Pup XP, and opens the AP with a summary.                *<- wardriving but we're calling it Sniff Walk because we want to be trendy and keep to the doggo brand..but we all know what it is*

### Start a walk on the device

1. From the summary, `[2]` = Pup
  **On the Pup page:**
   - `[1]` = play with Pup
   - `[2]` = back
   - `[hold]` = start the wal
2. Carry it while it runs
3. `[hold]` = end the walk
4. Join the AP when the screen shows the join prompt to see the summary

During a walk, clicks do nothing. Only `[hold]` works

### Start a walk from the phone

1. Turn on the phone page
2. Go to the **Pup** tab
3. Tap **Start Sniff Walk**
4. Tap again if it asks you to confirm
5. The AP closes while you walk
6. End it on the device with `[hold]`
7. The AP comes back on its own with the summary

## Channels tab (live tools)

The Channels tab is in the report. The live buttons only work on the live report while joined to the SniffCheck AP.

**It shows:**

- A bar graph of channel activity from the last scan
- Bars sized against the busiest channel
- 2.4 GHz channels first, then 5 GHz
- A list of stations the device saw active during its scan
**Buttons:** capture stations, CSI, packet scan     *<- this is a work in progress, it works, but we haven't spent a ton of time on it because like a lot of other features this ties into future things we want to do so we've pushed most of it off till we're actually ready to work on it all. for now its ok if you don't know what all this does, feel free to just kinda ignore the channels tab until we flesh this out*

All of these only listen. Nothing is ever sent    *<- at the moment this is a global decision for SniffCheck, we're looking at allowing certain things to be possible in adv mode down the road once we integrate mqtt/zigbee/thread but we haven't crossed that rubicon yet so things to figure out later*

### Capture stations

1. Open the live report from the AP
2. Go to **Channels**
3. Tap **Capture stations**
4. Type a channel and a time (`1` to `30` seconds)
5. The AP closes during capture
6. It reads MAC headers only. It does not decrypt traffic
7. After, re-open the AP from the device to see results

### CSI capture

1. Open the live report from the AP
2. Go to **Channels**
3. Tap **Run CSI capture**
4. Type a channel and a time (`1` to `30` seconds)
5. The AP closes during the window
6. You get a GO / NO-GO result
7. After, re-open the AP from the device to see results

### Packet scan (PCAP)

1. Open the live report from the AP
2. Go to **Channels**
3. Look at the channel graph
4. Tap **Packet scan: 10s per channel**
5. The AP closes while it captures
6. It spends `10 seconds` on each channel in the graph
7. The AP comes back on its own when done
8. Rejoin the AP
9. Go back to Channels and download the PCAP when it's ready

Packet scan only listens. Nothing is sent.    *<- for the moment*

## If something goes wrong

- Captive portal won't open? Go straight to `http://192.168.4.1/`    *<- save yourself some time, don't set auto connect in device settings for the ap for sniffcheck because it generates a new pass every time, but do save the webpage to your homescreen so you can just skip the second qrcode.*
- Phone page drops during a scan or capture? That's normal. The radio can't serve the AP and scan at the same time *<- if you hit 'Continue trying wifi' it will stay connected*
- After **Start new scan**, station capture, or CSI: re-open the AP from the device *<- should be same password so just rejoining the ap once it shows up works 70% or 90% of the time... we're still trying to figure that one out but I'm sure it'll sneak in there in one of the updates to the repo...*
- After a Sniff Walk or packet scan: the AP comes back on its own *<- see above note*
- Saved reports open later, but live tools need the SniffCheck AP *<- minus the channels...thats temporary*
- Lost in the menus? `[hold]` backs you out toward Main
