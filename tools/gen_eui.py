
"""
gen_eui.py v3 — pack data/eui.bin (unified typed identifier index).

Sources (in order of preference):
  1. Local /oui-eui-cid/ tree (IEEE CSVs + Bluetooth SIG public repo).
  2. Cached fetch in data/.eui_cache/ (older fallback).
  3. Live IEEE/SIG fetch.

Binary format v3 (multi-section, see main/eui_db.h for record layouts):
  PREAMBLE        32 B (magic, version, built, section_count, reserved)
  SECTION TABLE   16 B per descriptor (kind, offset, count, stride)
  TRAILER         8 B (names_off, names_len)
  SECTIONS        sorted index of records per kind
  NAMES           deduplicated NUL-terminated UTF-8

Sections (kind → identifier):
   1 MAC /24 OUI         std 12 B   oui.csv
   2 MAC /28 (MA-M)      std 12 B   mam.csv
   3 MAC /36 (MA-S)      wide 16 B  oui36.csv
   4 IAB                 wide 16 B  iab.csv
   5 CID                 std 12 B   cid.csv
  10 BT Company ID       std 12 B   SIG company_identifiers.yaml
  11 BT UUID16           std 12 B   SIG member/service/sdo_uuids.yaml
  12 BT UUID32           std 12 B   data/uuid32.yaml          (Step 4)
  13 BT UUID128          uuid 24 B  data/uuid128.yaml         (Step 4)
  20 Mfg-data byte rule  rule 24 B  data/ble_catalog.yaml     (Step 5)
  21 Apple Continuity    tiny 8 B   data/apple_continuity.yaml(Step 6)
  22 MS CDP subtype      tiny 8 B   data/ms_cdp.yaml          (Step 6)
  23 Fast Pair model ID  std 12 B   data/fast_pair.yaml       (Step 6)
  24 BLE name rule       ssid 12 B  data/name_rules.yaml      (Step 6)
  30 Wi-Fi vendor IE OUI std 12 B   data/vendor_ie.yaml       (Step 7)
  31 SSID typed rule     ssid 12 B  data/ssid_rules.yaml      (Step 7)
  32 IE-sig hash         std 12 B   data/ie_signatures.yaml   (Step 7)
  33 WPS mfg hash        std 12 B   data/wps_strings.yaml     (Step 7)
  34 RSN cipher OUI      std 12 B   static                    (Step 7)
  35 Country code        tiny 8 B   ISO 3166                  (Step 7)
  40 CDP org-TLV OUI     std 12 B   data/cdp_lldp_org.yaml    (Step 8)
  41 LLDP org-TLV OUI    std 12 B   data/cdp_lldp_org.yaml    (Step 8)
  42 DHCP Option 60 hash std 12 B   data/dhcp_fingerprints.yaml (Step 8)
  43 DHCP Option 55 hash std 12 B   data/dhcp_fingerprints.yaml (Step 8)
  50 FCC Grantee Code    std 12 B   data/fcc_ids.yaml         (Step 9)
  51 FCC Covered List    std 12 B   overlay covered_list      (Step 9)
"""

import csv
import io
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import yaml

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT    = os.path.dirname(SCRIPT_DIR)
DATA_DIR     = os.path.join(REPO_ROOT, "data")
OVERLAY_PATH = os.path.join(DATA_DIR, "eui_overlay.yaml")
OUTPUT_PATH  = os.path.join(DATA_DIR, "eui.bin")
CACHE_DIR    = os.path.join(DATA_DIR, ".eui_cache")
LOCAL_DIR    = os.path.join(REPO_ROOT, "oui-eui-cid")

REGISTRIES = {
    "oui":   ("https://standards-oui.ieee.org/oui/oui.csv",     "oui.csv"),
    "mam":   ("https://standards-oui.ieee.org/oui28/mam.csv",   "mam.csv"),
    "oui36": ("https://standards-oui.ieee.org/oui36/oui36.csv", "oui36.csv"),
    "cid":   ("https://standards-oui.ieee.org/cid/cid.csv",     "cid.csv"),
    "iab":   ("https://standards-oui.ieee.org/iab/iab.csv",     "iab.csv"),
}

BT_COMPANY_YAML = "public/assigned_numbers/company_identifiers/company_identifiers.yaml"
BT_MEMBER_YAML  = "public/assigned_numbers/uuids/member_uuids.yaml"
BT_SERVICE_YAML = "public/assigned_numbers/uuids/service_uuids.yaml"
BT_SDO_YAML     = "public/assigned_numbers/uuids/sdo_uuids.yaml"

SIG_RAW_URL_BASE = "https://bitbucket.org/bluetooth-SIG/public/raw/main/"

MAGIC   = b"SCEUIDB\x00"
VERSION = 3

SECTION_MAC24          = 1
SECTION_MAC28          = 2
SECTION_MAC36          = 3
SECTION_IAB            = 4
SECTION_CID            = 5
SECTION_BT_COMPANY     = 10
SECTION_BT_UUID16      = 11
SECTION_BT_UUID32      = 12
SECTION_BT_UUID128     = 13
SECTION_MFG_RULE       = 20
SECTION_APPLE_SUBTYPE  = 21
SECTION_MS_SUBTYPE     = 22
SECTION_FAST_PAIR      = 23
SECTION_NAME_RULE      = 24
SECTION_VENDOR_IE      = 30
SECTION_SSID_RULE      = 31
SECTION_IE_SIGNATURE   = 32
SECTION_WPS_MFG        = 33
SECTION_RSN_OUI        = 34
SECTION_COUNTRY        = 35
SECTION_CDP_ORG        = 40
SECTION_LLDP_ORG       = 41
SECTION_DHCP_VC        = 42
SECTION_DHCP_FP        = 43
SECTION_FCC_GRANTEE    = 50
SECTION_FCC_COVERED    = 51
SECTION_DRONE_MFR      = 60

STRIDE_STD     = 12
STRIDE_WIDE    = 16

STRIDE_RULE    = 24
STRIDE_UUID128 = 24
STRIDE_SSID    = 16
STRIDE_TINY    = 12

F_MALICIOUS     = 0x0001
F_ENTERPRISE    = 0x0002
F_CONSUMER      = 0x0004
F_IOT           = 0x0008
F_MOBILE        = 0x0010
F_REG_OUI28     = 0x0020
F_REG_OUI36     = 0x0040
F_REG_CID       = 0x0080
F_SURVEILLANCE  = 0x0100
F_INVESTIGATION = 0x0200
F_MAKER         = 0x0400
F_DEV_MODULE    = 0x0800
F_STANDARDS     = 0x1000
F_PRIVATE       = 0x2000
F_FCC_COVERED   = 0x4000
F_FCC_APPROVED  = 0x8000

CLASS_NAMES = [
    "unknown", "enterprise_ap", "consumer_ap", "iot_hub", "iot_leaf",
    "mobile", "surveillance_cam", "investigation", "maker_board",
    "dev_module", "beacon", "tracker", "wearable", "medical",
    "automotive", "standards", "attack_signal",
    "phone", "tablet", "laptop", "audio", "access_control",
    "infrastructure", "pos_payment", "vehicle",
    "drone", "surveillance_oui", "rogue_hw_oui",
]
CLASS_ID = {name: idx for idx, name in enumerate(CLASS_NAMES)}

CLASS_ALIASES = {
    "iot_sensor":     "iot_leaf",
    "iot_appliance":  "iot_hub",
    "surveillance":   "surveillance_cam",
    "dev_board":      "maker_board",
    "pentest_tool":   "attack_signal",
    "automotive":     "vehicle",
}
for _alias, _target in CLASS_ALIASES.items():
    if _target in CLASS_ID:
        CLASS_ID[_alias] = CLASS_ID[_target]

def fnv1a32(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h

def fnv1a32_str_lower(s):
    return fnv1a32(s.lower().encode("utf-8"))

def read_source(name, filename, url):
    local = os.path.join(LOCAL_DIR, filename)
    if os.path.exists(local):
        print(f"  {name}: local oui-eui-cid", flush=True)
        with open(local, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, filename)
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < 86400 * 7:
        print(f"  {name}: cached", flush=True)
        with open(cache, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    print(f"  {name}: fetching {url}", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "sniffcheck-gen-eui/3.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read().decode("utf-8", errors="replace")
    with open(cache, "w", encoding="utf-8") as f:
        f.write(data)
    return data

def read_local_yaml(rel_path):
    """Resolve a Bluetooth SIG public-assigned-numbers YAML.

    Priority: local checkout under LOCAL_DIR -> cached fetch (7-day TTL)
    -> fresh fetch from SIG_RAW_URL_BASE. Returns parsed YAML or None on
    every-fallback miss (network failure with empty cache)."""
    full = os.path.join(LOCAL_DIR, rel_path)
    if os.path.exists(full):
        with open(full, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    cache_name = rel_path.replace("/", "__")
    cache_path = os.path.join(CACHE_DIR, cache_name)
    if os.path.exists(cache_path) and (time.time() - os.path.getmtime(cache_path)) < 86400 * 7:
        with open(cache_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    if rel_path.startswith("public/"):
        url_rel = rel_path[len("public/"):]
    else:
        url_rel = rel_path
    url = SIG_RAW_URL_BASE + url_rel

    try:
        print(f"  sig_yaml: fetching {url}", flush=True)
        req = urllib.request.Request(url, headers={"User-Agent": "sniffcheck-gen-eui/3.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8", errors="replace")
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(data)
        return yaml.safe_load(data)
    except (urllib.error.URLError, OSError) as e:

        if os.path.exists(cache_path):
            print(f"  sig_yaml: fetch failed ({e}); using stale cache", file=sys.stderr)
            with open(cache_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        print(f"  sig_yaml: fetch failed ({e}); section will be empty", file=sys.stderr)
        return None

def read_data_yaml(filename):
    """Load an optional data/*.yaml seed. Returns {} if absent."""
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def parse_ieee_csv(text):
    """Yield (hex_prefix, vendor_name) from IEEE registry CSV."""
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 3:
            continue
        raw = row[1].strip()
        name = row[2].strip()
        if not raw or not name or raw.lower() == "organization name":
            continue
        yield raw, name

def hex_to_int(hex_str, expected_chars):
    h = hex_str.replace("-", "").replace(":", "")
    if len(h) < expected_chars:
        return None
    try:
        return int(h[:expected_chars], 16)
    except ValueError:
        return None

def substring_match(needles, haystack):
    h = haystack.lower()
    for needle in needles:
        n = needle.lower()
        if n in h or h in n:
            return needle
    return None

def derive_flags_class(name, overlay, base_flags=0):
    flags = base_flags
    class_id = CLASS_ID["unknown"]
    n_lower = name.lower()

    if any(m in n_lower for m in ("hak5", "pineapple")):
        flags |= F_MALICIOUS

    if substring_match(overlay.get("covered_list", []), name):
        flags |= F_FCC_COVERED

    tiers = overlay.get("vendor_tiers", {})
    if substring_match(tiers.get("enterprise", []), name):
        flags |= F_ENTERPRISE
        class_id = CLASS_ID["enterprise_ap"]
    if substring_match(tiers.get("consumer", []), name):
        flags |= F_CONSUMER
        if class_id == CLASS_ID["unknown"]:
            class_id = CLASS_ID["consumer_ap"]
    if substring_match(tiers.get("iot", []), name):
        flags |= F_IOT
        if class_id == CLASS_ID["unknown"]:
            class_id = CLASS_ID["iot_leaf"]
    if substring_match(tiers.get("mobile", []), name):
        flags |= F_MOBILE
        if class_id == CLASS_ID["unknown"]:
            class_id = CLASS_ID["mobile"]

    classes = overlay.get("device_classes", {})
    if substring_match(classes.get("surveillance", []), name):
        flags |= F_SURVEILLANCE
        class_id = CLASS_ID["surveillance_cam"]
    if substring_match(classes.get("investigation", []), name):
        flags |= F_INVESTIGATION
        class_id = CLASS_ID["investigation"]
    if substring_match(classes.get("maker", []), name):
        flags |= F_MAKER
        class_id = CLASS_ID["maker_board"]
    if substring_match(classes.get("dev_module", []), name):
        flags |= F_DEV_MODULE
        if class_id == CLASS_ID["unknown"]:
            class_id = CLASS_ID["dev_module"]

    if name.strip().lower() == "private":
        flags |= F_PRIVATE

    return flags, class_id

class NameTable:
    def __init__(self):
        self.offsets = {}
        self.blob = bytearray()

    def offset(self, name):
        if name not in self.offsets:
            self.offsets[name] = len(self.blob)
            self.blob.extend(name.encode("utf-8") + b"\x00")
        return self.offsets[name]

def pack_std(key32, flags, class_id, name_off):
    return struct.pack("<IHBBI", key32 & 0xFFFFFFFF, flags, class_id, 0, name_off)

def pack_wide(key64, flags, class_id, name_off):
    return struct.pack("<QHBBI", key64 & 0xFFFFFFFFFFFFFFFF, flags, class_id, 0, name_off)

def pack_tiny(key16, flags, class_id, name_off):

    return struct.pack("<HHBBHI",
                       key16 & 0xFFFF, flags, class_id, 0, 0,
                       name_off & 0xFFFFFFFF)

def pack_uuid128(key16b, flags, class_id, name_off):
    assert len(key16b) == 16
    return struct.pack("<16sHBBI", bytes(key16b), flags, class_id, 0, name_off)

def pack_rule(key_hash, cid, prefix_bytes, flags, class_id, subtype, name_off):
    prefix6 = bytes(prefix_bytes) + b"\x00" * (6 - len(prefix_bytes))
    return struct.pack("<IHB6s3sHBBI",
                       key_hash & 0xFFFFFFFF, cid & 0xFFFF, len(prefix_bytes),
                       prefix6, b"\x00\x00\x00",
                       flags, class_id, subtype, name_off)

def pack_ssid(_unused, flags, class_id, match_type, pattern_off, name_off):
    """eui_record_ssid_t: u32 pattern_off, u32 name_off, u16 flags, u8 class,
    u8 match_type, u32 reserved = 16 B."""
    return struct.pack("<IIHBBI",
                       pattern_off & 0xFFFFFFFF, name_off & 0xFFFFFFFF,
                       flags, class_id, match_type, 0)

FLAG_BY_NAME = {
    "MALICIOUS":     F_MALICIOUS,
    "ENTERPRISE":    F_ENTERPRISE,
    "CONSUMER":      F_CONSUMER,
    "IOT":           F_IOT,
    "MOBILE":        F_MOBILE,
    "SURVEILLANCE":  F_SURVEILLANCE,
    "INVESTIGATION": F_INVESTIGATION,
    "MAKER":         F_MAKER,
    "DEV_MODULE":    F_DEV_MODULE,
    "STANDARDS":     F_STANDARDS,
    "PRIVATE":       F_PRIVATE,
    "FCC_COVERED":   F_FCC_COVERED,
    "FCC_APPROVED":  F_FCC_APPROVED,
    "TRACKER":       0,
}

def flags_from_list(flag_names):
    out = 0
    for n in flag_names or []:
        if n in FLAG_BY_NAME:
            out |= FLAG_BY_NAME[n]
    return out

def class_from_name(class_name, default="unknown"):
    return CLASS_ID.get(class_name or default, CLASS_ID[default])

HARD_MATCH_CLASS_IDS = {
    CLASS_ID["surveillance_cam"],
    CLASS_ID["attack_signal"],
    CLASS_ID["investigation"],
}
HARD_MATCH_MIN_TOKEN_LEN = 5

_DEVICE_SUBTYPES = None
_SUBTYPE_WARN_SEEN = set()

def load_device_subtypes():
    global _DEVICE_SUBTYPES
    if _DEVICE_SUBTYPES is not None:
        return _DEVICE_SUBTYPES
    yml = read_data_yaml("device_subtypes.yaml")
    out = {}
    for cls, subs in (yml.get("subtypes") or {}).items():
        out[cls] = set(s for s in (subs or []) if isinstance(s, str))
    _DEVICE_SUBTYPES = out
    return out

def validate_device_subtype(rule_id, class_name, subtype_label):
    """Warn (don't fail) if subtype_label not in overlay for class_name."""
    if not subtype_label:
        return
    overlay = load_device_subtypes()
    known = overlay.get(class_name, set())
    if subtype_label in known:
        return
    key = (class_name, subtype_label)
    if key in _SUBTYPE_WARN_SEEN:
        return
    _SUBTYPE_WARN_SEEN.add(key)
    print(f"  WARNING: catalog rule {rule_id!r} uses unknown device_subtype "
          f"{subtype_label!r} for class {class_name!r}; add to "
          f"data/device_subtypes.yaml or fix the rule",
          file=sys.stderr)

def require_device_class(rule_id, item, source):
    """Every BLE catalog rule must declare a device_class.
    Accepts either `device_class:` or legacy `class:`."""
    class_name = item.get("device_class") or item.get("class")
    if not class_name:
        print(f"  ERROR: {source} rule {rule_id!r} missing required "
              f"`device_class` field (locked vocabulary)",
              file=sys.stderr)
        sys.exit(1)
    if class_name not in CLASS_ID:
        print(f"  ERROR: {source} rule {rule_id!r} unknown device_class "
              f"{class_name!r}; valid: {sorted(CLASS_ID)}",
              file=sys.stderr)
        sys.exit(1)
    return class_name

def uuid128_bytes(uuid_str):
    """Parse 8-4-4-4-12 UUID string to 16 raw bytes (big-endian / network order)."""
    h = uuid_str.replace("-", "").strip()
    if len(h) != 32:
        return None
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None

def build_section_mac24(overlay, names):
    """kind=1 — MAC /24 OUI from oui.csv only."""
    entries = {}
    malicious_set = set()
    for entry in overlay.get("malicious_prefixes", []):
        h = entry["prefix"].replace(":", "").replace("-", "")
        try:
            malicious_set.add(int(h[:6], 16))
        except ValueError:
            pass

    # Rogue-AP build platforms (Raspberry Pi, ALFA, etc.). Evidence tier, NOT
    # a verdict: these are legitimate general-purpose parts, so they get the
    # soft ROGUE-HW? class and no F_MALICIOUS. value = optional display-name
    # override (None -> keep the IEEE vendor name).
    rogue_hw_map = {}
    for entry in overlay.get("rogue_hw_prefixes", []):
        h = entry["prefix"].replace(":", "").replace("-", "")
        try:
            rogue_hw_map[int(h[:6], 16)] = entry.get("name")
        except ValueError:
            pass

    surveillance_map = {}
    for entry in overlay.get("surveillance_prefixes", []):
        h = entry["prefix"].replace(":", "").replace("-", "")
        high = str(entry.get("confidence", "low")).lower() == "high"
        try:
            surveillance_map[int(h[:6], 16)] = (entry.get("name", "Surveillance camera"), high)
        except ValueError:
            pass

    def _surv_pack(name, high):
        if high:
            return (F_SURVEILLANCE, CLASS_ID["surveillance_cam"], name)

        hint = name if name.endswith("(OUI)") else f"{name} (OUI)"
        return (0, CLASS_ID["surveillance_oui"], hint)

    vehicle_map = {}
    for entry in overlay.get("vehicle_prefixes", []):
        h = entry["prefix"].replace(":", "").replace("-", "")
        try:
            vehicle_map[int(h[:6], 16)] = entry.get("name", "Vehicle")
        except ValueError:
            pass

    text = read_source("oui", REGISTRIES["oui"][1], REGISTRIES["oui"][0])
    for hex_str, vendor in parse_ieee_csv(text):
        p24 = hex_to_int(hex_str, 6)
        if p24 is None or p24 in entries:
            continue
        flags, cid = derive_flags_class(vendor, overlay)
        if p24 in malicious_set:
            flags |= F_MALICIOUS
        if p24 in rogue_hw_map:
            cid = CLASS_ID["rogue_hw_oui"]
            if rogue_hw_map[p24]:
                vendor = rogue_hw_map[p24]
        if p24 in surveillance_map:
            sname, high = surveillance_map[p24]
            f2, cid, vendor = _surv_pack(sname, high)
            flags = (flags | f2) if high else f2
        elif p24 in vehicle_map:
            cid, vendor = CLASS_ID["vehicle"], vehicle_map[p24]
        entries[p24] = (flags, cid, vendor)

    for p24 in malicious_set:
        if p24 not in entries:
            entries[p24] = (F_MALICIOUS, CLASS_ID["investigation"],
                            "Known-malicious prefix")

    for p24, override in rogue_hw_map.items():
        if p24 not in entries:
            entries[p24] = (0, CLASS_ID["rogue_hw_oui"],
                            override or "Rogue-AP hardware platform")

    for p24, (sname, high) in surveillance_map.items():
        if p24 not in entries:
            entries[p24] = _surv_pack(sname, high)

    rows = sorted(entries.items())
    return [pack_std(p, f, c, names.offset(n)) for p, (f, c, n) in rows], STRIDE_STD

def build_section_mac28(overlay, names):
    """kind=2 — MAC /28 from mam.csv."""
    entries = {}
    try:
        text = read_source("mam", REGISTRIES["mam"][1], REGISTRIES["mam"][0])
    except Exception as e:
        print(f"  WARNING: mam.csv failed: {e}", file=sys.stderr)
        return [], STRIDE_STD
    for hex_str, vendor in parse_ieee_csv(text):
        p28 = hex_to_int(hex_str, 7)
        if p28 is None or p28 in entries:
            continue
        flags, cid = derive_flags_class(vendor, overlay, base_flags=F_REG_OUI28)
        entries[p28] = (flags, cid, vendor)
    rows = sorted(entries.items())
    return [pack_std(p, f, c, names.offset(n)) for p, (f, c, n) in rows], STRIDE_STD

def build_section_mac36(overlay, names):
    """kind=3 — MAC /36 from oui36.csv. Wide record (u64 key)."""
    entries = {}
    try:
        text = read_source("oui36", REGISTRIES["oui36"][1], REGISTRIES["oui36"][0])
    except Exception as e:
        print(f"  WARNING: oui36.csv failed: {e}", file=sys.stderr)
        return [], STRIDE_WIDE
    for hex_str, vendor in parse_ieee_csv(text):
        p36 = hex_to_int(hex_str, 9)
        if p36 is None or p36 in entries:
            continue
        flags, cid = derive_flags_class(vendor, overlay, base_flags=F_REG_OUI36)
        entries[p36] = (flags, cid, vendor)
    rows = sorted(entries.items())
    return [pack_wide(p, f, c, names.offset(n)) for p, (f, c, n) in rows], STRIDE_WIDE

def build_section_iab(overlay, names):
    """kind=4 — IAB (36-bit assignments under OUI 00-50-C2). Wide record."""
    entries = {}
    try:
        text = read_source("iab", REGISTRIES["iab"][1], REGISTRIES["iab"][0])
    except Exception as e:
        print(f"  WARNING: iab.csv failed: {e}", file=sys.stderr)
        return [], STRIDE_WIDE
    for hex_str, vendor in parse_ieee_csv(text):
        p36 = hex_to_int(hex_str, 9)
        if p36 is None or p36 in entries:
            continue
        flags, cid = derive_flags_class(vendor, overlay)
        entries[p36] = (flags, cid, vendor)
    rows = sorted(entries.items())
    return [pack_wide(p, f, c, names.offset(n)) for p, (f, c, n) in rows], STRIDE_WIDE

def build_section_cid(overlay, names):
    """kind=5 — CID (Company ID, /24 private MAC space). Std record."""
    entries = {}
    try:
        text = read_source("cid", REGISTRIES["cid"][1], REGISTRIES["cid"][0])
    except Exception as e:
        print(f"  WARNING: cid.csv failed: {e}", file=sys.stderr)
        return [], STRIDE_STD
    for hex_str, vendor in parse_ieee_csv(text):
        p24 = hex_to_int(hex_str, 6)
        if p24 is None or p24 in entries:
            continue
        flags, cid = derive_flags_class(vendor, overlay, base_flags=F_REG_CID)
        entries[p24] = (flags, cid, vendor)
    rows = sorted(entries.items())
    return [pack_std(p, f, c, names.offset(n)) for p, (f, c, n) in rows], STRIDE_STD

def build_section_bt_company(overlay, names):
    """kind=10 — BT SIG company IDs."""
    yml = read_local_yaml(BT_COMPANY_YAML)
    if not yml:
        print("  bt_company: skip (yaml not found)")
        return [], STRIDE_STD

    overrides = {o["id"]: o["class"] for o in overlay.get("bt_company_overrides", [])}
    class_to_flag = {
        "investigation": F_INVESTIGATION, "maker": F_MAKER,
        "dev_module": F_DEV_MODULE, "surveillance_cam": F_SURVEILLANCE,
        "tracker": 0, "beacon": 0, "standards": F_STANDARDS, "mobile": F_MOBILE,
    }
    entries = []
    for item in yml.get("company_identifiers", []):
        cid = item.get("value")
        name = item.get("name", "")
        if cid is None or not name:
            continue
        flags, class_id = derive_flags_class(name, overlay)
        if cid in overrides:
            class_name = overrides[cid]
            if class_name in CLASS_ID:
                class_id = CLASS_ID[class_name]
            flags |= class_to_flag.get(class_name, 0)
        entries.append((cid, flags, class_id, name))

    entries.sort(key=lambda r: r[0])
    return [pack_std(c, f, cls, names.offset(n)) for c, f, cls, n in entries], STRIDE_STD

def build_section_bt_uuid16(overlay, names):
    """kind=11 — BT 16-bit UUIDs (member + service + SDO + overlay overrides)."""
    seen = {}
    for path, label in ((BT_MEMBER_YAML, "member"),
                        (BT_SERVICE_YAML, "service"),
                        (BT_SDO_YAML, "sdo")):
        yml = read_local_yaml(path)
        if not yml:
            print(f"  bt_uuid16/{label}: skip (yaml not found)")
            continue
        for item in yml.get("uuids", []):
            uuid = item.get("uuid")
            name = item.get("name", "")
            if uuid is None or not name or uuid in seen:
                continue
            flags, class_id = derive_flags_class(name, overlay)
            seen[uuid] = (flags, class_id, name)

    class_to_flag = {
        "tracker": 0, "beacon": 0, "attack_signal": 0,
        "standards": F_STANDARDS, "investigation": F_INVESTIGATION,
        "surveillance_cam": F_SURVEILLANCE,
    }
    for ov in overlay.get("uuid16_classes", []):
        uuid = ov.get("uuid")
        cname = ov.get("class")
        if uuid is None or cname not in CLASS_ID:
            continue
        prev = seen.get(uuid)

        prev_name = ov.get("name") or (prev[2] if prev else f"UUID {uuid:#06x}")
        prev_flags = prev[0] if prev else 0
        seen[uuid] = (prev_flags | class_to_flag.get(cname, 0),
                      CLASS_ID[cname], prev_name)

    rows = sorted(seen.items())
    return [pack_std(u, f, c, names.offset(n)) for u, (f, c, n) in rows], STRIDE_STD

def build_section_bt_uuid32(overlay, names):
    """kind=12 — BT 32-bit UUIDs from data/uuid32.yaml."""
    yml = read_data_yaml("uuid32.yaml")
    entries = {}
    for item in yml.get("uuids", []) or []:
        u = item.get("uuid")
        if u is None:
            continue
        if isinstance(u, str):
            try:
                u = int(u, 16)
            except ValueError:
                continue
        name = item.get("name", f"UUID32 {u:#010x}")
        flags = flags_from_list(item.get("flags"))
        class_id = class_from_name(item.get("class"))
        entries[u] = (flags, class_id, name)
    rows = sorted(entries.items())
    return [pack_std(u, f, c, names.offset(n)) for u, (f, c, n) in rows], STRIDE_STD

def build_section_vendor_ie(overlay, names):
    """kind=30 — Wi-Fi vendor IE OUIs from data/vendor_ie.yaml. std 12 B."""
    yml = read_data_yaml("vendor_ie.yaml")
    entries = {}
    for item in yml.get("ouis", []) or []:
        oui_str = (item.get("oui") or "").replace(":", "").replace("-", "")
        if len(oui_str) != 6:
            continue
        try:
            k = int(oui_str, 16)
        except ValueError:
            continue
        entries[k] = (flags_from_list(item.get("flags")),
                      class_from_name(item.get("class")),
                      item.get("name", oui_str))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

SSID_MATCH_EXACT    = 0
SSID_MATCH_PREFIX   = 1
SSID_MATCH_SUFFIX   = 2
SSID_MATCH_CONTAINS = 3
SSID_MATCH_COMPOUND = 4
SSID_MATCH_BY_NAME = {
    "exact": SSID_MATCH_EXACT,
    "prefix": SSID_MATCH_PREFIX,
    "suffix": SSID_MATCH_SUFFIX,
    "contains": SSID_MATCH_CONTAINS,
    "compound": SSID_MATCH_COMPOUND,
}

def build_section_ssid_rule(overlay, names):
    """kind=31 — SSID typed match rules from data/ssid_rules.yaml. ssid 12 B."""
    yml = read_data_yaml("ssid_rules.yaml")
    rows = []
    for item in yml.get("rules", []) or []:
        match_name = (item.get("match") or "").lower()
        mtype = SSID_MATCH_BY_NAME.get(match_name)
        if mtype is None:
            continue
        if mtype == SSID_MATCH_COMPOUND:
            prefix = item.get("compound_prefix", "") or ""
            suffix = item.get("compound_suffix", "") or ""
            if not prefix or not suffix:
                continue

            pat_off = len(names.blob)
            names.blob.extend(prefix.encode("utf-8") + b"\x00")
            names.blob.extend(suffix.encode("utf-8") + b"\x00")
            label = item.get("name") or f"{prefix}*{suffix}"
        else:
            pat = item.get("pattern", "") or ""
            if not pat:
                continue
            pat_off = names.offset(pat)

            label = item.get("name") or pat
        flags = flags_from_list(item.get("flags"))
        class_id = class_from_name(item.get("class"))
        pattern_hash = 0
        rows.append(pack_ssid(pattern_hash, flags, class_id, mtype,
                              pat_off, names.offset(label)))
    return rows, STRIDE_SSID

def build_section_ie_signature(overlay, names):
    """kind=32 — Probe-req IE-order fingerprint from data/ie_signatures.yaml.

    Hash = FNV-1a over the ordered IE type ID bytes. Mirrors
    main/frame_parser.c::parse_ies() so the runtime sees the same key.
    """
    yml = read_data_yaml("ie_signatures.yaml")
    entries = {}
    for item in yml.get("signatures", []) or []:
        order = item.get("ie_order") or []
        if not order:
            continue
        try:
            ie_bytes = bytes(int(x) & 0xFF for x in order)
        except (TypeError, ValueError):
            continue
        key = fnv1a32(ie_bytes)
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class")),
                        item.get("name", f"sig:{key:08x}"))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_wps_mfg(overlay, names):
    """kind=33 — WPS manufacturer string hash from data/wps_strings.yaml."""
    yml = read_data_yaml("wps_strings.yaml")
    entries = {}
    for item in yml.get("strings", []) or []:
        mfg = item.get("mfg", "")
        if not mfg:
            continue
        key = fnv1a32_str_lower(mfg)
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class")),
                        item.get("name", mfg))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_rsn_oui(overlay, names):
    """kind=34 — RSN cipher OUI + suite type (static IEEE 802.11)."""

    base_8021 = 0x000FAC
    base_wpa  = 0x0050F2
    entries = []
    for suite, name in [
        (0, "Use Group Cipher"),
        (1, "WEP-40"),
        (2, "TKIP"),
        (3, "Reserved (RSN)"),
        (4, "CCMP-128 (AES)"),
        (5, "WEP-104"),
        (6, "BIP-CMAC-128"),
        (7, "Group not allowed"),
        (8, "GCMP-128"),
        (9, "GCMP-256"),
        (10, "CCMP-256"),
        (11, "BIP-GMAC-128"),
        (12, "BIP-GMAC-256"),
        (13, "BIP-CMAC-256"),
    ]:
        key = (base_8021 << 8) | suite
        entries.append((key, 0, CLASS_ID["standards"], name))
    for suite, name in [
        (1, "WEP-40 (WPA legacy)"),
        (2, "TKIP (WPA legacy)"),
        (4, "CCMP (WPA legacy)"),
    ]:
        key = (base_wpa << 8) | suite
        entries.append((key, 0, CLASS_ID["standards"], name))
    entries.sort(key=lambda r: r[0])
    return [pack_std(k, f, c, names.offset(n)) for k, f, c, n in entries], STRIDE_STD

def build_section_country(overlay, names):
    """kind=35 — ISO 3166-1 alpha-2 country codes (tiny 8 B record).
    Seed limited to common 2-letter codes that show up in 802.11 Country IEs."""
    common = [
        ("US", "United States"), ("CA", "Canada"), ("MX", "Mexico"),
        ("GB", "United Kingdom"), ("IE", "Ireland"), ("FR", "France"),
        ("DE", "Germany"), ("ES", "Spain"), ("IT", "Italy"), ("PT", "Portugal"),
        ("NL", "Netherlands"), ("BE", "Belgium"), ("LU", "Luxembourg"),
        ("CH", "Switzerland"), ("AT", "Austria"), ("DK", "Denmark"),
        ("SE", "Sweden"), ("NO", "Norway"), ("FI", "Finland"), ("IS", "Iceland"),
        ("PL", "Poland"), ("CZ", "Czechia"), ("SK", "Slovakia"), ("HU", "Hungary"),
        ("RO", "Romania"), ("BG", "Bulgaria"), ("GR", "Greece"), ("HR", "Croatia"),
        ("SI", "Slovenia"), ("EE", "Estonia"), ("LV", "Latvia"), ("LT", "Lithuania"),
        ("UA", "Ukraine"), ("RU", "Russia"), ("TR", "Turkey"),
        ("CN", "China"), ("HK", "Hong Kong"), ("TW", "Taiwan"), ("JP", "Japan"),
        ("KR", "Korea"), ("IN", "India"), ("ID", "Indonesia"),
        ("AU", "Australia"), ("NZ", "New Zealand"), ("SG", "Singapore"),
        ("MY", "Malaysia"), ("TH", "Thailand"), ("VN", "Vietnam"), ("PH", "Philippines"),
        ("BR", "Brazil"), ("AR", "Argentina"), ("CL", "Chile"), ("CO", "Colombia"),
        ("ZA", "South Africa"), ("EG", "Egypt"), ("AE", "UAE"), ("SA", "Saudi Arabia"),
        ("IL", "Israel"),
    ]
    entries = []
    for cc, name in common:
        key = (ord(cc[0]) << 8) | ord(cc[1])
        entries.append((key, 0, CLASS_ID["unknown"], name))
    entries.sort(key=lambda r: r[0])
    return [pack_tiny(k, f, c, names.offset(n)) for k, f, c, n in entries], STRIDE_TINY

def build_section_drone_mfr(overlay, names):
    """kind=60 — ASTM Remote ID / CTA-2063-A 4-char manufacturer code -> make.
    Key is the 4 ASCII chars packed big-endian into a u32 (matches
    eui_lookup_drone_mfr() in eui_db.c). Empty until data/drone_mfr.yaml is
    populated; the firmware always surfaces the raw code regardless."""
    yml = read_data_yaml("drone_mfr.yaml")
    entries = {}
    for item in yml.get("codes", []) or []:
        code = (item.get("code") or "").strip()
        if len(code) != 4 or not code.isalnum() or not code.isascii():
            continue
        key = (ord(code[0]) << 24) | (ord(code[1]) << 16) | \
              (ord(code[2]) << 8) | ord(code[3])
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class") or "drone"),
                        item.get("name", code))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def _build_org_oui_section(yml_key, source_yml, names):
    yml = read_data_yaml(source_yml)
    entries = {}
    for item in yml.get(yml_key, []) or []:
        oui_str = (item.get("oui") or "").replace(":", "").replace("-", "")
        if len(oui_str) != 6: continue
        try:
            k = int(oui_str, 16)
        except ValueError:
            continue
        entries[k] = (flags_from_list(item.get("flags")),
                      class_from_name(item.get("class")),
                      item.get("name", oui_str))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_cdp_org(overlay, names):
    return _build_org_oui_section("cdp_org_ouis", "cdp_lldp_org.yaml", names)

def build_section_lldp_org(overlay, names):
    return _build_org_oui_section("lldp_org_ouis", "cdp_lldp_org.yaml", names)

def build_section_dhcp_vc(overlay, names):
    """kind=42 — DHCP Option 60 vendor class hash."""
    yml = read_data_yaml("dhcp_fingerprints.yaml")
    entries = {}
    for item in yml.get("option_60_strings", []) or []:
        vc = item.get("vc", "")
        if not vc: continue
        key = fnv1a32_str_lower(vc)
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class")),
                        item.get("name", vc))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_dhcp_fp(overlay, names):
    """kind=43 — DHCP Option 55 PRL byte sequence hash."""
    yml = read_data_yaml("dhcp_fingerprints.yaml")
    entries = {}
    for item in yml.get("option_55_fingerprints", []) or []:
        prl = item.get("prl") or []
        if not prl: continue
        prl_bytes = bytes(b & 0xFF for b in prl)
        key = fnv1a32(prl_bytes)
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class")),
                        item.get("name", ""))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_fcc_grantee(overlay, names):
    """kind=50 — FCC Grantee Code (first 3 ASCII chars packed into u32)."""
    yml = read_data_yaml("fcc_ids.yaml")
    entries = {}
    for item in yml.get("grantees", []) or []:
        code = item.get("code", "")
        if len(code) < 3:
            continue
        g3 = code[:3]
        key = (ord(g3[0]) << 16) | (ord(g3[1]) << 8) | ord(g3[2])

        if key in entries:
            continue
        entries[key] = (flags_from_list(item.get("flags")),
                        class_from_name(item.get("class")),
                        item.get("name", code))
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_fcc_covered(overlay, names):
    """kind=51 — FCC Covered List entity name hash."""
    entries = {}
    for name in overlay.get("covered_list", []) or []:
        key = fnv1a32_str_lower(name)
        entries[key] = (F_FCC_COVERED, CLASS_ID["unknown"], name)
    rows = sorted(entries.items())
    return [pack_std(k, f, c, names.offset(n)) for k, (f, c, n) in rows], STRIDE_STD

def build_section_apple_subtype(overlay, names):
    """kind=21 — Apple Continuity subtype byte (tiny 8 B record)."""
    yml = read_data_yaml("apple_continuity.yaml")
    entries = {}
    for item in yml.get("subtypes", []) or []:
        st = item.get("subtype")
        if st is None: continue
        if isinstance(st, str): st = int(st, 16)
        entries[st & 0xFF] = (flags_from_list(item.get("flags")),
                              class_from_name(item.get("class")),
                              item.get("name", ""))
    rows = sorted(entries.items())
    return [pack_tiny(s, f, c, names.offset(n)) for s, (f, c, n) in rows], STRIDE_TINY

def build_section_ms_subtype(overlay, names):
    """kind=22 — Microsoft CDP / Swift Pair subtype byte."""
    yml = read_data_yaml("ms_cdp.yaml")
    entries = {}
    for item in yml.get("subtypes", []) or []:
        st = item.get("subtype")
        if st is None: continue
        if isinstance(st, str): st = int(st, 16)
        entries[st & 0xFF] = (flags_from_list(item.get("flags")),
                              class_from_name(item.get("class")),
                              item.get("name", ""))
    rows = sorted(entries.items())
    return [pack_tiny(s, f, c, names.offset(n)) for s, (f, c, n) in rows], STRIDE_TINY

def build_section_fast_pair(overlay, names):
    """kind=23 — Google Fast Pair model ID (24-bit) → std record."""
    yml = read_data_yaml("fast_pair.yaml")
    entries = {}
    for item in yml.get("models", []) or []:
        mid = item.get("model_id")
        if mid is None: continue
        if isinstance(mid, str): mid = int(mid, 16)
        entries[mid & 0xFFFFFF] = (flags_from_list(item.get("flags")),
                                    class_from_name(item.get("class")),
                                    item.get("name", ""))
    rows = sorted(entries.items())
    return [pack_std(m, f, c, names.offset(n)) for m, (f, c, n) in rows], STRIDE_STD

def build_section_name_rule(overlay, names):
    """kind=24 — BLE local-name substring rules (ssid-style record).
    pattern_hash is set to 0 — runtime walks linearly. pattern_off points at
    the lowercased token in the names blob.

    Hard-match-only enforcement: surveillance / pentest_tool classes refuse
    short tokens. The rule keeps its flags but is downgraded
    to class=unknown so a generic substring can't paint a device with a
    security-loaded label."""
    yml = read_data_yaml("name_rules.yaml")
    rows = []
    for item in yml.get("rules", []) or []:
        token = (item.get("token") or "").lower()
        if not token: continue
        flags = flags_from_list(item.get("flags"))

        class_name = item.get("device_class") or item.get("class")
        class_id = class_from_name(class_name)
        if class_id in HARD_MATCH_CLASS_IDS and len(token) < HARD_MATCH_MIN_TOKEN_LEN:
            print(f"  WARNING: name_rules token {token!r} is too short "
                  f"({len(token)} < {HARD_MATCH_MIN_TOKEN_LEN}) for hard-match class "
                  f"{class_name!r}; downgrading class to unknown",
                  file=sys.stderr)
            class_id = CLASS_ID["unknown"]
        name = item.get("name", token)

        NAME_RULE_KIND_GENERIC = 0
        NAME_RULE_KIND_PHONE_MODEL = 1
        is_phone_model = (class_id in (CLASS_ID["phone"], CLASS_ID["tablet"])
                          and not item.get("make_only"))
        kind = NAME_RULE_KIND_PHONE_MODEL if is_phone_model else NAME_RULE_KIND_GENERIC
        rows.append(pack_ssid(0, flags, class_id, kind,
                              names.offset(token), names.offset(name)))
    return rows, STRIDE_SSID

def build_section_mfg_rule(overlay, names):
    """kind=20 — BLE mfg-data byte-prefix catalog from data/ble_catalog.yaml."""
    yml = read_data_yaml("ble_catalog.yaml")
    rows = []
    for item in yml.get("rules", []) or []:
        cid = item.get("company_id")
        if cid is None:
            continue
        prefix_hex = item.get("mfg_prefix_hex", "") or ""
        try:
            prefix_bytes = bytes.fromhex(prefix_hex)
        except ValueError:
            print(f"  WARNING: catalog rule {item.get('id')} bad prefix_hex {prefix_hex!r}",
                  file=sys.stderr)
            continue
        if len(prefix_bytes) > 6:
            print(f"  WARNING: catalog rule {item.get('id')} prefix > 6 bytes; truncating",
                  file=sys.stderr)
            prefix_bytes = prefix_bytes[:6]
        name = item.get("name") or item.get("id", "")
        if not name:
            continue
        rule_id = item.get("id", name)
        flags = flags_from_list(item.get("flags"))
        class_name = require_device_class(rule_id, item, "ble_catalog.yaml")
        class_id = CLASS_ID[class_name]
        validate_device_subtype(rule_id, class_name, item.get("device_subtype"))
        subtype = int(item.get("subtype", 0)) & 0xFF
        key_hash = fnv1a32(struct.pack("<H", cid) + prefix_bytes)
        rows.append(pack_rule(key_hash, cid, prefix_bytes, flags, class_id,
                              subtype, names.offset(name)))
    return rows, STRIDE_RULE

def build_section_bt_uuid128(overlay, names):
    """kind=13 — BT 128-bit UUIDs from data/uuid128.yaml. Wide 24 B record."""
    yml = read_data_yaml("uuid128.yaml")
    entries = []
    for item in yml.get("uuids", []) or []:
        b = uuid128_bytes(item.get("uuid", ""))
        if b is None:
            continue
        name = item.get("name", "")
        if not name:
            continue
        flags = flags_from_list(item.get("flags"))
        class_id = class_from_name(item.get("class"))
        entries.append((b, flags, class_id, name))
    entries.sort(key=lambda r: r[0])
    return [pack_uuid128(b, f, c, names.offset(n)) for b, f, c, n in entries], STRIDE_UUID128

def pack(sections, names, output_path):
    """sections: list of (kind, stride, packed_record_bytes_list)."""
    section_count = len(sections)
    header_size = 32 + section_count * 16 + 8

    section_table = []
    section_buf = bytearray()
    cursor = header_size
    for kind, stride, rows in sections:
        section_table.append((kind, cursor, len(rows), stride))
        for rec in rows:
            assert len(rec) == stride, f"kind={kind} record len {len(rec)} != stride {stride}"
            section_buf.extend(rec)
        cursor += len(rows) * stride

    names_off = cursor
    names_blob = bytes(names.blob)

    header = bytearray()
    header.extend(struct.pack("<8sIQI8s",
                              MAGIC, VERSION, int(time.time()), section_count,
                              b"\x00" * 8))
    for kind, offset, count, stride in section_table:
        header.extend(struct.pack("<IIII", kind, offset, count, stride))
    header.extend(struct.pack("<II", names_off, len(names_blob)))
    assert len(header) == header_size, f"header {len(header)} != expected {header_size}"

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(section_buf)
        f.write(names_blob)

    total = len(header) + len(section_buf) + len(names_blob)
    print(f"\ngen_eui: wrote {output_path}")
    print(f"  header:    {len(header)} B")
    print(f"  sections:  {len(section_buf)} B  ({section_count} sections)")
    print(f"  names:     {len(names_blob)} B  ({len(names.offsets)} unique)")
    print(f"  total:     {total/1024:.1f} KB")

    if total > 2_800_000:
        print(f"\n  ERROR: total {total} B exceeds 2.7 MB safety threshold",
              file=sys.stderr)
        sys.exit(1)

def sanity_check(sections_by_kind, names_table):
    """Confirm fixture entries landed in correct sections with expected flags."""
    print("\ngen_eui: sanity asserts")

    def find(kind, target_key, stride):
        rows = sections_by_kind.get(kind, [])
        for rec in rows:
            if stride == STRIDE_STD:
                k, f, c, _r, _no = struct.unpack("<IHBBI", rec)
            elif stride == STRIDE_WIDE:
                k, f, c, _r, _no = struct.unpack("<QHBBI", rec)
            else:
                continue
            if k == target_key:
                return (f, c)
        return None

    def find_uuid128(target_hex):
        target = bytes.fromhex(target_hex.replace("-", ""))
        for rec in sections_by_kind.get(SECTION_BT_UUID128, []):
            key, f, c, _r, _no = struct.unpack("<16sHBBI", rec)
            if key == target:
                return (f, c)
        return None

    fixtures = [
        ("Flock Safety OUI B4:1E:52 (kind=1)",
         find(SECTION_MAC24, 0xB41E52, STRIDE_STD),
         lambda r: r and (r[0] & F_SURVEILLANCE)),
        ("Flipper OUI 0C:FA:22 (kind=1)",
         find(SECTION_MAC24, 0x0CFA22, STRIDE_STD),
         lambda r: r and (r[0] & F_INVESTIGATION)),
        ("Espressif OUI 10:06:1C (kind=1)",
         find(SECTION_MAC24, 0x10061C, STRIDE_STD),
         lambda r: r and (r[0] & F_DEV_MODULE)),
        ("Adafruit OUI 98:76:B6 (kind=1)",
         find(SECTION_MAC24, 0x9876B6, STRIDE_STD),
         lambda r: r and (r[0] & F_MAKER)),
        ("00:13:37 rogue-hw evidence, NOT malicious (kind=1)",
         find(SECTION_MAC24, 0x001337, STRIDE_STD),
         lambda r: r and not (r[0] & F_MALICIOUS)
                   and r[1] == CLASS_ID["rogue_hw_oui"]),
        ("Raspberry Pi B8:27:EB rogue-hw evidence, NOT malicious (kind=1)",
         find(SECTION_MAC24, 0xB827EB, STRIDE_STD),
         lambda r: r and not (r[0] & F_MALICIOUS)
                   and r[1] == CLASS_ID["rogue_hw_oui"]),
        ("Nordic UART UUID128 (kind=13)",
         find_uuid128("6E400001B5A3F393E0A9E50E24DCCA9E"),
         lambda r: r and r[1] == CLASS_ID["dev_module"]),
        ("Tile FEED-expanded UUID128 (kind=13)",
         find_uuid128("0000FEED00001000800000805F9B34FB"),
         lambda r: r and r[1] == CLASS_ID["tracker"]),
        ("Matter FFF6-expanded UUID128 (kind=13)",
         find_uuid128("0000FFF600001000800000805F9B34FB"),
         lambda r: r and r[1] == CLASS_ID["standards"]),

        ("Ford OUI 00:76:B6 (kind=1)",
         find(SECTION_MAC24, 0x0076B6, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["vehicle"]),
        ("Tesla company 0x022B (kind=10)",
         find(SECTION_BT_COMPANY, 0x022B, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["vehicle"]),
        ("Tesla member UUID 0xFE97 (kind=11)",
         find(SECTION_BT_UUID16, 0xFE97, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["vehicle"]),
        ("CCC Digital Key UUID 0xFFF5 (kind=11)",
         find(SECTION_BT_UUID16, 0xFFF5, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["vehicle"]),
    ]

    def find_rule(cid, prefix_hex):
        prefix = bytes.fromhex(prefix_hex) if prefix_hex else b""
        for rec in sections_by_kind.get(SECTION_MFG_RULE, []):
            kh, rec_cid, plen, p6, _pad, f, c, st, _no = struct.unpack("<IHB6s3sHBBI", rec)
            if rec_cid != cid: continue
            if plen != len(prefix): continue
            if p6[:plen] != prefix: continue
            return (f, c, st)
        return None

    def find_tiny(kind, target):
        for rec in sections_by_kind.get(kind, []):
            k, f, c, _r, _pad, _no = struct.unpack("<HHBBHI", rec)
            if k == target:
                return (f, c)
        return None

    def find_ssid_pattern(kind, expected_lower):
        names_blob = bytes(names_table.blob)
        for rec in sections_by_kind.get(kind, []):
            pat_off, _no, f, c, mt, _r = struct.unpack("<IIHBBI", rec)
            end = names_blob.find(b"\x00", pat_off)
            pat = names_blob[pat_off:end].decode("utf-8", "replace").lower()
            if pat == expected_lower:
                return (f, c, mt)
        return None

    def find_name_token(kind, token_lower):
        names_blob = bytes(names_table.blob)
        for rec in sections_by_kind.get(kind, []):
            pat_off, _no, f, c, mt, _r = struct.unpack("<IIHBBI", rec)
            end = names_blob.find(b"\x00", pat_off)
            tok = names_blob[pat_off:end].decode("utf-8", "replace").lower()
            if tok == token_lower:
                return (f, c, mt)
        return None

    def name_first_match(kind, full_name):

        names_blob = bytes(names_table.blob)
        hay = full_name.lower()
        for rec in sections_by_kind.get(kind, []):
            pat_off, name_off, f, c, _mt, _r = struct.unpack("<IIHBBI", rec)
            tok = names_blob[pat_off:names_blob.find(b"\x00", pat_off)] \
                .decode("utf-8", "replace").lower()
            if tok and tok in hay:
                label = names_blob[name_off:names_blob.find(b"\x00", name_off)] \
                    .decode("utf-8", "replace")
                return (label, c)
        return None

    fixtures.extend([

        ("Name 'John's iPhone 15 Pro' → iPhone 15 Pro (kind=24)",
         name_first_match(SECTION_NAME_RULE, "John's iPhone 15 Pro"),
         lambda r: r and r[0] == "iPhone 15 Pro" and r[1] == CLASS_ID["phone"]),
        ("Name 'Pixel 9 Pro' → Pixel 9 Pro (kind=24)",
         name_first_match(SECTION_NAME_RULE, "Pixel 9 Pro"),
         lambda r: r and r[0] == "Pixel 9 Pro" and r[1] == CLASS_ID["phone"]),
        ("Name 'Galaxy S24 Ultra' → Samsung Galaxy S24 Ultra (kind=24)",
         name_first_match(SECTION_NAME_RULE, "Galaxy S24 Ultra"),
         lambda r: r and r[0] == "Samsung Galaxy S24 Ultra"
                     and r[1] == CLASS_ID["phone"]),
        ("Name \"Dad's iPhone\" → generic iPhone make (kind=24)",
         name_first_match(SECTION_NAME_RULE, "Dad's iPhone"),
         lambda r: r and r[0] == "iPhone" and r[1] == CLASS_ID["phone"]),

        ("Name kind: 'iphone 15 pro' is PHONE_MODEL (kind=24 mt=1)",
         find_name_token(SECTION_NAME_RULE, "iphone 15 pro"),
         lambda r: r and r[2] == 1),
        ("Name kind: 'galaxy s24 ultra' is PHONE_MODEL (kind=24 mt=1)",
         find_name_token(SECTION_NAME_RULE, "galaxy s24 ultra"),
         lambda r: r and r[2] == 1),
        ("Name kind: generic 'iphone' is make-only (kind=24 mt=0)",
         find_name_token(SECTION_NAME_RULE, "iphone"),
         lambda r: r and r[2] == 0),
        ("Name kind: 'ipad' make-only (kind=24 mt=0)",
         find_name_token(SECTION_NAME_RULE, "ipad"),
         lambda r: r and r[2] == 0),
        ("AirTag rule (cid=0x004C prefix=1219)",
         find_rule(0x004C, "1219"),
         lambda r: r and r[1] == CLASS_ID["tracker"]),
        ("Flipper rule (cid=0x0E29)",
         find_rule(0x0E29, ""),
         lambda r: r and (r[0] & F_INVESTIGATION)),
        ("Hikvision rule (cid=0x0220)",
         find_rule(0x0220, ""),
         lambda r: r and (r[0] & F_FCC_COVERED)),
        ("Apple subtype 0x12 → tracker (kind=21)",
         find_tiny(SECTION_APPLE_SUBTYPE, 0x12),
         lambda r: r and r[1] == CLASS_ID["tracker"]),
        ("MS subtype 0x03 → Swift Pair (kind=22)",
         find_tiny(SECTION_MS_SUBTYPE, 0x03),
         lambda r: r and r[1] == CLASS_ID["mobile"]),
        ("Country US (kind=35)",
         find_tiny(SECTION_COUNTRY, (ord("U") << 8) | ord("S")),
         lambda r: r is not None),
        ("Fast Pair Pixel Buds A (kind=23)",
         find(SECTION_FAST_PAIR, 0x000007, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["audio"]),
        ("Vendor IE 00:50:F2 Microsoft (kind=30)",
         find(SECTION_VENDOR_IE, 0x0050F2, STRIDE_STD),
         lambda r: r is not None),
        ("CDP org 00:00:0C Cisco (kind=40)",
         find(SECTION_CDP_ORG, 0x00000C, STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["enterprise_ap"]),
        ("LLDP org 00:12:BB TIA (kind=41)",
         find(SECTION_LLDP_ORG, 0x0012BB, STRIDE_STD),
         lambda r: r is not None),
        ("DHCP VC 'MSFT 5.0' (kind=42)",
         find(SECTION_DHCP_VC, fnv1a32_str_lower("MSFT 5.0"), STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["laptop"]),
        ("DHCP FP Windows 10/11 PRL (kind=43)",
         find(SECTION_DHCP_FP,
              fnv1a32(bytes([1,3,6,15,31,33,43,44,46,47,119,121,249,252])),
              STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["laptop"]),
        ("FCC Grantee BCG → Apple (kind=50)",
         find(SECTION_FCC_GRANTEE,
              (ord('B') << 16) | (ord('C') << 8) | ord('G'),
              STRIDE_STD),
         lambda r: r and r[1] == CLASS_ID["mobile"]),
        ("FCC Covered Huawei (kind=51)",
         find(SECTION_FCC_COVERED, fnv1a32_str_lower("Huawei"), STRIDE_STD),
         lambda r: r and (r[0] & F_FCC_COVERED)),
        ("SSID rule 'Starbucks WiFi' (kind=31)",
         find_ssid_pattern(SECTION_SSID_RULE, "starbucks wifi"),
         lambda r: r and r[2] == 0),
        ("Name rule 'flipper' (kind=24)",
         find_name_token(SECTION_NAME_RULE, "flipper"),
         lambda r: r and (r[0] & F_INVESTIGATION)),
        ("Name rule 'cu7000' → Samsung TV (kind=24)",
         find_name_token(SECTION_NAME_RULE, "cu7000"),
         lambda r: r and r[1] == CLASS_ID["iot_appliance"]),
        ("IE sig Flipper Zero (kind=32)",
         find(SECTION_IE_SIGNATURE,
              fnv1a32(bytes([0, 1, 50, 3, 221])),
              STRIDE_STD),
         lambda r: r and (r[0] & F_INVESTIGATION)),
        ("IE sig ESP32 minimal (kind=32)",
         find(SECTION_IE_SIGNATURE,
              fnv1a32(bytes([0, 1, 50, 3, 45, 127])),
              STRIDE_STD),
         lambda r: r and (r[0] & F_DEV_MODULE)),
    ])

    failed = 0
    for label, result, predicate in fixtures:
        ok = predicate(result)
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{status}] {label}: {result}")

    if failed:
        print(f"\n{failed} fixture(s) failed", file=sys.stderr)
        sys.exit(1)

def main():
    print("gen_eui v3: loading overlay")
    with open(OVERLAY_PATH, "r", encoding="utf-8") as f:
        overlay = yaml.safe_load(f)

    names = NameTable()
    sections = []
    by_kind = {}

    builders = [
        ("MAC /24",    SECTION_MAC24,      build_section_mac24),
        ("MAC /28",    SECTION_MAC28,      build_section_mac28),
        ("MAC /36",    SECTION_MAC36,      build_section_mac36),
        ("IAB",        SECTION_IAB,        build_section_iab),
        ("CID",        SECTION_CID,        build_section_cid),
        ("BT CID",     SECTION_BT_COMPANY, build_section_bt_company),
        ("BT UUID16",  SECTION_BT_UUID16,  build_section_bt_uuid16),
        ("BT UUID32",  SECTION_BT_UUID32,  build_section_bt_uuid32),
        ("BT UUID128", SECTION_BT_UUID128, build_section_bt_uuid128),
        ("Mfg rule",   SECTION_MFG_RULE,   build_section_mfg_rule),
        ("Apple sub",  SECTION_APPLE_SUBTYPE, build_section_apple_subtype),
        ("MS sub",     SECTION_MS_SUBTYPE, build_section_ms_subtype),
        ("Fast Pair",  SECTION_FAST_PAIR,  build_section_fast_pair),
        ("Name rule",  SECTION_NAME_RULE,  build_section_name_rule),
        ("Vendor IE",  SECTION_VENDOR_IE,  build_section_vendor_ie),
        ("SSID rule",  SECTION_SSID_RULE,  build_section_ssid_rule),
        ("IE sig",     SECTION_IE_SIGNATURE, build_section_ie_signature),
        ("WPS mfg",    SECTION_WPS_MFG,    build_section_wps_mfg),
        ("RSN OUI",    SECTION_RSN_OUI,    build_section_rsn_oui),
        ("Country",    SECTION_COUNTRY,    build_section_country),
        ("CDP org",    SECTION_CDP_ORG,    build_section_cdp_org),
        ("LLDP org",   SECTION_LLDP_ORG,   build_section_lldp_org),
        ("DHCP VC",    SECTION_DHCP_VC,    build_section_dhcp_vc),
        ("DHCP FP",    SECTION_DHCP_FP,    build_section_dhcp_fp),
        ("FCC grantee", SECTION_FCC_GRANTEE, build_section_fcc_grantee),
        ("FCC covered", SECTION_FCC_COVERED, build_section_fcc_covered),
        ("Drone mfr",  SECTION_DRONE_MFR,  build_section_drone_mfr),
    ]

    for label, kind, fn in builders:
        print(f"\ngen_eui: building {label} (kind={kind})")
        rows, stride = fn(overlay, names)
        print(f"  {label}: {len(rows)} entries, stride {stride}")
        sections.append((kind, stride, rows))
        by_kind[kind] = rows

    sanity_check(by_kind, names)
    pack(sections, names, OUTPUT_PATH)
    print("gen_eui: done")

if __name__ == "__main__":
    main()
