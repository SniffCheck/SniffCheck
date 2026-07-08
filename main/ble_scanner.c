#include "ble_scanner.h"
#include "ble_adv_ring.h"
#include "apple_continuity.h"
#include "analyzer.h"
#include "eui_db.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"

#include "store/config/ble_store_config.h"
#include <string.h>
#include <math.h>
#include <ctype.h>

void ble_store_config_init(void);

static const char *TAG = "sc_ble";

static SemaphoreHandle_t s_sync_sem;
static SemaphoreHandle_t s_done_sem;
static ble_results_t    *s_results;

static void host_task(void *arg)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void on_sync(void)
{
    xSemaphoreGive(s_sync_sem);
}

static void on_reset(int reason)
{
    ESP_LOGE(TAG, "host reset: %d", reason);
}

static ble_addr_subtype_t classify_addr(uint8_t nimble_type, const uint8_t *addr_be)
{
    if (nimble_type == BLE_ADDR_PUBLIC) return BLE_ADDR_SUB_PUBLIC;

    switch (addr_be[0] & 0xC0) {
    case 0xC0: return BLE_ADDR_SUB_STATIC_RANDOM;
    case 0x40: return BLE_ADDR_SUB_RPA;
    default:   return BLE_ADDR_SUB_NRPA;
    }
}

#define BLE_REF_1M_RSSI    -59
#define BLE_DIST_CAP_DM    1000
#define BLE_PATHLOSS_DEN   25.0f 

static uint16_t estimate_distance_dm(int8_t tx_power, int8_t rssi)
{
    int16_t ref = (tx_power == 127)
                ? BLE_REF_1M_RSSI
                : (int16_t)tx_power + BLE_REF_1M_RSSI;
    if (ref >   0) ref =   0;
    if (ref < -127) ref = -127;

    float dm = powf(10.0f, (float)(ref - rssi) / BLE_PATHLOSS_DEN) * 10.0f;
    if (dm < 0.0f) return 0xFFFF;
    if (dm > (float)BLE_DIST_CAP_DM) dm = (float)BLE_DIST_CAP_DM;
    return (uint16_t)(dm + 0.5f);
}

const char *ble_proximity_label(uint16_t distance_dm)
{
    if (distance_dm == 0xFFFF) return "Dist unknown";
    if (distance_dm < 10)  return "Very close";
    if (distance_dm < 50)  return "Near";
    if (distance_dm < 150) return "In room";
    return "Far";
}

static bool is_seos_name(const char *name)
{
    static const char key[] = "seos";
    if (!name || !name[0]) return false;
    for (int i = 0; i < 4; i++) {
        if (!name[i]) return false;
        if ((char)tolower((unsigned char)name[i]) != key[i]) return false;
    }
    return name[4] == '\0';
}

#define BLE_Q88_ONE 256u
static inline uint16_t ble_q88_mul(uint16_t a, uint16_t b)
{
    return (uint16_t)(((uint32_t)a * (uint32_t)b) >> 8);
}

#define BLE_TRUST_PUBLIC_ANON    230u
#define BLE_TRUST_NO_MFG         243u
#define BLE_TRUST_NO_NAME_HID    230u
#define BLE_TRUST_RECOGNIZED     269u
#define BLE_TRUST_STANDARDS_POS  272u

static void score_ble_device(ble_device_t *d)
{
    if (d->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) {
        d->base_quality   = 0;
        d->trust_q88      = 0;
        d->identity_score = 0;
        d->identity_conf  = 0;
        d->threat_level   = THREAT_HIGH;
        return;
    }

    uint16_t uuid_flags_or = 0;
    uint8_t  uuid16_class = EUI_CLASS_UNKNOWN;
    const char *uuid16_name = NULL;
    bool tracker_uuid = false, beacon_uuid = false, attack_uuid = false;
    for (uint8_t i = 0; i < d->num_uuids16; i++) {
        uint16_t u = d->uuids16[i];
        uint16_t f = 0;
        uint8_t  c = EUI_CLASS_UNKNOWN;
        const char *name = eui_lookup_uuid16(u, &f, &c);
        uuid_flags_or |= f;
        if (!uuid16_class && c) {
            uuid16_class = c;
            if (name) uuid16_name = name;
        } else if (!uuid16_name && name) {
            uuid16_name = name;
        }
        if (c == EUI_CLASS_TRACKER)        tracker_uuid = true;
        if (c == EUI_CLASS_BEACON)         beacon_uuid  = true;
        if (c == EUI_CLASS_ATTACK_SIGNAL)  attack_uuid  = true;
    }
    d->uuid16_flags = uuid_flags_or;
    d->uuid16_class = uuid16_class;
    d->uuid16_name = uuid16_name;

    bool catalog_tracker = (d->mfg_rule_class == EUI_CLASS_TRACKER);
    bool airtag = catalog_tracker && d->mfg_company_id == 0x004C &&
                  d->mfg_payload[0] == 0x12 && d->mfg_payload[1] == 0x19;
    d->is_airtag = airtag;
    if (airtag && !d->name[0]) {
        strlcpy(d->name, "Find My tag", sizeof(d->name));
    }

    bool find_my_short = (d->mfg_company_id == 0x004C &&
                          d->mfg_payload[0] == 0x12 &&
                          d->mfg_payload[1] != 0x19);
    bool tracker_high  = tracker_uuid || (catalog_tracker && !find_my_short);
    bool tracker_low   = catalog_tracker && find_my_short;

    if (d->mfg_company_id != 0xFFFF) {
        uint16_t cflags = 0;
        uint8_t  cclass = EUI_CLASS_UNKNOWN;
        const char *cname = eui_lookup_company(d->mfg_company_id, &cflags, &cclass);
        if (cname) {
            strlcpy(d->company_name, cname, sizeof(d->company_name));
            d->bt_company_flags = cflags;
            d->bt_company_class = cclass;
        }
    }

    if (d->name[0]) {
        d->name_rule_name = eui_match_name(d->name,
                                            &d->name_rule_flags,
                                            &d->name_rule_class,
                                            &d->name_rule_kind);
    }

    if (is_seos_name(d->name) && !d->is_airtag) {
        strlcpy(d->company_name, "ASSA ABLOY (Seos)", sizeof(d->company_name));
        if (!d->vendor[0]) {
            strlcpy(d->vendor, "HID Global", sizeof(d->vendor));
        }
    }

    uint16_t combined = d->eui_flags | d->bt_company_flags |
                        d->mfg_rule_flags | d->uuid128_flags |
                        d->name_rule_flags | d->apple_subtype_flags |
                        d->ms_subtype_flags | d->uuid32_flags |
                        d->fastpair_flags | uuid_flags_or;

    uint16_t base = 0;
    if (combined & EUI_FLAG_STANDARDS) base += 30;
    if (d->device_class != EUI_CLASS_UNKNOWN && d->vendor[0]) base += 25;
    else if (d->vendor[0]) base += 18;
    if (d->company_name[0]) base += 20;
    if (d->mfg_rule_name)   base += 20;
    if (d->uuid16_class)    base += 15;
    if (d->name[0]) base += 15;
    if (d->apple_subtype_name || d->ms_subtype_name) base += 10;
    if (d->scannable && d->name[0]) base += 10;
    if (base > 100) base = 100;
    d->base_quality = (uint8_t)base;

    uint16_t t = BLE_Q88_ONE;
    if (d->addr_subtype == BLE_ADDR_SUB_PUBLIC && !d->vendor[0])
        t = ble_q88_mul(t, BLE_TRUST_PUBLIC_ANON);
    if (d->mfg_company_id == 0xFFFF)
        t = ble_q88_mul(t, BLE_TRUST_NO_MFG);
    if (!d->scannable && !d->name[0])
        t = ble_q88_mul(t, BLE_TRUST_NO_NAME_HID);

    if (d->name[0] && d->vendor[0] && d->device_class != EUI_CLASS_UNKNOWN)
        t = ble_q88_mul(t, BLE_TRUST_RECOGNIZED);
    if (combined & EUI_FLAG_STANDARDS)
        t = ble_q88_mul(t, BLE_TRUST_STANDARDS_POS);
    if (t < 64)  t = 64;
    if (t > 333) t = 333;
    d->trust_q88 = t;

    bool notable =
        (combined & (EUI_FLAG_INVESTIGATION | EUI_FLAG_FCC_COVERED |
                     EUI_FLAG_DEV_MODULE | EUI_FLAG_MAKER |
                     EUI_FLAG_SURVEILLANCE)) != 0 ||
        attack_uuid || beacon_uuid ||
        d->uuid128_class == EUI_CLASS_INVESTIGATION ||
        d->uuid128_class == EUI_CLASS_SURVEILLANCE_CAM ||
        d->name_rule_class == EUI_CLASS_INVESTIGATION;

    uint16_t concerning = EUI_FLAG_KNOWN_MALICIOUS | EUI_FLAG_INVESTIGATION |
                          EUI_FLAG_SURVEILLANCE    | EUI_FLAG_FCC_COVERED;

    d->suppressed = (d->base_quality == 0 && !notable &&
                     (combined & concerning) == 0 &&
                     !tracker_high && !tracker_low && !d->has_rid);

    uint8_t vc = 0;
    if (d->vendor[0]) {
        if      (d->mac_match_len >= 36) vc = 95;
        else if (d->mac_match_len >= 28) vc = 85;
        else if (d->mac_match_len >= 24) vc = 75;
        else                              vc = 60;
    }
    if (d->company_name[0] && vc < 65) vc = 65;
    d->vendor_conf = vc;

    uint8_t cc = 0;
    uint8_t csrc = BLE_CLASS_SRC_NONE;
    if (d->has_rid) {

        cc = 95; csrc = BLE_CLASS_SRC_DRONE_RID;
    } else if (d->mfg_rule_class) {
        cc = 95; csrc = BLE_CLASS_SRC_MFG_RULE;
    } else if (d->uuid128_class) {
        cc = 90; csrc = BLE_CLASS_SRC_UUID128;
    } else if (d->uuid16_class) {
        cc = 70; csrc = BLE_CLASS_SRC_UUID16;
    } else if (d->apple_subtype_class) {
        cc = 80; csrc = BLE_CLASS_SRC_APPLE_SUBTYPE;
    } else if (d->ms_subtype_class) {
        cc = 80; csrc = BLE_CLASS_SRC_MS_SUBTYPE;
    } else if (d->bt_company_class) {
        cc = 65; csrc = BLE_CLASS_SRC_BT_COMPANY;
    } else if (d->device_class) {
        csrc = BLE_CLASS_SRC_MAC_OUI;
        if      (d->mac_match_len >= 36) cc = 80;
        else if (d->mac_match_len >= 28) cc = 65;
        else                              cc = 50;
    } else if (d->name_rule_class) {
        cc = 35; csrc = BLE_CLASS_SRC_NAME_RULE;
    }

    if (d->name_rule_class && csrc == BLE_CLASS_SRC_BT_COMPANY) {
        cc = 70;
        csrc = BLE_CLASS_SRC_NAME_RULE;
    }

    if (d->name_rule_class && d->mfg_company_id == 0x004C) {
        cc = 85;
        csrc = BLE_CLASS_SRC_NAME_RULE;
    }

    d->class_conf = cc;
    d->class_source = csrc;

    int32_t id = ((int32_t)d->base_quality * (int32_t)d->trust_q88) >> 8;
    if (id < 0)   id = 0;
    if (id > 100) id = 100;
    d->identity_score = (uint8_t)id;

    d->identity_conf = (vc > cc) ? vc : cc;

    uint8_t tl = THREAT_NONE;
    #define BUMP(lvl) do { if ((lvl) > tl) tl = (lvl); } while (0)
    bool find_my_separated =
        d->is_airtag || (d->apple_subtype == APPLE_SUB_FIND_MY_SEP);
    if (combined & EUI_FLAG_KNOWN_MALICIOUS)            BUMP(THREAT_HIGH);
    if (combined & EUI_FLAG_INVESTIGATION)              BUMP(THREAT_HIGH);
    if (attack_uuid)                                    BUMP(THREAT_HIGH);
    if (d->uuid128_class == EUI_CLASS_INVESTIGATION)    BUMP(THREAT_HIGH);
    if (d->name_rule_class == EUI_CLASS_INVESTIGATION)  BUMP(THREAT_HIGH);
    if (find_my_separated)                              BUMP(THREAT_LOW);
    if (combined & (EUI_FLAG_SURVEILLANCE | EUI_FLAG_FCC_COVERED)) BUMP(THREAT_MEDIUM);
    if (d->uuid128_class == EUI_CLASS_SURVEILLANCE_CAM) BUMP(THREAT_MEDIUM);
    if (d->mfg_company_id == 0x004C && d->apple_subtype == APPLE_SUB_AIRDROP)
        BUMP(THREAT_LOW);
    #undef BUMP
    d->threat_level = tl;
}

uint8_t ble_score_trail(const ble_device_t *d, ble_evidence_t *out, uint8_t max)
{
    if (!d || !out || max == 0) return 0;
    uint8_t n = 0;
    #define EV_ADD(k, dl, txt) do { \
        if (n < max) { out[n].kind = (uint8_t)(k); out[n].delta = (int16_t)(dl); \
                       strlcpy(out[n].label, (txt), sizeof(out[n].label)); n++; } \
    } while (0)

    if (d->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) {
        EV_ADD(BLE_EV_PENALTY, -100, "known malicious");
        return n;
    }

    bool beacon_uuid = false, attack_uuid = false;
    for (uint8_t i = 0; i < d->num_uuids16; i++) {
        uint16_t f = 0; uint8_t c = EUI_CLASS_UNKNOWN;
        eui_lookup_uuid16(d->uuids16[i], &f, &c);
        if (c == EUI_CLASS_BEACON)        beacon_uuid = true;
        if (c == EUI_CLASS_ATTACK_SIGNAL) attack_uuid = true;
    }
    uint16_t combined = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags |
                        d->uuid128_flags | d->name_rule_flags |
                        d->apple_subtype_flags | d->ms_subtype_flags |
                        d->uuid32_flags | d->fastpair_flags | d->uuid16_flags;

    if (combined & EUI_FLAG_INVESTIGATION) EV_ADD(BLE_EV_PENALTY, -50, "investigation");
    if (combined & EUI_FLAG_FCC_COVERED)   EV_ADD(BLE_EV_PENALTY, -25, "FCC-covered");
    if (combined & EUI_FLAG_DEV_MODULE)    EV_ADD(BLE_EV_PENALTY, -10, "dev module");
    if (combined & EUI_FLAG_MAKER)         EV_ADD(BLE_EV_PENALTY,  -5, "maker board");
    if (combined & EUI_FLAG_SURVEILLANCE)  EV_ADD(BLE_EV_PENALTY, -10, "surveillance");
    if (attack_uuid)                       EV_ADD(BLE_EV_PENALTY, -25, "attack UUID");
    if (beacon_uuid)                       EV_ADD(BLE_EV_PENALTY,  -5, "beacon UUID");
    if (d->uuid128_class == EUI_CLASS_INVESTIGATION)    EV_ADD(BLE_EV_PENALTY, -25, "inv UUID128");
    if (d->uuid128_class == EUI_CLASS_SURVEILLANCE_CAM) EV_ADD(BLE_EV_PENALTY, -10, "cam UUID128");
    if (d->name_rule_class == EUI_CLASS_INVESTIGATION)  EV_ADD(BLE_EV_PENALTY, -25, "inv name");

    if (combined & EUI_FLAG_STANDARDS) EV_ADD(BLE_EV_BASE, 30, "standards");
    if (d->device_class != EUI_CLASS_UNKNOWN && d->vendor[0])
        EV_ADD(BLE_EV_BASE, 25, "vendor+class");
    else if (d->vendor[0])
        EV_ADD(BLE_EV_BASE, 18, "vendor");
    if (d->company_name[0])  EV_ADD(BLE_EV_BASE, 20, "BT company");
    if (d->mfg_rule_name)    EV_ADD(BLE_EV_BASE, 20, "catalog rule");
    if (d->uuid16_class)     EV_ADD(BLE_EV_BASE, 15, "UUID16 class");
    if (d->name[0])          EV_ADD(BLE_EV_BASE, 15, "local name");
    if (d->apple_subtype_name || d->ms_subtype_name) EV_ADD(BLE_EV_BASE, 10, "subtype");
    if (d->scannable && d->name[0]) EV_ADD(BLE_EV_BASE, 10, "scan response");

    if (d->addr_subtype == BLE_ADDR_SUB_PUBLIC && !d->vendor[0])
        EV_ADD(BLE_EV_TRUST, BLE_TRUST_PUBLIC_ANON, "public+anon");
    if (d->mfg_company_id == 0xFFFF)
        EV_ADD(BLE_EV_TRUST, BLE_TRUST_NO_MFG, "no mfg data");
    if (!d->scannable && !d->name[0])
        EV_ADD(BLE_EV_TRUST, BLE_TRUST_NO_NAME_HID, "no name/hidden");
    if (d->name[0] && d->vendor[0] && d->device_class != EUI_CLASS_UNKNOWN)
        EV_ADD(BLE_EV_TRUST, BLE_TRUST_RECOGNIZED, "recognized");
    if (combined & EUI_FLAG_STANDARDS)
        EV_ADD(BLE_EV_TRUST, BLE_TRUST_STANDARDS_POS, "standards");

    #undef EV_ADD
    return n;
}

static int find_device(const ble_results_t *r, const uint8_t *addr_be)
{
    for (uint16_t i = 0; i < r->count; i++) {
        if (memcmp(r->devices[i].addr, addr_be, 6) == 0) return (int)i;
    }
    return -1;
}

static void uuid128_swap(uint8_t out[16], const uint8_t in[16])
{
    for (int i = 0; i < 16; i++) out[i] = in[15 - i];
}

static void apply_adv_fields(ble_device_t *d, const uint8_t *data, uint8_t len)
{
    if (!len) return;
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, data, len) != 0) return;

    if (!d->name[0] && fields.name && fields.name_len > 0) {
        uint8_t nl = fields.name_len < 32 ? fields.name_len : 32;
        memcpy(d->name, fields.name, nl);
        d->name[nl] = '\0';
    }
    if (d->tx_power == 127 && fields.tx_pwr_lvl_is_present)
        d->tx_power = fields.tx_pwr_lvl;

    if (d->mfg_company_id == 0xFFFF && fields.mfg_data_len >= 2) {
        d->mfg_company_id = (uint16_t)fields.mfg_data[0]
                          | ((uint16_t)fields.mfg_data[1] << 8);
        if (fields.mfg_data_len >= 4) {
            d->mfg_payload[0] = fields.mfg_data[2];
            d->mfg_payload[1] = fields.mfg_data[3];
        }
        if (fields.mfg_data_len > 2) {
            const uint8_t *payload = fields.mfg_data + 2;
            size_t plen = fields.mfg_data_len - 2;
            d->mfg_rule_name = eui_match_mfg_data(d->mfg_company_id,
                                                   payload, plen,
                                                   &d->mfg_rule_flags,
                                                   &d->mfg_rule_class,
                                                   &d->mfg_rule_subtype);

            if (d->mfg_company_id == 0x004C && plen >= 1) {
                d->apple_subtype = payload[0];
                d->apple_subtype_name = eui_lookup_apple_subtype(
                    payload[0], &d->apple_subtype_flags, &d->apple_subtype_class);
                apple_continuity_decode(d, payload, plen);

                if (d->apple_subtype != payload[0]) {
                    d->apple_subtype_name = eui_lookup_apple_subtype(
                        d->apple_subtype,
                        &d->apple_subtype_flags, &d->apple_subtype_class);
                }
            }

            if (d->mfg_company_id == 0x0006 && plen >= 1) {
                d->ms_subtype_name = eui_lookup_ms_subtype(
                    payload[0], &d->ms_subtype_flags, &d->ms_subtype_class);
            }
        }
    }

    if (d->num_uuids16 == 0 && fields.num_uuids16 > 0) {
        uint8_t n = fields.num_uuids16 < 8 ? fields.num_uuids16 : 8;
        for (uint8_t k = 0; k < n; k++)
            d->uuids16[k] = fields.uuids16[k].value;
        d->num_uuids16 = n;
    }

    if (fields.num_uuids32 > 0) {
        d->num_uuids32 = fields.num_uuids32;
        for (uint8_t k = 0; k < fields.num_uuids32; k++) {
            if (d->uuid32_name) break;
            d->uuid32_name = eui_lookup_uuid32(fields.uuids32[k].value,
                                                &d->uuid32_flags,
                                                &d->uuid32_class);
        }
    }

    if (fields.num_uuids128 > 0) {
        d->num_uuids128 = fields.num_uuids128;
        for (uint8_t k = 0; k < fields.num_uuids128; k++) {
            if (d->uuid128_name) break;
            uint8_t swapped[16];
            uuid128_swap(swapped, fields.uuids128[k].value);
            d->uuid128_name = eui_lookup_uuid128(swapped,
                                                  &d->uuid128_flags,
                                                  &d->uuid128_class);
        }
    }

    if (!d->fastpair_name && fields.svc_data_uuid16 &&
        fields.svc_data_uuid16_len >= 5) {
        uint16_t svc_uuid = (uint16_t)fields.svc_data_uuid16[0]
                          | ((uint16_t)fields.svc_data_uuid16[1] << 8);
        if (svc_uuid == 0xFE2C) {
            uint32_t mid = ((uint32_t)fields.svc_data_uuid16[2] << 16) |
                           ((uint32_t)fields.svc_data_uuid16[3] <<  8) |
                            (uint32_t)fields.svc_data_uuid16[4];
            d->fastpair_model_id = mid;
            uint16_t f = 0; uint8_t c = 0;
            d->fastpair_name = eui_lookup_fastpair(mid, &f, &c);
            d->fastpair_flags = f;
            d->fastpair_class = c;
        }
    }

    if (!d->has_rid && fields.svc_data_uuid16 && fields.svc_data_uuid16_len >= 5) {
        uint16_t svc_uuid = (uint16_t)fields.svc_data_uuid16[0]
                          | ((uint16_t)fields.svc_data_uuid16[1] << 8);
        if (svc_uuid == 0xFFFA &&
            drone_rid_decode(fields.svc_data_uuid16, fields.svc_data_uuid16_len, &d->drone)) {
            d->has_rid = true;
            d->eui_flags |= EUI_FLAG_STANDARDS;
        }
    }
}

static void ring_push_adv(const uint8_t be[6], int8_t rssi, int8_t tx_power,
                          uint8_t prim_phy, uint8_t props,
                          const uint8_t *data, uint8_t len)
{
    ble_adv_frame_t f = {
        .rssi     = rssi,
        .tx_power = tx_power,
        .prim_phy = prim_phy,
        .props    = props,
        .ts_ms    = (uint32_t)(esp_timer_get_time() / 1000),
    };
    memcpy(f.addr, be, 6);
    if (len > BLE_ADV_DATA_MAX) len = BLE_ADV_DATA_MAX;
    if (data && len) memcpy(f.data, data, len);
    f.data_len = len;
    ble_adv_ring_add(&f);
}

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    if (!s_results) return 0;

    switch (event->type) {
    case BLE_GAP_EVENT_EXT_DISC: {

        const struct ble_gap_ext_disc_desc *disc = &event->ext_disc;

        const uint8_t *v = disc->addr.val;
        uint8_t be[6]    = { v[5], v[4], v[3], v[2], v[1], v[0] };

        ring_push_adv(be, disc->rssi, disc->tx_power, disc->prim_phy,
                      (uint8_t)disc->props, disc->data, disc->length_data);

        int idx = find_device(s_results, be);
        if (idx >= 0) {
            ble_device_t *d = &s_results->devices[idx];
            d->_rssi_sum += disc->rssi;
            d->_rssi_count++;
            if (d->tx_power == 127 && disc->tx_power != 127)
                d->tx_power = disc->tx_power;
            apply_adv_fields(d, disc->data, disc->length_data);
            break;
        }

        if (s_results->count >= BLE_MAX_DEVICES) break;

        ble_device_t *d = &s_results->devices[s_results->count];
        memset(d, 0, sizeof(*d));
        memcpy(d->addr, be, 6);
        d->addr_subtype   = classify_addr(disc->addr.type, be);
        d->rssi           = disc->rssi;
        d->tx_power       = disc->tx_power;
        d->prim_phy       = disc->prim_phy;
        d->distance_dm    = 0xFFFF;
        d->mfg_company_id = 0xFFFF;
        d->_rssi_sum      = disc->rssi;
        d->_rssi_count    = 1;

        d->scannable      = (disc->props & 0x02) != 0;

        apply_adv_fields(d, disc->data, disc->length_data);

        uint16_t flags = 0;
        uint8_t  cls   = EUI_CLASS_UNKNOWN;
        uint8_t  mlen  = 0;
        const char *vendor = eui_lookup_mac(be, &flags, &cls, &mlen);
        if (vendor) {
            strlcpy(d->vendor, vendor, sizeof(d->vendor));
            if (flags & EUI_FLAG_KNOWN_MALICIOUS)
                ESP_LOGW(TAG, "%02X:%02X:%02X:%02X:%02X:%02X malicious vendor",
                         be[0], be[1], be[2], be[3], be[4], be[5]);
        }
        d->eui_flags     = flags;
        d->device_class  = cls;
        d->mac_match_len = mlen;

        s_results->count++;
        break;
    }

    case BLE_GAP_EVENT_DISC: {

        const struct ble_gap_disc_desc *disc = &event->disc;

        const uint8_t *v = disc->addr.val;
        uint8_t be[6]    = { v[5], v[4], v[3], v[2], v[1], v[0] };

        ring_push_adv(be, disc->rssi, 127, 1, (uint8_t)disc->event_type,
                      disc->data, disc->length_data);

        int idx = find_device(s_results, be);
        if (idx >= 0) {
            ble_device_t *d = &s_results->devices[idx];
            d->_rssi_sum += disc->rssi;
            d->_rssi_count++;
            apply_adv_fields(d, disc->data, disc->length_data);
            break;
        }

        if (s_results->count >= BLE_MAX_DEVICES) break;

        ble_device_t *d = &s_results->devices[s_results->count];
        memset(d, 0, sizeof(*d));
        memcpy(d->addr, be, 6);
        d->addr_subtype   = classify_addr(disc->addr.type, be);
        d->rssi           = disc->rssi;
        d->tx_power       = 127;
        d->prim_phy       = 1;
        d->distance_dm    = 0xFFFF;
        d->mfg_company_id = 0xFFFF;
        d->_rssi_sum      = disc->rssi;
        d->_rssi_count    = 1;

        d->scannable = (disc->event_type == 0 || disc->event_type == 2);

        apply_adv_fields(d, disc->data, disc->length_data);

        uint16_t flags = 0;
        uint8_t  cls   = EUI_CLASS_UNKNOWN;
        uint8_t  mlen  = 0;
        const char *vendor = eui_lookup_mac(be, &flags, &cls, &mlen);
        if (vendor) {
            strlcpy(d->vendor, vendor, sizeof(d->vendor));
            if (flags & EUI_FLAG_KNOWN_MALICIOUS)
                ESP_LOGW(TAG, "%02X:%02X:%02X:%02X:%02X:%02X malicious vendor",
                         be[0], be[1], be[2], be[3], be[4], be[5]);
        }
        d->eui_flags     = flags;
        d->device_class  = cls;
        d->mac_match_len = mlen;

        s_results->count++;
        break;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        xSemaphoreGive(s_done_sem);
        break;

    default:
        break;
    }
    return 0;
}

esp_err_t ble_scanner_init(void)
{
    s_sync_sem = xSemaphoreCreateBinary();
    s_done_sem = xSemaphoreCreateBinary();
    if (!s_sync_sem || !s_done_sem) return ESP_ERR_NO_MEM;

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.sync_cb         = on_sync;
    ble_hs_cfg.reset_cb        = on_reset;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_store_config_init();

    nimble_port_freertos_init(host_task);

    if (xSemaphoreTake(s_sync_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "NimBLE sync timeout");
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGI(TAG, "BLE stack ready");
    return ESP_OK;
}

esp_err_t ble_scan_run(ble_results_t *out, uint32_t duration_ms)
{
    return ble_scan_run_ex(out, duration_ms, false, false);
}

esp_err_t ble_scan_run_ex(ble_results_t *out, uint32_t duration_ms, bool continuous,
                          bool coded_phy)
{
    if (!out) return ESP_ERR_INVALID_ARG;

    out->count = 0;
    s_results  = out;

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(1, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto: %d", rc);
        s_results = NULL;
        return ESP_FAIL;
    }

    uint32_t free_heap = esp_get_free_heap_size();
    size_t largest8  = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    size_t free_int  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_i = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    ESP_LOGW(TAG, "ble_scan_run entry: free=%lu largest8=%u INT free=%u largest=%u",
             (unsigned long)free_heap, (unsigned)largest8,
             (unsigned)free_int, (unsigned)largest_i);
    if (free_heap < (16 * 1024)) {
        ESP_LOGW(TAG, "BLE scan skipped — low heap (%lu B, largest8=%u)",
                 (unsigned long)free_heap, (unsigned)largest8);
        s_results = NULL;
        return ESP_OK;
    }

    struct ble_gap_ext_disc_params uncoded = {
        .itvl    = 0,
        .window  = 0,
        .passive = 0,
    };
    struct ble_gap_ext_disc_params coded = {
        .itvl    = 0,
        .window  = 0,
        .passive = 0,
    };
    uint16_t dur_units = (uint16_t)(duration_ms / 10);

    uint8_t filter_dupes = continuous ? 0 : 1;
    rc = ble_gap_ext_disc(own_addr_type, dur_units, 0,
                          filter_dupes,
                          0,
                          0,
                          &uncoded,
                          coded_phy ? &coded : NULL,
                          gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_ext_disc: %d", rc);
        s_results = NULL;
        return ESP_FAIL;
    }

    if (xSemaphoreTake(s_done_sem, pdMS_TO_TICKS(duration_ms + 1000)) != pdTRUE) {
        ESP_LOGW(TAG, "scan timeout — cancelling");
        ble_gap_disc_cancel();
    }

    s_results = NULL;

    for (uint16_t i = 0; i < out->count; i++) {
        ble_device_t *d = &out->devices[i];
        if (d->_rssi_count > 0)
            d->rssi = (int8_t)(d->_rssi_sum / (int32_t)d->_rssi_count);
        d->distance_dm = estimate_distance_dm(d->tx_power, d->rssi);
        score_ble_device(d);
        ESP_LOGI(TAG,
                 "BLE[%u] name=\"%s\" airtag=%u addr=%02X:%02X:%02X:%02X:%02X:%02X vendor=\"%s\" company=\"%s\" rssi=%d tx=%d dist_dm=%u uuids=%u mfg=0x%04X flags_eui=0x%04X flags_bt=0x%04X ident=%u/%u threat=%u",
                 (unsigned)i,
                 d->name[0] ? d->name : "(no local name)",
                 d->is_airtag ? 1u : 0u,
                 d->addr[0], d->addr[1], d->addr[2], d->addr[3], d->addr[4], d->addr[5],
                 d->vendor[0] ? d->vendor : "(unknown)",
                 d->company_name[0] ? d->company_name : "(unknown)",
                 (int)d->rssi, (int)d->tx_power, (unsigned)d->distance_dm,
                 (unsigned)d->num_uuids16, (unsigned)d->mfg_company_id,
                 (unsigned)d->eui_flags, (unsigned)d->bt_company_flags,
                 (unsigned)d->identity_score, (unsigned)d->identity_conf,
                 (unsigned)d->threat_level);
    }

    ESP_LOGI(TAG, "BLE scan complete: %u devices", out->count);
    return ESP_OK;
}
