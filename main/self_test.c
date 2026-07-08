#include "self_test.h"
#include "analyzer.h"
#include "ble_scanner.h"
#include "public_safety_detect.h"
#include "medical_responder_detect.h"
#include "physical_device_cluster.h"
#include "drone_rid.h"
#include "eui_db.h"
#include "apple_continuity.h"
#include "opendroneid.h"

#include "esp_attr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>

static const char *TAG = "selftest";

static const char *fmt_deg(int32_t e7, char *buf, size_t sz)
{
    long a = e7 < 0 ? -(long)e7 : (long)e7;
    snprintf(buf, sz, "%s%ld.%07ld", e7 < 0 ? "-" : "", a / 10000000, a % 10000000);
    return buf;
}

typedef enum {
    ID_MAC,
    ID_BT_CID,
    ID_UUID16,
    ID_UUID128,
    ID_NAME,
    ID_SSID,
    ID_VENDOR_IE,
} id_kind_t;

typedef struct {
    const char *label;
    id_kind_t   kind;
    const char *str;
    uint8_t     bytes[6];
    uint32_t    num;
    const char *expect;
} id_case_t;

static const id_case_t s_id_cases[] = {

    { .label="Xfinity public SSID", .kind=ID_SSID, .str="xfinitywifi",     .expect="" },
    { .label="Xfinity Mobile SSID", .kind=ID_SSID, .str="Xfinity Mobile",  .expect="Xfinity Mobile" },
    { .label="eduroam SSID",        .kind=ID_SSID, .str="eduroam",          .expect="" },
    { .label="Cisco vendor IE",     .kind=ID_VENDOR_IE, .bytes={0x00,0x40,0x96}, .expect="" },

    { .label="Hikvision camera",    .kind=ID_NAME, .str="HIKVISION DS-2CD", .expect="CAMERA" },
    { .label="Reolink camera",      .kind=ID_NAME, .str="Reolink RLC-810",  .expect="" },
    { .label="eufyCam",             .kind=ID_NAME, .str="eufyCam 2C",        .expect="" },

    { .label="Flock OUI (OEM-reg)",  .kind=ID_MAC, .bytes={0x70,0xC9,0x4E,0x00,0x00,0x01}, .expect="Flock" },
    { .label="Flock OUI (registered)",.kind=ID_MAC,.bytes={0xB4,0x1E,0x52,0x00,0x00,0x01}, .expect="Flock" },
    { .label="Flock company 0x09C8", .kind=ID_BT_CID, .num=0x09C8,          .expect="CAMERA" },
    { .label="Flock name Pigvision", .kind=ID_NAME, .str="Pigvision",        .expect="Flock" },
    { .label="Flock name FS Ext Bat",.kind=ID_NAME, .str="FS Ext Battery",   .expect="Flock" },
    { .label="Raven svc uuid 0x3100",.kind=ID_UUID16, .num=0x3100,           .expect="Raven" },

    { .label="ASTM RID uuid16",     .kind=ID_UUID16,  .num=0xFFFA,           .expect="" },
    { .label="ASTM RID uuid128",    .kind=ID_UUID128,
      .str="0000FFFA-0000-1000-8000-00805F9B34FB",                          .expect="" },

    { .label="Apple company",       .kind=ID_BT_CID, .num=0x004C,           .expect="Apple" },
    { .label="Samsung company",     .kind=ID_BT_CID, .num=0x0075,           .expect="Samsung" },
    { .label="Microsoft company",   .kind=ID_BT_CID, .num=0x0006,           .expect="Microsoft" },
    { .label="Google company",      .kind=ID_BT_CID, .num=0x00E0,           .expect="Google" },
    { .label="iPhone name",         .kind=ID_NAME, .str="John's iPhone",    .expect="PHONE" },

    { .label="Meshtastic name",     .kind=ID_NAME, .str="Meshtastic_a1b2",  .expect="" },
    { .label="Ray-Ban Meta name",   .kind=ID_NAME, .str="Ray-Ban Meta",     .expect="" },

    { .label="Flipper Zero name",   .kind=ID_NAME, .str="Flipper Trinity",  .expect="INVEST" },
    { .label="Marauder name",       .kind=ID_NAME, .str="ESP32 Marauder",   .expect="INVEST" },

    { .label="MacBook Pro name",    .kind=ID_NAME, .str="Jack's MacBook Pro", .expect="LAPTOP" },
    { .label="MacBook make label",  .kind=ID_NAME, .str="Susan's MacBook Air",.expect="Apple" },
    { .label="ThinkPad name",       .kind=ID_NAME, .str="ThinkPad-X1",        .expect="LAPTOP" },
    { .label="ThinkPad make label", .kind=ID_NAME, .str="ThinkPad T14",       .expect="Lenovo" },
    { .label="Dell Latitude name",  .kind=ID_NAME, .str="LATITUDE-7420",      .expect="LAPTOP" },
    { .label="HP EliteBook name",   .kind=ID_NAME, .str="EliteBook 840",      .expect="LAPTOP" },
    { .label="Surface Laptop name", .kind=ID_NAME, .str="Surface Laptop 5",   .expect="LAPTOP" },

    { .label="'Yoga Studio' SSID",  .kind=ID_NAME, .str="Yoga Studio Guest",  .expect="" },

    { .label="Example full MAC",    .kind=ID_MAC, .bytes={0x3C,0x06,0x30,0x12,0x34,0x56}, .expect="" },

};

static bool ci_contains(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0]) return false;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl) return true;
    }
    return false;
}

static void parse_uuid128(const char *s, uint8_t out[16])
{
    memset(out, 0, 16);
    int nib = 0;
    for (const char *p = s; *p && nib < 32; p++) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;
        if ((nib & 1) == 0) out[nib / 2]  = (uint8_t)(v << 4);
        else                out[nib / 2] |= (uint8_t)v;
        nib++;
    }
}

static void run_id_case(const id_case_t *c)
{
    uint16_t flags = 0;
    uint8_t  cls = 0, mlen = 0;
    const char *name = NULL;
    char extra[16] = "";

    switch (c->kind) {
    case ID_MAC:
        name = eui_lookup_mac(c->bytes, &flags, &cls, &mlen);
        snprintf(extra, sizeof(extra), " /%u", mlen);
        break;
    case ID_BT_CID:    name = eui_lookup_company((uint16_t)c->num, &flags, &cls); break;
    case ID_UUID16:    name = eui_lookup_uuid16((uint16_t)c->num, &flags, &cls);  break;
    case ID_UUID128: { uint8_t u[16]; parse_uuid128(c->str, u);
                       name = eui_lookup_uuid128(u, &flags, &cls); break; }
    case ID_NAME:      name = eui_match_name(c->str, &flags, &cls, NULL);  break;
    case ID_SSID:      name = eui_match_ssid(c->str, &flags, &cls);  break;
    case ID_VENDOR_IE: name = eui_lookup_vendor_ie(c->bytes, &flags, &cls); break;
    }

    const char *cls_lbl = eui_class_label(cls);
    const char *verdict = "INFO";
    if (c->expect && c->expect[0])
        verdict = (ci_contains(name, c->expect) || ci_contains(cls_lbl, c->expect))
                ? "PASS" : "FAIL";

    ESP_LOGI(TAG, "[%-4s] %-22s -> name=%-24s class=%-8s%s flags=0x%04X %s",
             verdict, c->label, name ? name : "(none)",
             cls_lbl[0] ? cls_lbl : "-", extra, flags,
             (c->expect && c->expect[0]) ? c->expect : "");
}

static void run_id_tests(void)
{
    const size_t n = sizeof(s_id_cases) / sizeof(s_id_cases[0]);
    ESP_LOGI(TAG, "── identifier tests (%u) ──", (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        run_id_case(&s_id_cases[i]);
        if ((i & 7) == 7) vTaskDelay(1);
    }
}

typedef struct {
    const char *label;
    const char *id;
    uint8_t     ua_type;
    uint8_t     id_type;
    bool        loc;         double lat, lon; float alt_geo, speed, track;
    bool        system;      double op_lat, op_lon;
    bool        operator_id; const char *op_id;
    bool        self_id;     const char *self_text;
} rid_case_t;

static const rid_case_t s_rid_cases[] = {
    { .label="Multirotor + operator",
      .id="1581F5FMC243600A1B2C", .ua_type=ODID_UATYPE_HELICOPTER_OR_MULTIROTOR,
      .id_type=ODID_IDTYPE_SERIAL_NUMBER,
      .loc=true, .lat=37.774900, .lon=-122.419400, .alt_geo=120.0f, .speed=8.0f, .track=270.0f,
      .system=true, .op_lat=37.774000, .op_lon=-122.420000,
      .operator_id=true, .op_id="FA12OPERATOR01",
      .self_id=true, .self_text="Survey flight" },
    { .label="Fixed-wing, no operator loc",
      .id="FW-TEST-0001", .ua_type=ODID_UATYPE_AEROPLANE,
      .id_type=ODID_IDTYPE_CAA_REGISTRATION_ID,
      .loc=true, .lat=51.507400, .lon=-0.127800, .alt_geo=300.0f, .speed=22.0f, .track=90.0f,
      .system=false, .operator_id=false, .self_id=false },

};

static size_t build_rid_pack(const rid_case_t *c, ODID_MessagePack_encoded *enc)
{
    static ODID_MessagePack_data pack;
    memset(&pack, 0, sizeof(pack));
    pack.SingleMessageSize = ODID_MESSAGE_SIZE;
    int n = 0;

    {
        ODID_BasicID_data b; odid_initBasicIDData(&b);
        b.UAType = (ODID_uatype_t)c->ua_type;
        b.IDType = (ODID_idtype_t)c->id_type;
        strncpy(b.UASID, c->id, sizeof(b.UASID) - 1);
        if (encodeBasicIDMessage((ODID_BasicID_encoded *)&pack.Messages[n], &b) != ODID_SUCCESS)
            return 0;
        n++;
    }
    if (c->loc) {
        ODID_Location_data l; odid_initLocationData(&l);
        l.Status = ODID_STATUS_AIRBORNE;
        l.Latitude = c->lat; l.Longitude = c->lon;
        l.AltitudeGeo = c->alt_geo; l.SpeedHorizontal = c->speed; l.Direction = c->track;
        if (encodeLocationMessage((ODID_Location_encoded *)&pack.Messages[n], &l) != ODID_SUCCESS)
            return 0;
        n++;
    }
    if (c->system) {
        ODID_System_data s; odid_initSystemData(&s);
        s.OperatorLatitude = c->op_lat; s.OperatorLongitude = c->op_lon;
        if (encodeSystemMessage((ODID_System_encoded *)&pack.Messages[n], &s) != ODID_SUCCESS)
            return 0;
        n++;
    }
    if (c->operator_id) {
        ODID_OperatorID_data o; odid_initOperatorIDData(&o);
        strncpy(o.OperatorId, c->op_id, sizeof(o.OperatorId) - 1);
        if (encodeOperatorIDMessage((ODID_OperatorID_encoded *)&pack.Messages[n], &o) != ODID_SUCCESS)
            return 0;
        n++;
    }
    if (c->self_id) {
        ODID_SelfID_data sf; odid_initSelfIDData(&sf);
        strncpy(sf.Desc, c->self_text, sizeof(sf.Desc) - 1);
        if (encodeSelfIDMessage((ODID_SelfID_encoded *)&pack.Messages[n], &sf) != ODID_SUCCESS)
            return 0;
        n++;
    }
    pack.MsgPackSize = (uint8_t)n;

    if (encodeMessagePack(enc, &pack) != ODID_SUCCESS) return 0;
    return 3 + (size_t)n * ODID_MESSAGE_SIZE;
}

static size_t frame_ble(const ODID_MessagePack_encoded *enc, size_t pack_len,
                        uint8_t *out, size_t out_sz)
{
    if (out_sz < 4 + pack_len) return 0;
    out[0] = 0xFA; out[1] = 0xFF;
    out[2] = 0x0D;
    out[3] = 0x00;
    memcpy(&out[4], enc, pack_len);
    return 4 + pack_len;
}

static size_t frame_wifi_beacon(const ODID_MessagePack_encoded *enc, size_t pack_len,
                                uint8_t *out, size_t out_sz)
{
    if (out_sz < 5 + pack_len) return 0;
    out[0] = 0xFA; out[1] = 0x0B; out[2] = 0xBC;
    out[3] = 0x0D;
    out[4] = 0x00;
    memcpy(&out[5], enc, pack_len);
    return 5 + pack_len;
}

static size_t frame_wifi_nan(const ODID_MessagePack_encoded *enc, size_t pack_len,
                             uint8_t *out, size_t out_sz)
{
    size_t need = 44 + pack_len;
    if (out_sz < need) return 0;
    memset(out, 0, 44);
    out[24] = 0x04; out[25] = 0x09;
    out[26] = 0x50; out[27] = 0x6F; out[28] = 0x9A;
    out[29] = 0x13;
    out[30] = 0x03;

    out[33] = 0x88; out[34] = 0x69; out[35] = 0x19;
    out[36] = 0x9D; out[37] = 0x92; out[38] = 0x09;
    out[39] = 0x01;
    out[41] = 0x10;
    out[42] = (uint8_t)(1 + pack_len);
    out[43] = 0x00;
    memcpy(&out[44], enc, pack_len);
    return need;
}

static bool verify_rid(const rid_case_t *c, const drone_rid_t *r)
{
    if (strncmp(r->id, c->id, sizeof(r->id) - 1) != 0) return false;
    if (r->ua_type != c->ua_type)                       return false;
    if (c->loc) {
        int32_t want_lat = (int32_t)lround(c->lat * 1e7);
        int32_t want_lon = (int32_t)lround(c->lon * 1e7);
        if (labs((long)(r->lat - want_lat)) > 2) return false;
        if (labs((long)(r->lon - want_lon)) > 2) return false;
    }
    if (c->system && !r->has_op_loc) return false;
    return true;
}

typedef size_t (*rid_frame_fn)(const ODID_MessagePack_encoded *, size_t, uint8_t *, size_t);
typedef bool   (*rid_decode_fn)(const uint8_t *, size_t, drone_rid_t *);

static void run_rid_case(const rid_case_t *c)
{
    static ODID_MessagePack_encoded enc;
    size_t pack_len = build_rid_pack(c, &enc);
    if (pack_len == 0) { ESP_LOGW(TAG, "[FAIL] %s: encode failed", c->label); return; }

    static const struct {
        const char   *name;
        rid_frame_fn  frame;
        rid_decode_fn decode;
    } bearers[] = {
        { "BLE",       frame_ble,         drone_rid_decode },
        { "Wi-Fi",     frame_wifi_beacon, drone_rid_decode_wifi_beacon },
        { "Wi-Fi NaN", frame_wifi_nan,    drone_rid_decode_wifi_nan },
    };

    static uint8_t blob[256];
    for (size_t b = 0; b < sizeof(bearers) / sizeof(bearers[0]); b++) {
        size_t len = bearers[b].frame(&enc, pack_len, blob, sizeof(blob));
        drone_rid_t r;
        bool decoded = len && bearers[b].decode(blob, len, &r);
        if (!decoded) {
            ESP_LOGW(TAG, "[FAIL] %-26s [%-9s] decode returned no messages",
                     c->label, bearers[b].name);
            continue;
        }
        bool ok  = verify_rid(c, &r);
        int  sep = drone_op_separation_m(&r);
        char latb[16], lonb[16];
        ESP_LOGI(TAG, "[%-4s] %-26s [%-9s] id=%s type=%s mfr=%s",
                 ok ? "PASS" : "FAIL", c->label,
                 drone_rid_bearer_label(r.bearer), r.id,
                 drone_ua_type_label(r.ua_type), r.mfr_code[0] ? r.mfr_code : "-");
        ESP_LOGI(TAG, "        drone=%s,%s alt=%dm op_loc=%s sep=%dm op=%s self=%s auth=%s",
                 fmt_deg(r.lat, latb, sizeof(latb)), fmt_deg(r.lon, lonb, sizeof(lonb)),
                 (int)r.alt_m, r.has_op_loc ? "Y" : "N", sep,
                 r.op_id[0] ? r.op_id : "-", r.self_id[0] ? r.self_id : "-",
                 r.auth_present ? "Y" : "N");
    }
}

static void run_rid_tests(void)
{
    const size_t n = sizeof(s_rid_cases) / sizeof(s_rid_cases[0]);
    ESP_LOGI(TAG, "── drone Remote ID round-trip tests (%u cases x 3 bearers) ──", (unsigned)n);
    for (size_t i = 0; i < n; i++) run_rid_case(&s_rid_cases[i]);
}

static EXT_RAM_BSS_ATTR ap_score_t   s_ct_aps[4];

static EXT_RAM_BSS_ATTR ble_results_t s_ct_ble;
static int s_ct_pass, s_ct_fail;

static void ct_check(const char *name, bool ok)
{
    if (ok) { s_ct_pass++; ESP_LOGI(TAG, "[PASS] %s", name); }
    else    { s_ct_fail++; ESP_LOGW(TAG, "[FAIL] %s", name); }
}

static void mk_ap(ap_score_t *a, const uint8_t mac[6], const char *ssid,
                  uint8_t channel, bool band_5g, int8_t rssi)
{
    memset(a, 0, sizeof(*a));
    memcpy(a->bssid, mac, 6);
    if (ssid) strncpy(a->ssid, ssid, sizeof(a->ssid) - 1);
    a->channel    = channel;
    a->band_5g    = band_5g;
    a->rssi       = rssi;
    a->suppressed = false;
}

static bool ct_same_cluster(uint8_t i, uint8_t j)
{
    int8_t ci = pdc_cluster_of(PDC_NODE_WIFI, i);
    int8_t cj = pdc_cluster_of(PDC_NODE_WIFI, j);
    return ci >= 0 && ci == cj;
}

static bool ct_same_ble_cluster(uint8_t i, uint8_t j)
{
    int8_t ci = pdc_cluster_of(PDC_NODE_BLE, i);
    int8_t cj = pdc_cluster_of(PDC_NODE_BLE, j);
    return ci >= 0 && ci == cj;
}

static bool ct_clusters_disjoint(void)
{
    uint16_t seen[ANALYZER_MAX_APS + BLE_MAX_DEVICES];
    uint16_t ns = 0;
    uint8_t  nc = pdc_cluster_count();
    for (uint8_t c = 0; c < nc; c++) {
        const pdc_cluster_t *cl = pdc_cluster_get(c);
        if (!cl) return false;
        for (uint8_t m = 0; m < cl->member_count; m++) {
            const pdc_member_t *mb = &cl->members[m];
            if (pdc_cluster_of(mb->kind, mb->idx) != (int8_t)c) return false;
            uint16_t key = (uint16_t)((uint16_t)mb->kind << 8 | mb->idx);
            for (uint16_t k = 0; k < ns; k++)
                if (seen[k] == key) return false;
            if (ns < sizeof(seen) / sizeof(seen[0])) seen[ns++] = key;
        }
    }
    return true;
}

static bool ct_same_vehicle(uint8_t wifi_i, uint8_t ble_j)
{
    int8_t ci = pdc_vehicle_cluster_of(PDC_NODE_WIFI, wifi_i);
    int8_t cj = pdc_vehicle_cluster_of(PDC_NODE_BLE, ble_j);
    return ci >= 0 && ci == cj;
}

static const pdc_edge_t *ct_ble_edge(uint8_t i, uint8_t j)
{
    uint8_t ne = pdc_edge_count();
    for (uint8_t e = 0; e < ne; e++) {
        const pdc_edge_t *ed = pdc_edge_get(e);
        if (!ed) continue;
        if (ed->kind_a != PDC_NODE_BLE || ed->kind_b != PDC_NODE_BLE) continue;
        if ((ed->idx_a == i && ed->idx_b == j) ||
            (ed->idx_a == j && ed->idx_b == i)) return ed;
    }
    return NULL;
}

static void mk_ble(ble_device_t *d, const uint8_t addr[6], const char *name)
{
    memset(d, 0, sizeof(*d));
    memcpy(d->addr, addr, 6);
    if (name) strncpy(d->name, name, sizeof(d->name) - 1);
    d->suppressed = false;
}

static void run_cluster_tests(void)
{
    s_ct_pass = s_ct_fail = 0;
    ESP_LOGI(TAG, "── physical-device clustering tests ──");

    const uint8_t A0[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x30};
    const uint8_t A2[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x32};
    const uint8_t B1[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x01};
    const uint8_t B2[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x02};
    const uint8_t C9[6] = {0x3C,0x5A,0xB4,0x99,0x88,0x77};

    mk_ap(&s_ct_aps[0], A0, "HomeA", 1, false, -50);
    mk_ap(&s_ct_aps[1], C9, "HomeB", 6, false, -55);
    for (int k = 0; k < 2; k++) {
        strcpy(s_ct_aps[k].wps_manufacturer, "Acme");
        strcpy(s_ct_aps[k].wps_model_name,   "RT-1000");
    }
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("1 same-model diff-box not merged", pdc_cluster_count() == 0);

    mk_ap(&s_ct_aps[0], B1, "BatchA", 1,  false, -50);
    mk_ap(&s_ct_aps[1], B2, "BatchB", 11, false, -52);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("2 same-OUI batch diff-channel not merged", pdc_cluster_count() == 0);

    mk_ap(&s_ct_aps[0], A0, "DualB",  6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "DualB",  36, true,  -58);
    strcpy(s_ct_aps[0].cdp_device_id, "rtr-home-7");
    strcpy(s_ct_aps[1].cdp_device_id, "rtr-home-7");
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("3 dual-band + L2L3 id merges", ct_same_cluster(0, 1));

    mk_ap(&s_ct_aps[0], A0, "DualC", 6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "DualC", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("3b cross-band same-SSID corroborates (merges)",
             ct_same_cluster(0, 1) && pdc_edge_get(0) && pdc_edge_get(0)->corroborated);

    mk_ap(&s_ct_aps[0], A0, "DualC", 6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "DualC", 36, true,  -60);
    strcpy(s_ct_aps[0].country_code, "US");
    strcpy(s_ct_aps[1].country_code, "DE");
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("3c country conflict vetoes corroboration",
             pdc_cluster_count() == 0 && pdc_edge_count() >= 1);

    mk_ap(&s_ct_aps[0], A0, "DualC", 6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "DualD", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("3d cross-band diff-SSID stays candidate",
             pdc_cluster_count() == 0 && pdc_edge_count() >= 1);

    mk_ap(&s_ct_aps[0], A0, "Main",  6, false, -50);
    mk_ap(&s_ct_aps[1], A2, "Guest", 6, false, -54);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("4 multi-SSID one radio merges", ct_same_cluster(0, 1));

    mk_ap(&s_ct_aps[0], A0, "Main",  6, false, -50);
    mk_ap(&s_ct_aps[1], A2, "Guest", 6, false, -54);
    strcpy(s_ct_aps[0].country_code, "US");
    strcpy(s_ct_aps[1].country_code, "DE");
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("4b country conflict vetoes merge", pdc_cluster_count() == 0);

    mk_ap(&s_ct_aps[0], B1, "CorpWiFi", 1,  false, -50);
    mk_ap(&s_ct_aps[1], B2, "CorpWiFi", 6,  false, -55);
    mk_ap(&s_ct_aps[2], A0, "CorpWiFi", 11, false, -60);
    pdc_build(s_ct_aps, 3, NULL);
    ct_check("5 mesh same-SSID no transitive merge", pdc_cluster_count() == 0);

    mk_ap(&s_ct_aps[0], A0, "MyPlug", 6, false, -50);
    memset(&s_ct_ble, 0, sizeof(s_ct_ble));
    s_ct_ble.count = 1;
    s_ct_ble.devices[0].addr[0] = 0x12;
    s_ct_ble.devices[0].addr[5] = 0xAB;
    strcpy(s_ct_ble.devices[0].name, "MyPlug");
    s_ct_ble.devices[0].suppressed = false;
    pdc_build(s_ct_aps, 1, &s_ct_ble);
    ct_check("6 BLE name match is candidate not merged",
             pdc_cluster_count() == 0 && pdc_edge_count() >= 1);

    mk_ap(&s_ct_aps[0], A0, "SwA", 1, false, -50);
    mk_ap(&s_ct_aps[1], C9, "SwB", 6, false, -55);
    strcpy(s_ct_aps[0].lldp_system_name, "switch");
    strcpy(s_ct_aps[1].lldp_system_name, "switch");
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("7 generic L2L3 id does not merge", pdc_cluster_count() == 0);

    ESP_LOGI(TAG, "── matching tests (2) ──");

    mk_ap(&s_ct_aps[0], A0, "MyNet",    6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "MyNet-5G", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("S2-1 dual-band SSID variant corroborates (merges)",
             ct_same_cluster(0, 1));

    mk_ap(&s_ct_aps[0], A0, "xfinitywifi", 6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "xfinitywifi", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("S2-2 public chain SSID vetoes corroboration",
             pdc_cluster_count() == 0 && pdc_edge_count() >= 1);

    {
        const uint8_t M2[6] = {0xAA,0xBB,0xCC,0x01,0x02,0x03};
        const uint8_t M3[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        mk_ap(&s_ct_aps[0], A0, "MeshNet", 6,  false, -50);
        mk_ap(&s_ct_aps[1], A2, "MeshNet", 36, true,  -60);
        mk_ap(&s_ct_aps[2], M2, "MeshNet", 1,  false, -70);
        mk_ap(&s_ct_aps[3], M3, "MeshNet", 11, false, -72);
        pdc_build(s_ct_aps, 4, NULL);
        ct_check("S2-3 large same-SSID group vetoes corroboration",
                 pdc_cluster_count() == 0);
    }

    ESP_LOGI(TAG, "── matching tests (3) ──");

    {
        const uint8_t A4[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x34};
        mk_ap(&s_ct_aps[0], A0, "AmbNet", 6,  false, -50);
        mk_ap(&s_ct_aps[1], A2, "AmbNet", 36, true,  -58);
        mk_ap(&s_ct_aps[2], A4, "AmbNet", 40, true,  -60);
        pdc_build(s_ct_aps, 3, NULL);
        ct_check("S3-1 ambiguous 2.4->two 5G demoted (no merge)",
                 pdc_cluster_count() == 0);
    }

    {
        const uint8_t W9[6] = {0x9A,0x8B,0x7C,0x6D,0x5E,0x4F};
        mk_ap(&s_ct_aps[0], A0, "DualF",    6,  false, -50);
        mk_ap(&s_ct_aps[1], A2, "DualF-5G", 36, true,  -58);
        mk_ap(&s_ct_aps[2], W9, "Cafe",     1,  false, -70);
        pdc_build(s_ct_aps, 3, NULL);
        ct_check("S3-2 dual-band still merges beside unrelated AP",
                 ct_same_cluster(0, 1) && pdc_cluster_count() == 1);
    }

    ESP_LOGI(TAG, "── matching tests (4) ──");

    mk_ap(&s_ct_aps[0], A0, "MyNet",    6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "MyNet-5G", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("S4-1 corroborated edge carries facts, no conflict",
             pdc_edge_get(0) && pdc_edge_get(0)->corroborated &&
             pdc_edge_get(0)->cand_mask != 0 &&
             pdc_edge_get(0)->conflict_mask == 0);

    mk_ap(&s_ct_aps[0], A0, "attwifi", 6,  false, -50);
    mk_ap(&s_ct_aps[1], A2, "attwifi", 36, true,  -60);
    pdc_build(s_ct_aps, 2, NULL);
    ct_check("S4-2 chain edge records conflict, not corroborated",
             pdc_edge_get(0) && !pdc_edge_get(0)->corroborated &&
             pdc_edge_get(0)->conflict_mask != 0);

    ESP_LOGI(TAG, "── matching tests (5) ──");

    {
        const uint8_t Q0[6] = {0x66,0x77,0x88,0x11,0x99,0x10};
        const uint8_t Q2[6] = {0x66,0x77,0x88,0x11,0x99,0x12};
        mk_ap(&s_ct_aps[0], A0, "NetA",    6,  false, -50);
        mk_ap(&s_ct_aps[1], A2, "NetA-5G", 36, true,  -58);
        mk_ap(&s_ct_aps[2], Q0, "NetB",    6,  false, -52);
        mk_ap(&s_ct_aps[3], Q2, "NetB-5G", 36, true,  -60);
        pdc_build(s_ct_aps, 4, NULL);
        ct_check("S5-1 two dual-band APs -> two disjoint clusters",
                 pdc_cluster_count() == 2 && ct_same_cluster(0, 1) &&
                 ct_same_cluster(2, 3) && !ct_same_cluster(0, 2) &&
                 ct_clusters_disjoint());
    }

    {
        const uint8_t R1[6] = {0xC2,0x01,0x02,0x03,0x04,0x05};
        const uint8_t R2[6] = {0xDA,0x06,0x07,0x08,0x09,0x0A};
        mk_ap(&s_ct_aps[0], A0, "NetC",    6,  false, -50);
        mk_ap(&s_ct_aps[1], A2, "NetC-5G", 36, true,  -58);
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], R1, NULL);
        mk_ble(&s_ct_ble.devices[1], R2, NULL);
        for (int k = 0; k < 2; k++) {
            s_ct_ble.devices[k].has_rid = true;
            s_ct_ble.devices[k].drone.id_type = 1;
            strcpy(s_ct_ble.devices[k].drone.id, "SN-MIX-001");
        }
        pdc_build(s_ct_aps, 2, &s_ct_ble);
        ct_check("S5-2 wifi + ble clusters coexist, disjoint",
                 pdc_cluster_count() == 2 && ct_same_cluster(0, 1) &&
                 ct_same_ble_cluster(0, 1) && ct_clusters_disjoint());
    }

    ESP_LOGI(TAG, "── BLE clustering tests ──");

    {
        const uint8_t R1[6] = {0xC2,0x11,0x11,0x11,0x11,0x01};
        const uint8_t R2[6] = {0xD6,0x22,0x22,0x22,0x22,0x02};
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], R1, "Buds");
        mk_ble(&s_ct_ble.devices[1], R2, "Buds");
        s_ct_ble.devices[0].fastpair_model_id = 0x0A1B2C;
        s_ct_ble.devices[1].fastpair_model_id = 0x0A1B2C;
        pdc_build(NULL, 0, &s_ct_ble);
        const pdc_edge_t *e = ct_ble_edge(0, 1);
        ct_check("34f-1 same-model BLE: product edge, not merged",
                 e && !e->can_union && e->evidence == PDC_EV_BLE_FASTPAIR_MODEL &&
                 !ct_same_ble_cluster(0, 1) && pdc_cluster_count() == 0);
    }

    {
        const uint8_t P1[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x10};
        const uint8_t P2[6] = {0x3C,0x5A,0xB4,0x11,0x22,0x12};
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], P1, "Case");
        mk_ble(&s_ct_ble.devices[1], P2, "Case");
        pdc_build(NULL, 0, &s_ct_ble);
        const pdc_edge_t *e = ct_ble_edge(0, 1);
        ct_check("34f-2 adjacent public BLE: relation, not merged",
                 e && !e->can_union && e->evidence == PDC_EV_MAC_ADJACENT &&
                 !ct_same_ble_cluster(0, 1));
    }

    {
        const uint8_t R1[6] = {0xC2,0x33,0x44,0x55,0x66,0x77};
        const uint8_t R2[6] = {0xE6,0x88,0x99,0xAA,0xBB,0xCC};
        static const char *kUuid = "0000FE2C-0000-1000-8000-00805F9B34FB";
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], R1, NULL);
        mk_ble(&s_ct_ble.devices[1], R2, NULL);
        s_ct_ble.devices[0].uuid128_name = kUuid;
        s_ct_ble.devices[1].uuid128_name = kUuid;
        pdc_build(NULL, 0, &s_ct_ble);
        const pdc_edge_t *e = ct_ble_edge(0, 1);
        ct_check("34f-3 random-addr shared UUID: product edge, not merged",
                 e && !e->can_union && e->evidence == PDC_EV_BLE_SERVICE_UUID &&
                 !ct_same_ble_cluster(0, 1) && pdc_cluster_count() == 0);
    }

    {
        const uint8_t R1[6] = {0xC2,0x01,0x02,0x03,0x04,0x05};
        const uint8_t R2[6] = {0xDA,0x06,0x07,0x08,0x09,0x0A};
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], R1, NULL);
        mk_ble(&s_ct_ble.devices[1], R2, NULL);
        for (int k = 0; k < 2; k++) {
            s_ct_ble.devices[k].has_rid = true;
            s_ct_ble.devices[k].drone.id_type = 1;
            strcpy(s_ct_ble.devices[k].drone.id, "SN-AIRCRAFT-001");
        }
        pdc_build(NULL, 0, &s_ct_ble);
        const pdc_edge_t *e = ct_ble_edge(0, 1);
        ct_check("34f-5 RID serial unions same aircraft",
                 e && e->can_union && e->evidence == PDC_EV_BLE_RID_ID &&
                 ct_same_ble_cluster(0, 1));

        s_ct_ble.devices[0].drone.id_type = 4;
        s_ct_ble.devices[1].drone.id_type = 4;
        pdc_build(NULL, 0, &s_ct_ble);
        ct_check("34f-5b session RID id does not union",
                 !ct_same_ble_cluster(0, 1) && pdc_cluster_count() == 0);
    }

    {
        const uint8_t R1[6] = {0xC2,0xAA,0xAA,0xAA,0xAA,0xAA};
        const uint8_t R2[6] = {0xD6,0xBB,0xBB,0xBB,0xBB,0xBB};
        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], R1, "Buds");
        mk_ble(&s_ct_ble.devices[1], R2, "Buds");
        s_ct_ble.devices[0].fastpair_model_id = 0x0A1B2C;
        s_ct_ble.devices[1].fastpair_model_id = 0x0A1B2C;
        s_ct_ble.devices[1].suppressed = true;
        pdc_build(NULL, 0, &s_ct_ble);
        ct_check("34f-6 suppressed BLE makes no edge",
                 ct_ble_edge(0, 1) == NULL && pdc_cluster_count() == 0);
    }

    ESP_LOGI(TAG, "── ecosystem co-presence tests ──");

    {
        const uint8_t ACC[6] = {0xC2,0x10,0x20,0x30,0x40,0x50};
        const uint8_t PHN[6] = {0xDA,0x60,0x70,0x80,0x90,0xA0};

        memset(&s_ct_ble, 0, sizeof(s_ct_ble));
        s_ct_ble.count = 2;
        mk_ble(&s_ct_ble.devices[0], ACC, "Buds");
        mk_ble(&s_ct_ble.devices[1], PHN, "Galaxy");
        s_ct_ble.devices[0].fastpair_model_id = 0x0A1B2C;
        s_ct_ble.devices[0].distance_dm       = 30;
        s_ct_ble.devices[1].class_source      = BLE_CLASS_SRC_NAME_RULE;
        s_ct_ble.devices[1].name_rule_class   = EUI_CLASS_PHONE;
        s_ct_ble.devices[1].mfg_company_id    = 0xFFFF;
        s_ct_ble.devices[1].distance_dm       = 50;
        pdc_build(NULL, 0, &s_ct_ble);
        const pdc_edge_t *e = ct_ble_edge(0, 1);
        ct_check("46d-1 accessory + near non-Apple phone: co-presence, not merged",
                 e && !e->can_union &&
                 e->evidence == PDC_EV_ECOSYSTEM_COPRESENCE &&
                 e->evclass == PDC_CLASS_RELATIONSHIP &&
                 !ct_same_ble_cluster(0, 1) && pdc_cluster_count() == 0);

        s_ct_ble.devices[1].mfg_company_id = 0x004C;
        pdc_build(NULL, 0, &s_ct_ble);
        ct_check("46d-2 Apple phone makes no co-presence edge",
                 ct_ble_edge(0, 1) == NULL);

        s_ct_ble.devices[1].mfg_company_id = 0xFFFF;
        s_ct_ble.devices[1].distance_dm    = 400;
        pdc_build(NULL, 0, &s_ct_ble);
        ct_check("46d-3 distant phone: proximity gate drops co-presence",
                 ct_ble_edge(0, 1) == NULL);
    }

    ESP_LOGI(TAG, "── vehicle grouping tests ──");

    const uint8_t V0[6] = {0x3C,0x5A,0xB4,0x55,0x66,0x77};
    const uint8_t VB[6] = {0x4F,0xAA,0xAA,0xAA,0xAA,0xAA};
    const uint8_t VC[6] = {0x5E,0xBB,0xBB,0xBB,0xBB,0xBB};

    mk_ap(&s_ct_aps[0], V0, "FordPass", 6, false, -55);
    s_ct_aps[0].device_class = EUI_CLASS_VEHICLE;
    strcpy(s_ct_aps[0].vendor, "Ford");
    memset(&s_ct_ble, 0, sizeof(s_ct_ble));
    s_ct_ble.count = 1;
    mk_ble(&s_ct_ble.devices[0], VB, "SYNC 3");
    s_ct_ble.devices[0].class_source   = BLE_CLASS_SRC_NAME_RULE;
    s_ct_ble.devices[0].name_rule_class = EUI_CLASS_VEHICLE;
    s_ct_ble.devices[0].name_rule_name  = "Ford (SYNC 3)";
    pdc_build(s_ct_aps, 1, &s_ct_ble);
    ct_check("48e-1 same-make Wi-Fi+BLE form a vehicle group",
             ct_same_vehicle(0, 0) && pdc_vehicle_cluster_count() == 1);
    ct_check("48e-1 vehicle group is not a physical cluster",
             pdc_cluster_count() == 0);

    mk_ap(&s_ct_aps[0], V0, "FordPass", 6, false, -55);
    s_ct_aps[0].device_class = EUI_CLASS_VEHICLE;
    strcpy(s_ct_aps[0].vendor, "Ford");
    memset(&s_ct_ble, 0, sizeof(s_ct_ble));
    s_ct_ble.count = 1;
    mk_ble(&s_ct_ble.devices[0], VB, "RAV4");
    s_ct_ble.devices[0].class_source   = BLE_CLASS_SRC_NAME_RULE;
    s_ct_ble.devices[0].name_rule_class = EUI_CLASS_VEHICLE;
    s_ct_ble.devices[0].name_rule_name  = "Toyota RAV4";
    pdc_build(s_ct_aps, 1, &s_ct_ble);
    ct_check("48e-2 different makes do not group",
             !ct_same_vehicle(0, 0) && pdc_vehicle_cluster_count() == 0);

    memset(&s_ct_ble, 0, sizeof(s_ct_ble));
    s_ct_ble.count = 2;
    mk_ble(&s_ct_ble.devices[0], VB, "FordPass");
    mk_ble(&s_ct_ble.devices[1], VC, "SYNC 3");
    for (int k = 0; k < 2; k++) {
        s_ct_ble.devices[k].class_source    = BLE_CLASS_SRC_NAME_RULE;
        s_ct_ble.devices[k].name_rule_class = EUI_CLASS_VEHICLE;
        s_ct_ble.devices[k].name_rule_name  = "Ford";
    }
    pdc_build(NULL, 0, &s_ct_ble);
    ct_check("48e-3 same-make BLE-only pair groups",
             pdc_vehicle_cluster_count() == 1 && pdc_cluster_count() == 0);

    ESP_LOGI(TAG, "── clustering: %d passed, %d failed ──", s_ct_pass, s_ct_fail);
}

static EXT_RAM_BSS_ATTR scan_results_t s_tw_results;
static EXT_RAM_BSS_ATTR ap_score_t     s_tw_scores[16];
static int s_tw_pass, s_tw_fail;

static void tw_check(const char *name, bool ok)
{
    if (ok) { s_tw_pass++; ESP_LOGI(TAG, "[PASS] %s", name); }
    else    { s_tw_fail++; ESP_LOGW(TAG, "[FAIL] %s", name); }
}

static void tw_drain(void) { vTaskDelay(pdMS_TO_TICKS(60)); }

static void tw_add(const char *ssid, const uint8_t bssid[6],
                   uint8_t channel, bool band_5g, int8_t rssi)
{
    uint16_t i = s_tw_results.count;
    if (i >= sizeof(s_tw_scores) / sizeof(s_tw_scores[0])) return;
    ap_record_t *e = &s_tw_results.entries[i];
    memset(e, 0, sizeof(*e));
    strncpy(e->ssid, ssid, sizeof(e->ssid) - 1);
    memcpy(e->bssid, bssid, 6);
    e->channel = channel;
    e->band_5g = band_5g;
    e->rssi    = rssi;
    e->auth    = WIFI_AUTH_WPA2_PSK;
    s_tw_results.count = i + 1;
}

static bool tw_is_ubnt(const uint8_t b[6])
{
    return (b[0] & ~0x02) == 0x60 && b[1] == 0x22 && b[2] == 0x32;
}

static bool tw_is_arris(const uint8_t b[6])
{
    return b[0] == 0xB4 && b[1] == 0x63 && b[2] == 0x6F;
}

static void tw_group_flags(uint16_t count, const char *ssid,
                           bool *seen, bool *any_twin, bool *any_vm)
{
    *seen = *any_twin = *any_vm = false;
    for (uint16_t i = 0; i < count; i++) {
        const ap_score_t *s = &s_tw_scores[i];
        if (strcmp(s->ssid, ssid) != 0) continue;
        *seen = true;
        if (s->twin_detected)   *any_twin = true;
        if (s->vendor_mismatch) *any_vm = true;
        ESP_LOGI(TAG, "   %s %02X:%02X:%02X:%02X:%02X:%02X vendor=\"%s\" twin=%d vm=%d threat=%d class=%s",
                 ssid, s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5],
                 s->vendor, s->twin_detected, s->vendor_mismatch, s->threat_level,
                 analyzer_twin_class(s));
    }
}

static void run_twin_tests(void)
{
    s_tw_pass = s_tw_fail = 0;
    ESP_LOGI(TAG, "── evil-twin false-positive fixtures ──");
    ESP_LOGI(TAG, "   [TARGET] checks encode the fix; all pass once 58b-58d are in");

    const uint8_t U1[6] = {0x60,0x22,0x32,0x8E,0x64,0xB2};
    const uint8_t U2[6] = {0x60,0x22,0x32,0x8A,0x65,0x2E};
    const uint8_t U3[6] = {0x60,0x22,0x32,0x94,0xFD,0x68};
    const uint8_t L1[6] = {0x62,0x22,0x32,0x9E,0x64,0xB3};
    const uint8_t L2[6] = {0x62,0x22,0x32,0x94,0xFD,0x69};
    const uint8_t L3[6] = {0x62,0x22,0x32,0x9A,0x65,0x2F};
    const uint8_t AR[6] = {0xB4,0x63,0x6F,0x4F,0x45,0x34};

    memset(&s_tw_results, 0, sizeof(s_tw_results));
    tw_add("PSP", U1, 6,   false, -48);
    tw_add("PSP", U2, 36,  true,  -60);
    tw_add("PSP", U3, 149, true,  -66);
    tw_add("PSP", L1, 36,  true,  -61);
    tw_add("PSP", L2, 149, true,  -67);
    tw_add("PSP", L3, 44,  true,  -70);
    tw_add("PSP", AR, 1,   false, -72);

    uint16_t count = 0;
    analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);

    bool ubnt_twin = false, ubnt_vm = false;
    bool arris_seen = false, arris_flagged = false;
    for (uint16_t i = 0; i < count; i++) {
        const ap_score_t *s = &s_tw_scores[i];
        if (strcmp(s->ssid, "PSP") != 0) continue;
        ESP_LOGI(TAG, "   PSP %02X:%02X:%02X:%02X:%02X:%02X vendor=\"%s\" twin=%d vm=%d threat=%d radios=%u class=%s",
                 s->bssid[0], s->bssid[1], s->bssid[2], s->bssid[3], s->bssid[4], s->bssid[5],
                 s->vendor, s->twin_detected, s->vendor_mismatch, s->threat_level, s->radio_count,
                 analyzer_twin_class(s));
        if (tw_is_ubnt(s->bssid)) {
            if (s->twin_detected)   ubnt_twin = true;
            if (s->vendor_mismatch) ubnt_vm = true;
        } else if (tw_is_arris(s->bssid)) {
            arris_seen = true;
            if (s->twin_detected || s->vendor_mismatch) arris_flagged = true;
        }
    }

    tw_check("PSP-1 [TARGET] Ubiquiti mesh/virtuals not twin_detected", !ubnt_twin);
    tw_check("PSP-2 [TARGET] Ubiquiti LAA no vendor_mismatch",          !ubnt_vm);
    tw_check("PSP-3 Arris second vendor stays visible (not suppressed)", arris_seen && arris_flagged);
    tw_drain();

    {
        const uint8_t T1[6] = {0xCC,0xBA,0xBD,0x6D,0x33,0xFA};
        const uint8_t T2[6] = {0x3C,0x52,0xA1,0x1B,0x69,0xEE};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("Ollieandtheivy", T1, 6,  false, -70);
        tw_add("Ollieandtheivy", T2, 36, true,  -74);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool seen, twin, vm;
        tw_group_flags(count, "Ollieandtheivy", &seen, &twin, &vm);
        tw_check("OLLIE-1 [TARGET] same TP-Link family not twin_detected",  seen && !twin);
        tw_check("OLLIE-2 [TARGET] same TP-Link family no vendor_mismatch", seen && !vm);
    }
    tw_drain();

    {
        const uint8_t G1[6] = {0xDC,0x8D,0x8A,0x16,0x17,0x44};
        const uint8_t G2[6] = {0xA0,0x2D,0x13,0x7E,0x60,0xD0};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("ATT2yaRG3t", G1, 1,  false, -78);
        tw_add("ATT2yaRG3t", G2, 36, true,  -82);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool seen, twin, vm;
        tw_group_flags(count, "ATT2yaRG3t", &seen, &twin, &vm);
        tw_check("ATT-1 [TARGET] ISP CPE multi-vendor not twin_detected", seen && !twin);
    }
    tw_drain();

    {
        const uint8_t F1[6] = {0xC8,0x9E,0x43,0xD7,0xD2,0x2A};
        const uint8_t F2[6] = {0xC8,0x9E,0x43,0xD7,0xD2,0x52};
        const uint8_t F3[6] = {0xCE,0x9E,0x43,0xD7,0xD2,0x51};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("LefkoffLaw", F1, 40, true, -90);
        tw_add("LefkoffLaw", F2, 40, true, -91);
        tw_add("LefkoffLaw", F3, 40, true, -93);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool seen, twin, vm;
        tw_group_flags(count, "LefkoffLaw", &seen, &twin, &vm);
        tw_check("LEFKOFF NETGEAR + blank-LAA virtual not twin_detected", seen && !twin);
    }
    tw_drain();

    {
        const uint8_t O1[6] = {0x8C,0x3B,0xAD,0xAA,0x83,0x6D};
        const uint8_t O2[6] = {0x92,0x3B,0xAD,0xAA,0x79,0xC0};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("ORBI67", O1, 1,  false, -95);
        tw_add("ORBI67", O2, 36, true,  -85);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool seen, twin, vm;
        tw_group_flags(count, "ORBI67", &seen, &twin, &vm);
        tw_check("ORBI67 NETGEAR + blank-LAA virtual not twin_detected", seen && !twin);
    }
    tw_drain();

    {
        const uint8_t M1[6] = {0xE4,0x55,0xA8,0x10,0x20,0x30};
        const uint8_t M2[6] = {0xE6,0x55,0xA8,0x10,0x20,0x31};
        const uint8_t M3[6] = {0xE2,0x55,0xA8,0x10,0x20,0x32};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("MerakiNet", M1, 6,  false, -52);
        tw_add("MerakiNet", M2, 36, true,  -58);
        tw_add("MerakiNet", M3, 44, true,  -60);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool twin = false;
        for (uint16_t i = 0; i < count; i++)
            if (strcmp(s_tw_scores[i].ssid, "MerakiNet") == 0 && s_tw_scores[i].twin_detected)
                twin = true;
        tw_check("MERAKI sibling pair not twin_detected", !twin);
    }
    tw_drain();

    {
        const uint8_t N1[6] = {0x28,0x80,0x88,0xAA,0xBB,0x10};
        const uint8_t N2[6] = {0xCA,0x80,0x88,0xAA,0xBB,0x12};
        memset(&s_tw_results, 0, sizeof(s_tw_results));
        tw_add("NETGEAR80", N1, 1,  false, -55);
        tw_add("NETGEAR80", N2, 36, true,  -61);
        count = 0;
        analyzer_run(&s_tw_results, NULL, s_tw_scores, &count);
        bool twin = false;
        for (uint16_t i = 0; i < count; i++)
            if (strcmp(s_tw_scores[i].ssid, "NETGEAR80") == 0 && s_tw_scores[i].twin_detected)
                twin = true;
        tw_check("NETGEAR sibling pair not twin_detected", !twin);
    }
    tw_drain();

    ESP_LOGI(TAG, "── evil-twin: %d passed, %d failed (expect 0 failed at/after 58d) ──",
             s_tw_pass, s_tw_fail);
}

static void twin_test_task(void *arg)
{
    run_twin_tests();
    xSemaphoreGive((SemaphoreHandle_t)arg);
    vTaskDelete(NULL);
}

static void run_twin_tests_offloaded(void)
{
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) { ESP_LOGW(TAG, "twin tests: no semaphore, skipped"); return; }
    if (xTaskCreate(twin_test_task, "sc_sttwin", 10240, done, 4, NULL) != pdPASS) {
        ESP_LOGW(TAG, "twin tests: task create failed, skipped");
    } else {
        xSemaphoreTake(done, portMAX_DELAY);
    }
    vSemaphoreDelete(done);
}

static int s_apple_pass, s_apple_fail;

static void apple_case(const char *label, uint8_t dc_lo, uint8_t dc_hi,
                       size_t body_len, apple_devcat_t expect)
{

    uint8_t payload[16] = {0};
    payload[0] = APPLE_SUB_HEY_SIRI;
    payload[1] = (uint8_t)body_len;
    if (body_len >= 6) { payload[2 + 4] = dc_lo; payload[2 + 5] = dc_hi; }
    size_t total = 2 + body_len;

    ble_device_t d;
    memset(&d, 0, sizeof(d));
    apple_continuity_decode(&d, payload, total);

    bool ok = (d.apple_devcat == (uint8_t)expect);
    if (ok) s_apple_pass++; else s_apple_fail++;
    const char *got = apple_devcat_label((apple_devcat_t)d.apple_devcat);
    const char *exp = apple_devcat_label(expect);
    ESP_LOGI(TAG, "[%-4s] %-26s -> devcat=%-12s expect=%s",
             ok ? "PASS" : "FAIL", label,
             got ? got : "(unknown)", exp ? exp : "(unknown)");
}

static void run_apple_tests(void)
{
    s_apple_pass = s_apple_fail = 0;
    ESP_LOGI(TAG, "── Apple Continuity Hey Siri tests ──");

    apple_case("Hey Siri iPhone (LE 02 00)",  0x02, 0x00, 7, APPLE_DEVCAT_IPHONE);
    apple_case("Hey Siri iPad (LE 03 00)",    0x03, 0x00, 7, APPLE_DEVCAT_IPAD);
    apple_case("Hey Siri HomePod (LE 07 00)", 0x07, 0x00, 7, APPLE_DEVCAT_HOMEPOD);
    apple_case("Hey Siri MacBook (LE 09 00)", 0x09, 0x00, 7, APPLE_DEVCAT_MACBOOK);
    apple_case("Hey Siri Watch (LE 0A 00)",   0x0A, 0x00, 7, APPLE_DEVCAT_WATCH);

    apple_case("Hey Siri iPhone (BE 00 02)",  0x00, 0x02, 7, APPLE_DEVCAT_IPHONE);

    apple_case("Hey Siri unknown (FF 00)",    0xFF, 0x00, 7, APPLE_DEVCAT_UNKNOWN);

    apple_case("Hey Siri truncated (len 4)",  0x02, 0x00, 4, APPLE_DEVCAT_UNKNOWN);
    ESP_LOGI(TAG, "── Apple tests: %d passed, %d failed ──",
             s_apple_pass, s_apple_fail);
}

static int s_ps_pass, s_ps_fail;

static void ps_check(const char *name, bool ok)
{
    if (ok) { s_ps_pass++; ESP_LOGI(TAG, "[PASS] %s", name); }
    else    { s_ps_fail++; ESP_LOGW(TAG, "[FAIL] %s", name); }
}

static void ps_eval_ble(ps_result_t *r, const char *const names[],
                        const char *const vendors[], int n)
{
    static ble_device_t d;
    public_safety_begin(r);
    for (int i = 0; i < n; i++) {
        uint8_t addr[6] = { 0xde, 0xad, 0x00, 0x00, 0x00, (uint8_t)i };
        mk_ble(&d, addr, names[i]);
        if (vendors && vendors[i])
            strncpy(d.vendor, vendors[i], sizeof(d.vendor) - 1);
        public_safety_eval_ble(&d, r);
    }
    public_safety_finalize(r);
}

static void ps_officers(uint16_t body, uint16_t taser,
                        uint16_t *low, uint16_t *high)
{
    static ble_device_t d;
    ps_result_t r;
    public_safety_begin(&r);
    uint16_t k = 0;
    for (uint16_t i = 0; i < body; i++, k++) {
        uint8_t a2[6] = { 0xb0, 0x01, 0, 0, 0, (uint8_t)k };
        mk_ble(&d, a2, "Axon Body 3");
        public_safety_eval_ble(&d, &r);
    }
    for (uint16_t i = 0; i < taser; i++, k++) {
        uint8_t a2[6] = { 0x7a, 0x5e, 0, 0, 0, (uint8_t)k };
        mk_ble(&d, a2, "TASER 7");
        public_safety_eval_ble(&d, &r);
    }
    public_safety_finalize(&r);
    *low  = r.estimated_officers_low;
    *high = r.estimated_officers_high;
}

static void run_public_safety_tests(void)
{
    s_ps_pass = s_ps_fail = 0;
    ESP_LOGI(TAG, "── public-safety detector tests ──");

    ps_result_t r;

    {
        const char *names[]   = { "TASER 7" };
        const char *vends[]   = { "Axon Enterprise Inc" };
        ps_eval_ble(&r, names, vends, 1);
        ps_check("TASER name -> confirmed/taser",
                 r.presence == PS_PRESENCE_CONFIRMED &&
                 r.device_counts[PS_DEV_TASER] == 1);
    }
    {
        const char *names[] = { "Axon Body 3" };
        ps_eval_ble(&r, names, NULL, 1);
        ps_check("Axon Body name -> confirmed/body_camera",
                 r.presence == PS_PRESENCE_CONFIRMED &&
                 r.device_counts[PS_DEV_BODY_CAMERA] == 1);
    }

    {
        const char *names[] = { "Front Door Cam" };
        const char *vends[] = { "Hikvision Digital Technology" };
        ps_eval_ble(&r, names, vends, 1);
        ps_check("generic camera vendor -> none",
                 r.presence == PS_PRESENCE_NONE && r.matches == 0);
    }
    {
        const char *names[] = { "Headset" };
        const char *vends[] = { "Motorola Mobility LLC" };
        ps_eval_ble(&r, names, vends, 1);
        ps_check("generic Motorola vendor -> none",
                 r.presence == PS_PRESENCE_NONE && r.matches == 0);
    }

    {
        const char *names[] = { "", "" };
        const char *vends[] = { "Axon Enterprise", "Axon Enterprise" };
        ps_eval_ble(&r, names, vends, 2);
        ps_check("bare Axon x2 -> likely/unknown (not confirmed)",
                 r.presence == PS_PRESENCE_LIKELY &&
                 r.device_counts[PS_DEV_UNKNOWN] == 2 &&
                 r.strong_matches == 0 &&
                 r.estimated_officers_low == 1 && r.estimated_officers_high == 2);
    }

    {
        uint16_t lo, hi;
        ps_officers(4, 3, &lo, &hi); ps_check("4 body + 3 taser -> 4", lo == 4 && hi == 4);
        ps_officers(2, 2, &lo, &hi); ps_check("2 body + 2 taser -> 2", lo == 2 && hi == 2);
        ps_officers(8, 0, &lo, &hi); ps_check("8 body + 0 taser -> 8", lo == 8 && hi == 8);
        ps_officers(0, 5, &lo, &hi); ps_check("0 body + 5 taser -> 5", lo == 5 && hi == 5);
    }

    ESP_LOGI(TAG, "── public-safety: %d passed, %d failed ──", s_ps_pass, s_ps_fail);
}

static int s_mr_pass, s_mr_fail;

static void mr_check(const char *name, bool ok)
{
    if (ok) { s_mr_pass++; ESP_LOGI(TAG, "[PASS] %s", name); }
    else    { s_mr_fail++; ESP_LOGW(TAG, "[FAIL] %s", name); }
}

static void mr_eval_ssid(mr_result_t *r, const char *ssid)
{
    static ap_score_t a;
    uint8_t mac[6] = { 0xa0, 0x01, 0, 0, 0, 0 };
    mk_ap(&a, mac, ssid, 6, false, -50);
    medical_responder_begin(r);
    medical_responder_eval_wifi(&a, r);
    medical_responder_finalize(r);
}

static void mr_eval_ble1(mr_result_t *r, const char *name, const char *vendor)
{
    static ble_device_t d;
    uint8_t addr[6] = { 0xb0, 0x01, 0, 0, 0, 0 };
    mk_ble(&d, addr, name);
    if (vendor) strncpy(d.vendor, vendor, sizeof(d.vendor) - 1);
    medical_responder_begin(r);
    medical_responder_eval_ble(&d, r);
    medical_responder_finalize(r);
}

static void run_medical_responder_tests(void)
{
    s_mr_pass = s_mr_fail = 0;
    ESP_LOGI(TAG, "── medical/EMS responder detector tests ──");

    mr_result_t r;

    mr_eval_ssid(&r, "American Medical Response 12");
    mr_check("AMR full name -> likely/ambulance_gateway",
             r.presence == MR_PRESENCE_LIKELY &&
             r.could_be_first_responder &&
             r.device_counts[MR_DEV_AMBULANCE_GATEWAY] == 1);

    mr_eval_ble1(&r, "LIFEPAK 15", NULL);
    mr_check("LIFEPAK -> likely/medical_monitor",
             r.presence == MR_PRESENCE_LIKELY &&
             r.device_counts[MR_DEV_MEDICAL_MONITOR] == 1);

    mr_eval_ble1(&r, "Monitor", "ZOLL Medical");
    mr_check("ZOLL vendor -> possible/medical_monitor",
             r.presence == MR_PRESENCE_POSSIBLE &&
             r.device_counts[MR_DEV_MEDICAL_MONITOR] == 1);

    mr_eval_ssid(&r, "FirstNet 5G");
    mr_check("FirstNet SSID -> possible/unknown + first responder",
             r.presence == MR_PRESENCE_POSSIBLE &&
             r.could_be_first_responder &&
             r.device_counts[MR_DEV_UNKNOWN] == 1);

    mr_eval_ssid(&r, "St Mary Hospital Guest");
    mr_check("hospital guest SSID -> none",
             r.presence == MR_PRESENCE_NONE && r.matches == 0);

    mr_eval_ssid(&r, "JEMSTUDIO-5G");
    mr_check("'EMS' substring in unrelated SSID -> none",
             r.presence == MR_PRESENCE_NONE && r.matches == 0);

    mr_eval_ble1(&r, "Axon Body 3", "Axon Enterprise");
    mr_check("LE-only Axon -> medical none",
             r.presence == MR_PRESENCE_NONE && r.matches == 0);

    ESP_LOGI(TAG, "── medical/EMS: %d passed, %d failed ──", s_mr_pass, s_mr_fail);
}

void self_test_run(const char *args)
{
    bool do_id = true, do_rid = true, do_cluster = true, do_twin = true,
         do_apple = true, do_ps = true, do_mr = true;
    if (args && args[0]) {

        bool only_id = strcmp(args, "id") == 0;
        bool only_rid = strcmp(args, "rid") == 0;
        bool only_cluster = strcmp(args, "cluster") == 0;
        bool only_twin = strcmp(args, "twin") == 0;
        bool only_apple = strcmp(args, "apple") == 0;
        bool only_ps = strcmp(args, "ps") == 0 || strcmp(args, "publicsafety") == 0;
        bool only_mr = strcmp(args, "mr") == 0 || strcmp(args, "medical") == 0;
        if (only_id || only_rid || only_cluster || only_twin || only_apple ||
            only_ps || only_mr) {
            do_id = only_id; do_rid = only_rid; do_cluster = only_cluster;
            do_twin = only_twin; do_apple = only_apple; do_ps = only_ps;
            do_mr = only_mr;
        }
    }
    ESP_LOGI(TAG, "==== self-test start ====");
    if (do_id)      run_id_tests();
    if (do_rid)     run_rid_tests();
    if (do_cluster) run_cluster_tests();
    if (do_twin)    run_twin_tests_offloaded();
    if (do_apple)   run_apple_tests();
    if (do_ps)      run_public_safety_tests();
    if (do_mr)      run_medical_responder_tests();
    ESP_LOGI(TAG, "==== self-test done ====");
}
