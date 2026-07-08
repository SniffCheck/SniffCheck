#include "capture_writer.h"
#include "public_safety_detect.h"
#include "medical_responder_detect.h"
#include "pcap_capture.h"

#include "capture_ring.h"
#include "physical_device_cluster.h"
#include "eui_db.h"
#include "ble_advise.h"
#include "apple_continuity.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const char *TAG = "sc_capwrt";

#ifndef SNIFFCHECK_FW_VERSION
#define SNIFFCHECK_FW_VERSION  "0.86.0-phase86"
#endif
#ifndef SNIFFCHECK_FW_COMMIT
#define SNIFFCHECK_FW_COMMIT   "dev"
#endif

#ifndef SNIFFCHECK_SCHEMA_VER
#define SNIFFCHECK_SCHEMA_VER  "1.29.0"
#endif

#define LINE_BUF  3072

static uint32_t            s_boot_count;
static int64_t             s_session_start_us;
static char                s_session_id[24];
static char               *s_line;
static SemaphoreHandle_t   s_writer_mtx;
static volatile uint16_t   s_last_scan;

const char *capture_writer_session_id(void)     { return s_session_id; }
const char *capture_writer_fw_version(void)     { return SNIFFCHECK_FW_VERSION; }
const char *capture_writer_schema_version(void) { return SNIFFCHECK_SCHEMA_VER; }
uint16_t    capture_writer_last_scan(void)      { return s_last_scan; }

static inline int64_t now_us(void) { return esp_timer_get_time(); }

static int append_mac(char *dst, size_t n, const uint8_t m[6])
{
    return snprintf(dst, n, "%02x:%02x:%02x:%02x:%02x:%02x",
                    m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void json_escape(const char *in, char *out, size_t out_sz)
{
    size_t o = 0;
    if (out_sz == 0) return;
    while (*in && o + 7 < out_sz) {
        unsigned char c = (unsigned char)*in++;
        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20) {
                o += snprintf(out + o, out_sz - o, "\\u%04x", c);
            } else {
                out[o++] = (char)c;
            }
        }
    }
    out[o] = '\0';
}

static const char *auth_str(wifi_auth_mode_t a)
{
    switch (a) {
    case WIFI_AUTH_OPEN:           return "open";
    case WIFI_AUTH_WEP:            return "wep";
    case WIFI_AUTH_WPA_PSK:        return "wpa-psk";
    case WIFI_AUTH_WPA2_PSK:       return "wpa2-psk";
    case WIFI_AUTH_WPA_WPA2_PSK:   return "wpa-wpa2-psk";
    case WIFI_AUTH_ENTERPRISE:     return "wpa2-eap";
    case WIFI_AUTH_WPA3_PSK:       return "wpa3-sae";
    case WIFI_AUTH_WPA2_WPA3_PSK:  return "wpa2-wpa3-mixed";
    case WIFI_AUTH_WAPI_PSK:       return "wapi-psk";
    default:                       return "unknown";
    }
}

static const char *addr_subtype_str(ble_addr_subtype_t s)
{
    switch (s) {
    case BLE_ADDR_SUB_PUBLIC:        return "public";
    case BLE_ADDR_SUB_STATIC_RANDOM: return "static_random";
    case BLE_ADDR_SUB_RPA:           return "rpa";
    case BLE_ADDR_SUB_NRPA:          return "nrpa";
    default:                         return "unknown";
    }
}

static const char *class_source_str(uint8_t cs)
{
    switch (cs) {
    case BLE_CLASS_SRC_NONE:          return "none";
    case BLE_CLASS_SRC_MFG_RULE:      return "mfg_rule";
    case BLE_CLASS_SRC_UUID128:       return "uuid128";
    case BLE_CLASS_SRC_APPLE_SUBTYPE: return "apple_subtype";
    case BLE_CLASS_SRC_MS_SUBTYPE:    return "ms_subtype";
    case BLE_CLASS_SRC_BT_COMPANY:    return "bt_company";
    case BLE_CLASS_SRC_MAC_OUI:       return "mac_oui";
    case BLE_CLASS_SRC_NAME_RULE:     return "name_rule";
    case BLE_CLASS_SRC_DRONE_RID:     return "drone_rid";
    case BLE_CLASS_SRC_UUID16:        return "uuid16";
    default:                          return "none";
    }
}

typedef struct {
    const char *rule_id;
    const char *severity;
    const char *target_kind;
    const char *message;
} threat_rule_t;
static int collect_ap_threat_rules(const ap_score_t *ap, threat_rule_t *out);
static int collect_ble_threat_rules(const ble_device_t *d, threat_rule_t *out);
static int append_threat_rule_ids(char *line, int n,
                                  const threat_rule_t *r, int count);
#define THREAT_RULES_MAX 12

static const char *ssid_cat_str(ssid_category_t c)
{
    switch (c) {
    case SSID_CAT_PII:       return "pii";
    case SSID_CAT_CORPORATE: return "corporate";
    case SSID_CAT_HOTEL:     return "hotel";
    case SSID_CAT_AIRPORT:   return "airport";
    case SSID_CAT_ISP:       return "isp";
    case SSID_CAT_GENERIC:   return "generic";
    case SSID_CAT_HIDDEN:    return "hidden";
    default:                 return "other";
    }
}

static const char *end_reason_str(capture_end_reason_t r)
{
    switch (r) {
    case CAP_END_USER_DISABLE: return "user_disable";
    case CAP_END_TIMEOUT:      return "timeout";
    case CAP_END_ROTATION:     return "rotation";
    case CAP_END_SCAN_START:   return "scan_start";
    case CAP_END_IMPORT:       return "import";
    default:                   return "shutdown";
    }
}

static const char *tracker_kind_for(const ble_device_t *d)
{
    if (!d) return NULL;

    if (d->is_airtag) return "find_my_other";
    for (uint8_t i = 0; i < d->num_uuids16; i++) {
        if (d->uuids16[i] == 0xFEED) return "tile";
    }
    if (ble_effective_class(d) == EUI_CLASS_TRACKER) return "generic";
    return NULL;
}

void capture_writer_init(uint32_t boot_count)
{
    s_boot_count = boot_count;
    s_session_start_us = now_us();
    if (!s_line) {
        s_line = heap_caps_malloc(LINE_BUF, MALLOC_CAP_SPIRAM);
    }
    if (!s_writer_mtx) {
        s_writer_mtx = xSemaphoreCreateMutex();
    }
    if (!s_line || !s_writer_mtx) {
        ESP_LOGE(TAG, "writer init alloc failed (line=%p mtx=%p) — emits disabled",
                 s_line, s_writer_mtx);
    }

    snprintf(s_session_id, sizeof(s_session_id), "boot%04u-%08llx",
             (unsigned)(boot_count & 0xFFFF), (long long)s_session_start_us);
    ESP_LOGI(TAG, "session_id=%s (raw capture — no redaction)", s_session_id);
}

static char *line_lock(void)
{
    if (!s_line || !s_writer_mtx) return NULL;
    xSemaphoreTake(s_writer_mtx, portMAX_DELAY);
    return s_line;
}

static void line_unlock(void)
{
    if (s_writer_mtx) xSemaphoreGive(s_writer_mtx);
}

void capture_emit_header(void)
{
    esp_chip_info_t info;
    esp_chip_info(&info);
    char hw_rev[8];
    snprintf(hw_rev, sizeof(hw_rev), "v%u.%u",
             (unsigned)(info.revision / 100), (unsigned)(info.revision % 100));

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"header\",\"ts_us\":%lld,\"schema_version\":\"%s\","
        "\"device\":{\"model\":\"T-Dongle C5\",\"chip\":\"esp32-c5\","
        "\"fw_version\":\"%s\",\"fw_commit\":\"%s\",\"hw_rev\":\"%s\"},"
        "\"session\":{\"session_id\":\"%s\",\"start_us\":%lld,\"boot_count\":%u,"
        "\"redaction_tier\":\"none\",\"advisor_mode\":\"adv\",\"psram_enabled\":true}}",
        (long long)s_session_start_us, SNIFFCHECK_SCHEMA_VER,
        SNIFFCHECK_FW_VERSION, SNIFFCHECK_FW_COMMIT, hw_rev,
        s_session_id, (long long)s_session_start_us, (unsigned)s_boot_count);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_codebook(void)
{
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"codebook\",\"ts_us\":%lld,\"schema_version\":\"%s\",\"enums\":{",
        (long long)now_us(), SNIFFCHECK_SCHEMA_VER);

    n += snprintf(line + n, LINE_BUF - n, "\"device_class\":{");
    for (uint8_t c = 0; c <= EUI_CLASS_SURVEILLANCE_OUI; c++) {
        const char *lbl = eui_class_label(c);
        if (!lbl[0]) lbl = "unknown";
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      c ? "," : "", c, lbl);
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"verdict\":{");
    for (uint8_t v = VERDICT_GREEN; v <= VERDICT_RED; v++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      v ? "," : "", v, analyzer_verdict_label(v));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"tier\":{");
    for (uint8_t t = SCORE_TIER_ENTERPRISE; t <= SCORE_TIER_AVOID; t++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      t ? "," : "", t, analyzer_tier_label(t));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"class_source\":{");
    for (uint8_t s = BLE_CLASS_SRC_NONE; s <= BLE_CLASS_SRC_UUID16; s++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      s ? "," : "", s, class_source_str(s));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"addr_subtype\":{");
    for (uint8_t a = BLE_ADDR_SUB_PUBLIC; a <= BLE_ADDR_SUB_NRPA; a++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      a ? "," : "", a, addr_subtype_str(a));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"ssid_category\":{");
    for (uint8_t c = 0; c < SSID_CAT_COUNT; c++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      c ? "," : "", c, ssid_cat_str((ssid_category_t)c));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"threat_level\":{");
    for (uint8_t t = THREAT_NONE; t <= THREAT_HIGH; t++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      t ? "," : "", t, analyzer_threat_label(t));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"cluster_evidence\":{");
    for (uint8_t e = 0; e < PDC_EV_COUNT; e++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      e ? "," : "", e, pdc_evidence_label(e));
    }
    n += snprintf(line + n, LINE_BUF - n, "},");

    n += snprintf(line + n, LINE_BUF - n, "\"cluster_evidence_class\":{");
    for (uint8_t k = 0; k < PDC_CLASS_COUNT; k++) {
        n += snprintf(line + n, LINE_BUF - n, "%s\"%u\":\"%s\"",
                      k ? "," : "", k, pdc_class_label(k));
    }
    n += snprintf(line + n, LINE_BUF - n, "}}}");

    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

static void capture_emit_wifi_ap_internal(const ap_score_t *ap, uint16_t scan_index,
                                          const char *source, uint32_t walk_id)
{
    if (!ap || ap->suppressed) return;
    s_last_scan = scan_index;
    char *line = line_lock();
    if (!line) return;
    char bssid[24];
    char ssid_esc[68];
    append_mac(bssid, sizeof(bssid), ap->bssid);
    json_escape(ap->ssid, ssid_esc, sizeof(ssid_esc));

    char vendor_esc[96];
    json_escape(ap->vendor, vendor_esc, sizeof(vendor_esc));

    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"wifi_ap\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%u,\"band_5g\":%s,\"rssi\":%d,"
        "\"vendor\":\"%s\",\"vendor_match_len\":%u,\"device_class\":%u,\"eui_flags\":%u,"
        "\"auth\":\"%s\",\"has_wps\":%s,\"has_rsn\":%s,\"rsn_pmf_required\":%s,"
        "\"pmkid_exposed\":%s,"
        "\"beacon_interval\":%u,\"ie_pattern_hash\":%u,"
        "\"radio_count\":%u,\"same_oui_multiband\":%s,"
        "\"lldp_count\":%u,\"cdp_count\":%u,\"dhcp_count\":%u,"
        "\"ble_match\":%d,\"ble_match_conf\":%u,"
        "\"first_seen_scan\":%u,\"last_seen_scan\":%u,\"hit_count\":%u,"
        "\"identity_score\":%u,\"identity_conf\":%u,\"threat_level\":%u,"
        "\"twin_class\":\"%s\"",
        (long long)now_us(), scan_index,
        bssid, ssid_esc, ap->channel, ap->band_5g ? "true" : "false", ap->rssi,
        vendor_esc, ap->mac_match_len, ap->device_class, ap->eui_flags,
        auth_str(ap->auth),
        ap->has_wps ? "true" : "false",
        ap->has_rsn ? "true" : "false",
        ap->rsn_pmf_required ? "true" : "false",
        ap->pmkid_exposed ? "true" : "false",
        ap->beacon_interval, (unsigned)ap->ie_pattern_hash,
        ap->radio_count, ap->same_oui_multiband ? "true" : "false",
        ap->lldp_count, ap->cdp_count, ap->dhcp_count,
        ap->ble_match, ap->ble_match_conf,
        ap->first_seen_scan, ap->last_seen_scan, ap->hit_count,
        ap->identity_score, ap->identity_conf, ap->threat_level,
        analyzer_twin_class(ap));

    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    if (source && source[0]) {
        int wr = snprintf(line + n, LINE_BUF - n,
                          ",\"source\":\"%s\",\"walk_id\":%u",
                          source, (unsigned)walk_id);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->country_code[0]) {
        char cc_esc[16];
        json_escape(ap->country_code, cc_esc, sizeof(cc_esc));
        int wr = snprintf(line + n, LINE_BUF - n, ",\"country_code\":\"%s\"", cc_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->has_rsn) {
        int wr = snprintf(line + n, LINE_BUF - n,
            ",\"rsn_group_oui\":\"%02x:%02x:%02x\",\"rsn_group_suite\":%u",
            ap->rsn_group_oui[0], ap->rsn_group_oui[1], ap->rsn_group_oui[2],
            ap->rsn_group_suite);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->has_wps && (ap->wps_manufacturer[0] || ap->wps_model_name[0])) {
        char man_esc[68], mod_esc[68];
        json_escape(ap->wps_manufacturer, man_esc, sizeof(man_esc));
        json_escape(ap->wps_model_name,   mod_esc, sizeof(mod_esc));
        int wr = snprintf(line + n, LINE_BUF - n,
            ",\"wps_manufacturer\":\"%s\",\"wps_model_name\":\"%s\"",
            man_esc, mod_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->vendor_ie_count > 0) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"vendor_ie_ouis\":[");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
        for (uint8_t i = 0; i < ap->vendor_ie_count && i < 4; i++) {
            wr = snprintf(line + n, LINE_BUF - n, "%s\"%02x:%02x:%02x\"",
                          i ? "," : "",
                          ap->vendor_ie_ouis[i][0], ap->vendor_ie_ouis[i][1],
                          ap->vendor_ie_ouis[i][2]);
            if (wr <= 0 || n + wr >= LINE_BUF - 4) { line_unlock(); return; }
            n += wr;
        }
        wr = snprintf(line + n, LINE_BUF - n, "],\"vendor_ie_names\":[");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
        for (uint8_t i = 0; i < ap->vendor_ie_count && i < 4; i++) {
            char nm_esc[64];
            json_escape(ap->vendor_ie_names[i] ? ap->vendor_ie_names[i] : "",
                        nm_esc, sizeof(nm_esc));
            wr = snprintf(line + n, LINE_BUF - n, "%s%s%s%s",
                          i ? "," : "",
                          nm_esc[0] ? "\"" : "", nm_esc[0] ? nm_esc : "null",
                          nm_esc[0] ? "\"" : "");
            if (wr <= 0 || n + wr >= LINE_BUF - 4) { line_unlock(); return; }
            n += wr;
        }
        wr = snprintf(line + n, LINE_BUF - n, "]");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->l2l3_signal_count > 0) {
        char cdp_esc[68], lldp_esc[68], dhcp_esc[68];
        json_escape(ap->cdp_device_id,    cdp_esc,  sizeof(cdp_esc));
        json_escape(ap->lldp_system_name, lldp_esc, sizeof(lldp_esc));
        json_escape(ap->dhcp_vendor_class,dhcp_esc, sizeof(dhcp_esc));
        int wr = snprintf(line + n, LINE_BUF - n,
            ",\"l2l3\":{\"signal_count\":%u,\"class\":%u,\"flags\":%u,"
            "\"cdp_device_id\":\"%s\",\"lldp_system_name\":\"%s\","
            "\"dhcp_vendor_class\":\"%s\"}",
            ap->l2l3_signal_count, ap->l2l3_class, ap->l2l3_flags,
            cdp_esc, lldp_esc, dhcp_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (ap->sibling_count > 0) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"radio_siblings\":[");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
        for (uint8_t i = 0; i < ap->sibling_count && i < AP_MAX_SIBLINGS; i++) {
            const radio_sibling_t *sib = &ap->siblings[i];
            char sb[24];
            append_mac(sb, sizeof(sb), sib->bssid);
            wr = snprintf(line + n, LINE_BUF - n,
                "%s{\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%u,\"band_5g\":%s}",
                i ? "," : "", sb, sib->rssi, sib->channel,
                sib->band_5g ? "true" : "false");
            if (wr <= 0 || n + wr >= LINE_BUF - 4) { line_unlock(); return; }
            n += wr;
        }
        wr = snprintf(line + n, LINE_BUF - n, "]");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    {
        threat_rule_t rules[THREAT_RULES_MAX];
        int rc = collect_ap_threat_rules(ap, rules);
        n = append_threat_rule_ids(line, n, rules, rc);
        if (n < 0) { line_unlock(); return; }
    }

    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_wifi_ap(const ap_score_t *ap, uint16_t scan_index)
{
    capture_emit_wifi_ap_internal(ap, scan_index, NULL, 0);
}

void capture_emit_wifi_ap_walk(const ap_score_t *ap, uint16_t scan_index, uint32_t walk_id)
{
    capture_emit_wifi_ap_internal(ap, scan_index, "walk", walk_id);
}

static uint8_t byos_threat_level(uint16_t flags)
{
    if (flags & EUI_FLAG_KNOWN_MALICIOUS) return THREAT_HIGH;
    if (flags & (EUI_FLAG_SURVEILLANCE | EUI_FLAG_INVESTIGATION | EUI_FLAG_FCC_COVERED))
        return THREAT_MEDIUM;
    return THREAT_NONE;
}

static bool byos_contains_ci(const char *s, const char *needle)
{
    if (!s || !needle || !needle[0]) return false;
    size_t nl = strlen(needle);
    for (const char *p = s; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nl) return true;
    }
    return false;
}

static const char *byos_auth_label(const char *raw)
{
    if (!raw || !raw[0]) return "unknown";
    if (byos_contains_ci(raw, "WEP")) return "wep";
    if (byos_contains_ci(raw, "WPA3") && byos_contains_ci(raw, "WPA2"))
        return "wpa2-wpa3-mixed";
    if (byos_contains_ci(raw, "WPA3")) return "wpa3-sae";
    if (byos_contains_ci(raw, "WPA2")) return "wpa2-psk";
    if (byos_contains_ci(raw, "WPA")) return "wpa-psk";
    if (byos_contains_ci(raw, "OPEN") || byos_contains_ci(raw, "ESS")) return "open";
    return "unknown";
}

static uint8_t byos_identity_score(const char *vendor, uint8_t cls,
                                   uint8_t match_len, uint16_t flags)
{
    uint8_t score = 20;
    if (vendor && vendor[0]) score += 35;
    if (cls != EUI_CLASS_UNKNOWN) score += 25;
    if (match_len >= 36) score += 10;
    else if (match_len >= 28) score += 6;
    else if (match_len >= 24) score += 3;
    if (flags & EUI_FLAG_PRIVATE_ASSIGN) score = 25;
    return score > 95 ? 95 : score;
}

static uint8_t byos_wifi_identity_score(const char *vendor, uint8_t cls,
                                        uint8_t match_len, uint16_t flags,
                                        const char *ssid, uint8_t channel,
                                        int8_t rssi, const char *auth)
{
    int score = byos_identity_score(vendor, cls, match_len, flags);
    if (ssid && ssid[0]) score += 10;
    if (channel > 0) score += 5;
    if (rssi < 0) score += 5;
    if (auth && strstr(auth, "wpa3")) score += 10;
    else if (auth && strstr(auth, "wpa2")) score += 8;
    else if (auth && strstr(auth, "wpa")) score += 5;
    else if (auth && strcmp(auth, "wep") == 0) score -= 15;
    if (score < 0) score = 0;
    if (score > 95) score = 95;
    return (uint8_t)score;
}

static uint8_t byos_ble_identity_score(const char *vendor, uint8_t cls,
                                       uint8_t match_len, uint16_t flags,
                                       const char *name, const char *name_rule)
{
    int score = 15;
    if (vendor && vendor[0]) score += 30;
    if (cls != EUI_CLASS_UNKNOWN) score += 25;
    if (name && name[0]) score += 20;
    if (name_rule && name_rule[0]) score += 20;
    if (match_len >= 36) score += 10;
    else if (match_len >= 28) score += 6;
    else if (match_len >= 24) score += 3;
    if ((flags & EUI_FLAG_PRIVATE_ASSIGN) && !(name && name[0]) && !(name_rule && name_rule[0]))
        score = 25;
    if (score > 95) score = 95;
    return (uint8_t)score;
}

static uint8_t byos_vendor_conf(const char *vendor, uint8_t match_len)
{
    if (!vendor || !vendor[0]) return 0;
    if (match_len >= 36) return 95;
    if (match_len >= 28) return 85;
    return 75;
}

static ble_addr_subtype_t byos_ble_addr_subtype(const uint8_t addr[6])
{
    if (!addr || !mac_is_laa(addr)) return BLE_ADDR_SUB_PUBLIC;
    switch (addr[0] & 0xC0) {
    case 0xC0: return BLE_ADDR_SUB_STATIC_RANDOM;
    case 0x40: return BLE_ADDR_SUB_RPA;
    default:   return BLE_ADDR_SUB_NRPA;
    }
}

static int8_t byos_best_rssi(const capture_byos_sight_t *sg, uint8_t cnt)
{
    int8_t best = 0;
    bool any = false;
    for (uint8_t i = 0; i < cnt; i++) {
        if (!any || sg[i].rssi > best) { best = sg[i].rssi; any = true; }
    }
    return any ? best : 0;
}

static int byos_append_sources(char *line, int n, const capture_byos_sight_t *sg, uint8_t cnt)
{
    if (!sg || cnt == 0) return n;
    int wr = snprintf(line + n, LINE_BUF - n, ",\"sources\":[");
    if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
    n += wr;
    for (uint8_t i = 0; i < cnt; i++) {
        char id_esc[36];
        json_escape(sg[i].source_id, id_esc, sizeof(id_esc));
        wr = snprintf(line + n, LINE_BUF - n, "%s{\"id\":\"%s\",\"rssi\":%d",
                      i ? "," : "", id_esc, sg[i].rssi);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
        n += wr;
        if (sg[i].has_pos) {
            wr = snprintf(line + n, LINE_BUF - n, ",\"lat\":%.7f,\"lon\":%.7f",
                          sg[i].lat_e7 / 1e7, sg[i].lon_e7 / 1e7);
            if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
            n += wr;
        }
        if (sg[i].has_ts) {
            wr = snprintf(line + n, LINE_BUF - n, ",\"ts\":%u", (unsigned)sg[i].ts_s);
            if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
            n += wr;
        }
        wr = snprintf(line + n, LINE_BUF - n, "}");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
        n += wr;
    }
    wr = snprintf(line + n, LINE_BUF - n, "]");
    if (wr <= 0 || n + wr >= LINE_BUF - 2) return -1;
    return n + wr;
}

void capture_emit_byos_mac(const uint8_t mac[6], uint16_t scan_index,
                           uint32_t import_id, uint16_t import_index,
                           const capture_byos_sight_t *sights, uint8_t n_sight)
{
    if (!mac) return;
    s_last_scan = scan_index;

    uint16_t flags = 0;
    uint8_t cls = EUI_CLASS_UNKNOWN;
    uint8_t match_len = 0;
    const char *vendor = eui_lookup_mac(mac, &flags, &cls, &match_len);
    uint8_t threat = byos_threat_level(flags);
    uint8_t ident = byos_identity_score(vendor, cls, match_len, flags);
    uint8_t conf = byos_vendor_conf(vendor, match_len);
    if (conf == 0) conf = 20;

    char bssid[24];
    append_mac(bssid, sizeof(bssid), mac);
    char vendor_esc[96];
    json_escape(vendor ? vendor : "", vendor_esc, sizeof(vendor_esc));
    const char *note = "BYOS MAC-only import decoded by on-device eui.db; source type and RF checks unavailable";

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"wifi_ap\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"bssid\":\"%s\",\"ssid\":\"BYOS MAC import\",\"channel\":0,\"band_5g\":false,\"rssi\":0,"
        "\"vendor\":\"%s\",\"vendor_match_len\":%u,\"device_class\":%u,\"eui_flags\":%u,"
        "\"auth\":\"unknown\",\"has_wps\":false,\"has_rsn\":false,\"rsn_pmf_required\":false,"
        "\"pmkid_exposed\":false,\"beacon_interval\":0,\"ie_pattern_hash\":0,"
        "\"radio_count\":1,\"same_oui_multiband\":false,"
        "\"lldp_count\":0,\"cdp_count\":0,\"dhcp_count\":0,"
        "\"ble_match\":-1,\"ble_match_conf\":0,"
        "\"first_seen_scan\":%u,\"last_seen_scan\":%u,\"hit_count\":1,"
        "\"identity_score\":%u,\"identity_conf\":%u,\"threat_level\":%u,"
        "\"source\":\"byos\",\"import_id\":%u,\"import_index\":%u,"
        "\"import_note\":\"%s\",\"threat_rule_ids\":[]",
        (long long)now_us(), scan_index,
        bssid, vendor_esc, match_len, cls, flags,
        scan_index, scan_index, ident, conf, threat,
        (unsigned)import_id, (unsigned)import_index, note);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    n = byos_append_sources(line, n, sights, n_sight);
    if (n < 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n] = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_byos_wifi(const uint8_t bssid_raw[6], uint16_t scan_index,
                            uint32_t import_id, uint16_t import_index,
                            const char *ssid, uint8_t channel,
                            const char *auth_raw,
                            const capture_byos_sight_t *sights, uint8_t n_sight)
{
    if (!bssid_raw) return;
    s_last_scan = scan_index;
    int8_t rssi = byos_best_rssi(sights, n_sight);

    uint16_t mac_flags = 0, ssid_flags = 0;
    uint8_t mac_cls = EUI_CLASS_UNKNOWN, ssid_cls = EUI_CLASS_UNKNOWN;
    uint8_t match_len = 0;
    const char *vendor = eui_lookup_mac(bssid_raw, &mac_flags, &mac_cls, &match_len);
    const char *ssid_rule = (ssid && ssid[0]) ? eui_match_ssid(ssid, &ssid_flags, &ssid_cls) : NULL;
    uint16_t flags = mac_flags | ssid_flags;
    uint8_t cls = mac_cls != EUI_CLASS_UNKNOWN ? mac_cls : ssid_cls;
    const char *auth = byos_auth_label(auth_raw);
    bool has_rsn = auth && strncmp(auth, "wpa", 3) == 0;
    bool pmf_required = auth && strstr(auth, "wpa3") != NULL;
    uint8_t threat = byos_threat_level(flags);
    uint8_t ident = byos_wifi_identity_score(vendor, cls, match_len, flags, ssid,
                                             channel, rssi, auth);
    uint8_t conf = byos_vendor_conf(vendor, match_len);
    if (ssid_rule && ssid_rule[0] && conf < 70) conf = 70;
    if (conf == 0 && (ssid && ssid[0])) conf = 35;

    char bssid[24], ssid_esc[68], vendor_esc[96], auth_raw_esc[48], ssid_rule_esc[68];
    append_mac(bssid, sizeof(bssid), bssid_raw);
    json_escape(ssid ? ssid : "", ssid_esc, sizeof(ssid_esc));
    json_escape(vendor ? vendor : "", vendor_esc, sizeof(vendor_esc));
    json_escape(auth_raw ? auth_raw : "", auth_raw_esc, sizeof(auth_raw_esc));
    json_escape(ssid_rule ? ssid_rule : "", ssid_rule_esc, sizeof(ssid_rule_esc));
    const char *note = "BYOS Wi-Fi import decoded from external scan by on-device eui.db; active RF-only checks unavailable";

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"wifi_ap\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%u,\"band_5g\":%s,\"rssi\":%d,"
        "\"vendor\":\"%s\",\"vendor_match_len\":%u,\"device_class\":%u,\"eui_flags\":%u,"
        "\"auth\":\"%s\",\"has_wps\":false,\"has_rsn\":%s,\"rsn_pmf_required\":%s,"
        "\"pmkid_exposed\":false,\"beacon_interval\":0,\"ie_pattern_hash\":0,"
        "\"radio_count\":1,\"same_oui_multiband\":false,"
        "\"lldp_count\":0,\"cdp_count\":0,\"dhcp_count\":0,"
        "\"ble_match\":-1,\"ble_match_conf\":0,"
        "\"first_seen_scan\":%u,\"last_seen_scan\":%u,\"hit_count\":1,"
        "\"identity_score\":%u,\"identity_conf\":%u,\"threat_level\":%u,"
        "\"source\":\"byos\",\"import_id\":%u,\"import_index\":%u,"
        "\"import_note\":\"%s\",\"threat_rule_ids\":[]",
        (long long)now_us(), scan_index,
        bssid, ssid_esc, channel, channel > 14 ? "true" : "false", rssi,
        vendor_esc, match_len, cls, flags,
        auth, has_rsn ? "true" : "false", pmf_required ? "true" : "false",
        scan_index, scan_index, ident, conf, threat,
        (unsigned)import_id, (unsigned)import_index, note);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    if (auth_raw_esc[0] && strcmp(auth_raw_esc, auth) != 0) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"auth_raw\":\"%s\"", auth_raw_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }
    if (ssid_rule_esc[0]) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"ssid_rule_name\":\"%s\"", ssid_rule_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }
    n = byos_append_sources(line, n, sights, n_sight);
    if (n < 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n] = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

static int append_phone_model(char *buf, int cap, uint8_t eff_class,
                              const char *name_rule_name, uint8_t name_rule_kind,
                              uint8_t apple_devcat);

void capture_emit_byos_ble(const uint8_t addr_raw[6], uint16_t scan_index,
                           uint32_t import_id, uint16_t import_index,
                           const char *name,
                           const capture_byos_sight_t *sights, uint8_t n_sight)
{
    if (!addr_raw) return;
    s_last_scan = scan_index;
    int8_t rssi = byos_best_rssi(sights, n_sight);

    uint16_t mac_flags = 0, name_flags = 0;
    uint8_t mac_cls = EUI_CLASS_UNKNOWN, name_cls = EUI_CLASS_UNKNOWN;
    uint8_t name_kind = EUI_NAME_RULE_GENERIC;
    uint8_t match_len = 0;
    const char *vendor = eui_lookup_mac(addr_raw, &mac_flags, &mac_cls, &match_len);
    const char *name_rule = (name && name[0]) ? eui_match_name(name, &name_flags, &name_cls, &name_kind) : NULL;
    uint16_t flags = mac_flags | name_flags;
    uint8_t cls = name_cls != EUI_CLASS_UNKNOWN ? name_cls : mac_cls;
    uint8_t class_source = name_cls != EUI_CLASS_UNKNOWN ? BLE_CLASS_SRC_NAME_RULE :
                           (mac_cls != EUI_CLASS_UNKNOWN ? BLE_CLASS_SRC_MAC_OUI : BLE_CLASS_SRC_NONE);
    uint8_t vendor_conf = byos_vendor_conf(vendor, match_len);
    uint8_t class_conf = name_cls != EUI_CLASS_UNKNOWN ? 70 :
                         (mac_cls != EUI_CLASS_UNKNOWN ? (match_len >= 36 ? 80 : match_len >= 28 ? 65 : 50) : 0);
    uint8_t ident = byos_ble_identity_score(vendor, cls, match_len, flags, name, name_rule);
    uint8_t conf = vendor_conf > class_conf ? vendor_conf : class_conf;
    if (conf == 0 && name && name[0]) conf = 35;
    uint8_t threat = byos_threat_level(flags);

    char addr[24], name_esc[68], vendor_esc[68], name_rule_esc[68];
    append_mac(addr, sizeof(addr), addr_raw);
    json_escape(name ? name : "", name_esc, sizeof(name_esc));
    json_escape(vendor ? vendor : "", vendor_esc, sizeof(vendor_esc));
    json_escape(name_rule ? name_rule : "", name_rule_esc, sizeof(name_rule_esc));
    const char *note = "BYOS BLE import decoded from external scan by on-device eui.db; advertisement-payload checks unavailable";

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"ble_device\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"addr\":\"%s\",\"addr_subtype\":\"%s\",\"rssi\":%d,\"tx_power\":127,\"prim_phy\":0,"
        "\"name\":%s%s%s,\"vendor\":\"%s\",\"vendor_conf\":%u,\"class_conf\":%u,"
        "\"class_source\":\"%s\",\"device_class\":%u,\"mac_match_len\":%u,"
        "\"uuid16_flags\":0,\"wifi_match\":-1,\"eui_flags\":%u,"
        "\"source\":\"byos\",\"import_id\":%u,\"import_index\":%u,"
        "\"num_uuids32\":0,\"num_uuids128\":0,\"scannable\":false,"
        "\"identity_score\":%u,\"identity_conf\":%u,\"threat_level\":%u,"
        "\"import_note\":\"%s\",\"threat_rule_ids\":[]",
        (long long)now_us(), scan_index,
        addr, addr_subtype_str(byos_ble_addr_subtype(addr_raw)), rssi,
        name_esc[0] ? "\"" : "", name_esc[0] ? name_esc : "null", name_esc[0] ? "\"" : "",
        vendor_esc, vendor_conf, class_conf,
        class_source_str(class_source), cls, match_len,
        (unsigned)flags,
        (unsigned)import_id, (unsigned)import_index,
        ident, conf, threat, note);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    if (name_rule_esc[0]) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"name_rule_name\":\"%s\"", name_rule_esc);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }
    {
        int wr = append_phone_model(line + n, LINE_BUF - n, cls,
                                    name_rule, name_kind,
                                    APPLE_DEVCAT_UNKNOWN);
        if (wr < 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }
    n = byos_append_sources(line, n, sights, n_sight);
    if (n < 0 || n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n] = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

static int append_phone_model(char *buf, int cap, uint8_t eff_class,
                              const char *name_rule_name, uint8_t name_rule_kind,
                              uint8_t apple_devcat)
{
    if (eff_class != EUI_CLASS_PHONE) return 0;
    if (name_rule_name && name_rule_name[0] &&
        name_rule_kind == EUI_NAME_RULE_PHONE_MODEL) {
        char esc[68];
        json_escape(name_rule_name, esc, sizeof(esc));
        return snprintf(buf, cap,
            ",\"phone_model\":\"%s\",\"phone_model_confidence\":\"name\"", esc);
    }
    if (apple_devcat == APPLE_DEVCAT_IPHONE)
        return snprintf(buf, cap, ",\"phone_model_confidence\":\"inferred\"");
    return snprintf(buf, cap, ",\"phone_model_confidence\":\"make_only\"");
}

static void capture_emit_ble_device_internal(const ble_device_t *d, uint16_t scan_index,
                                             const char *source, uint32_t walk_id)
{

    if (!d) return;
    s_last_scan = scan_index;

    char addr_token[24];
    append_mac(addr_token, sizeof(addr_token), d->addr);

    char name_esc[68];
    json_escape(d->name, name_esc, sizeof(name_esc));

    char vendor_esc[68];
    json_escape(d->vendor, vendor_esc, sizeof(vendor_esc));

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"ble_device\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"addr\":\"%s\",\"addr_subtype\":\"%s\",\"rssi\":%d,\"tx_power\":%d,"
        "\"prim_phy\":%u,\"distance_dm\":%u,\"name\":%s%s%s,"
        "\"vendor\":\"%s\",\"vendor_conf\":%u,\"class_conf\":%u,"
        "\"class_source\":\"%s\",\"device_class\":%u,\"mac_match_len\":%u,"
        "\"uuid16_flags\":%u,\"wifi_match\":%d,\"eui_flags\":%u",
        (long long)now_us(), scan_index,
        addr_token, addr_subtype_str(d->addr_subtype), d->rssi, d->tx_power,
        d->prim_phy, d->distance_dm,
        name_esc[0] ? "\"" : "", name_esc[0] ? name_esc : "null", name_esc[0] ? "\"" : "",
        vendor_esc, d->vendor_conf, d->class_conf,
        class_source_str(d->class_source), ble_effective_class(d), d->mac_match_len,
        d->uuid16_flags, d->wifi_match,
        (unsigned)(d->eui_flags | d->bt_company_flags));

    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    if (d->suppressed) {
        int wr = snprintf(line + n, LINE_BUF - n, ",\"suppressed\":true");
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }
    if (source && source[0]) {
        int wr = snprintf(line + n, LINE_BUF - n,
                          ",\"source\":\"%s\",\"walk_id\":%u",
                          source, (unsigned)walk_id);
        if (wr <= 0 || n + wr >= LINE_BUF - 2) { line_unlock(); return; }
        n += wr;
    }

    if (d->company_name[0]) {
        char esc[68];
        json_escape(d->company_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"company_name\":\"%s\"", esc);
    }
    if (d->mfg_rule_name) {
        char esc[68];
        json_escape(d->mfg_rule_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"mfg_rule_name\":\"%s\"", esc);
    }
    if (d->ms_subtype_name) {
        char esc[68];
        json_escape(d->ms_subtype_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"ms_subtype_name\":\"%s\"", esc);
    }
    if (d->fastpair_name || d->fastpair_model_id) {
        char esc[68];
        json_escape(d->fastpair_name ? d->fastpair_name : "", esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n,
            ",\"fastpair_name\":%s%s%s,\"fastpair_model_id\":%u",
            esc[0] ? "\"" : "", esc[0] ? esc : "null", esc[0] ? "\"" : "",
            (unsigned)d->fastpair_model_id);
    }
    if (d->uuid16_name) {
        char esc[68];
        json_escape(d->uuid16_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"uuid16_name\":\"%s\"", esc);
    }
    if (d->uuid32_name) {
        char esc[68];
        json_escape(d->uuid32_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"uuid32_name\":\"%s\"", esc);
    }
    if (d->uuid128_name) {
        char esc[68];
        json_escape(d->uuid128_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"uuid128_name\":\"%s\"", esc);
    }
    if (d->name_rule_name) {
        char esc[68];
        json_escape(d->name_rule_name, esc, sizeof(esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"name_rule_name\":\"%s\"", esc);
    }
    n += append_phone_model(line + n, LINE_BUF - n, ble_effective_class(d),
                            d->name_rule_name, d->name_rule_kind, d->apple_devcat);
    if (n >= LINE_BUF - 2) { line_unlock(); return; }

    if (d->mfg_company_id != 0xFFFF) {
        n += snprintf(line + n, LINE_BUF - n,
                      ",\"mfg_company_id\":%u", d->mfg_company_id);
    }
    if (d->num_uuids16 > 0) {
        n += snprintf(line + n, LINE_BUF - n, ",\"uuids16\":[");
        for (uint8_t i = 0; i < d->num_uuids16 && n < LINE_BUF - 10; i++) {
            n += snprintf(line + n, LINE_BUF - n, "%s%u",
                          i ? "," : "", d->uuids16[i]);
        }
        n += snprintf(line + n, LINE_BUF - n, "]");
    }
    n += snprintf(line + n, LINE_BUF - n,
                  ",\"num_uuids32\":%u,\"num_uuids128\":%u",
                  d->num_uuids32, d->num_uuids128);

    if (d->mfg_company_id == 0x004C && d->apple_evidence[0]) {
        char ev_esc[64];
        json_escape(d->apple_evidence, ev_esc, sizeof(ev_esc));
        n += snprintf(line + n, LINE_BUF - n,
            ",\"apple\":{\"subtype\":%u,\"state\":%u,\"evidence\":\"%s\"}",
            d->apple_subtype, d->apple_state, ev_esc);
    }

    if (d->apple_devcat) {
        const char *cat = apple_devcat_label((apple_devcat_t)d->apple_devcat);
        if (cat)
            n += snprintf(line + n, LINE_BUF - n,
                          ",\"apple_category\":\"%s\"", cat);
    }

    n += snprintf(line + n, LINE_BUF - n,
        ",\"scannable\":%s,"
        "\"identity_score\":%u,\"identity_conf\":%u,\"threat_level\":%u",
        d->scannable ? "true" : "false",
        d->identity_score, d->identity_conf, d->threat_level);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    {
        threat_rule_t rules[THREAT_RULES_MAX];
        int rc = collect_ble_threat_rules(d, rules);
        n = append_threat_rule_ids(line, n, rules, rc);
        if (n < 0) { line_unlock(); return; }
    }

    if (n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_ble_device(const ble_device_t *d, uint16_t scan_index)
{
    capture_emit_ble_device_internal(d, scan_index, NULL, 0);
}

void capture_emit_ble_device_walk(const ble_device_t *d, uint16_t scan_index, uint32_t walk_id)
{
    capture_emit_ble_device_internal(d, scan_index, "walk", walk_id);
}

void capture_emit_tracker_if_applicable(const ble_device_t *d, uint16_t scan_index)
{
    const char *kind = tracker_kind_for(d);
    if (!kind) return;

    char addr[24];
    append_mac(addr, sizeof(addr), d->addr);
    char name_esc[68];
    json_escape(d->name, name_esc, sizeof(name_esc));
    char vendor_esc[68];
    json_escape(d->vendor, vendor_esc, sizeof(vendor_esc));

    bool find_my_separated =
        d->is_airtag || (d->apple_subtype == APPLE_SUB_FIND_MY_SEP);

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"tracker\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"addr\":\"%s\",\"tracker_kind\":\"%s\",\"name\":\"%s\",\"vendor\":\"%s\","
        "\"rssi\":%d,\"distance_dm\":%u,\"find_my_separated\":%s}",
        (long long)now_us(), scan_index, addr, kind, name_esc, vendor_esc,
        d->rssi, d->distance_dm, find_my_separated ? "true" : "false");
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

static void emit_drone_rid(const uint8_t addr_bytes[6], int rssi,
                           uint16_t distance_dm, const drone_rid_t *r,
                           uint16_t scan_index)
{
    char addr[24];
    append_mac(addr, sizeof(addr), addr_bytes);
    char id_esc[44];
    json_escape(r->id, id_esc, sizeof(id_esc));
    char ua_esc[24];
    json_escape(drone_ua_type_label(r->ua_type), ua_esc, sizeof(ua_esc));

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"drone_rid\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"addr\":\"%s\",\"rssi\":%d,\"distance_dm\":%u,\"bearer\":\"%s\","
        "\"id\":\"%s\",\"id_type\":%u,\"ua_type\":%u,\"ua_type_label\":\"%s\","
        "\"msg_mask\":%u",
        (long long)now_us(), scan_index, addr, rssi, distance_dm,
        drone_rid_bearer_label(r->bearer),
        id_esc, r->id_type, r->ua_type, ua_esc, r->msg_mask);

    if (r->mfr_code[0]) {
        n += snprintf(line + n, LINE_BUF - n, ",\"mfr_code\":\"%s\"", r->mfr_code);
        uint16_t mf = 0; uint8_t mc = 0;
        const char *make = eui_lookup_drone_mfr(r->mfr_code, &mf, &mc);
        if (make) {
            char make_esc[44];
            json_escape(make, make_esc, sizeof(make_esc));
            n += snprintf(line + n, LINE_BUF - n, ",\"make\":\"%s\"", make_esc);
        }
    }

    if (r->msg_mask & DRONE_RID_MSG_LOCATION) {
        n += snprintf(line + n, LINE_BUF - n,
            ",\"drone\":{\"lat_e7\":%ld,\"lon_e7\":%ld,\"alt_m\":%ld,"
            "\"speed_mps\":%d,\"track_deg\":%d}",
            (long)r->lat, (long)r->lon, (long)r->alt_m,
            (int)r->speed, (int)r->track);
    }
    if (r->has_op_loc) {
        n += snprintf(line + n, LINE_BUF - n,
            ",\"operator\":{\"lat_e7\":%ld,\"lon_e7\":%ld}",
            (long)r->op_lat, (long)r->op_lon);
    }
    n += snprintf(line + n, LINE_BUF - n,
        ",\"op_separation_m\":%d", drone_op_separation_m(r));

    if (r->op_id[0]) {
        char op_esc[44];
        json_escape(r->op_id, op_esc, sizeof(op_esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"operator_id\":\"%s\"", op_esc);
    }
    if (r->self_id[0]) {
        char self_esc[52];
        json_escape(r->self_id, self_esc, sizeof(self_esc));
        n += snprintf(line + n, LINE_BUF - n, ",\"self_id\":\"%s\"", self_esc);
    }
    n += snprintf(line + n, LINE_BUF - n,
        ",\"auth_present\":%s}", r->auth_present ? "true" : "false");

    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_drone_rid_if_applicable(const ble_device_t *d, uint16_t scan_index)
{
    if (!d || !d->has_rid) return;
    emit_drone_rid(d->addr, d->rssi, d->distance_dm, &d->drone, scan_index);
}

void capture_emit_drone_rid_wifi(const sniffer_rec_t *sr, uint16_t scan_index)
{
    if (!sr || !sr->has_rid) return;
    emit_drone_rid(sr->bssid, 0, 0xFFFF, &sr->drone, scan_index);
}

static void emit_one_cluster(const pdc_cluster_t *cl, uint8_t c,
                             uint16_t scan_index, bool vehicle)
{
        char *line = line_lock();
        if (!line) return;

        int n = snprintf(line, LINE_BUF,
            "{\"type\":\"device_cluster\",\"ts_us\":%lld,\"scan_index\":%u,"
            "\"cluster_index\":%u,\"cluster_kind\":\"%s\","
            "\"confidence\":%u,\"member_total\":%u,\"members\":[",
            (long long)now_us(), scan_index,
            c, vehicle ? "vehicle" : "physical", cl->confidence,
            cl->total_members);

        for (uint8_t m = 0; m < cl->member_count; m++) {
            const pdc_member_t *mb  = &cl->members[m];
            const uint8_t      *mac = pdc_node_mac(mb->kind, mb->idx);
            char macs[24] = "";
            if (mac) append_mac(macs, sizeof(macs), mac);
            n += snprintf(line + n, LINE_BUF - n,
                "%s{\"layer\":\"%s\",\"index\":%u,\"mac\":\"%s\"}",
                m ? "," : "",
                mb->kind == PDC_NODE_WIFI ? "wifi" : "ble",
                mb->idx, macs);
        }
        n += snprintf(line + n, LINE_BUF - n, "],\"edges\":[");

        uint8_t ne = pdc_edge_count(), written = 0;
        for (uint8_t e = 0; e < ne; e++) {
            const pdc_edge_t *ed = pdc_edge_get(e);
            if (!ed) continue;
            if (vehicle) {

                if (ed->evidence != PDC_EV_VEHICLE_NAME) continue;
                if (pdc_vehicle_cluster_of(ed->kind_a, ed->idx_a) != (int8_t)c ||
                    pdc_vehicle_cluster_of(ed->kind_b, ed->idx_b) != (int8_t)c)
                    continue;
            } else {
                if (ed->evidence == PDC_EV_VEHICLE_NAME) continue;
                if (pdc_cluster_of(ed->kind_a, ed->idx_a) != (int8_t)c) continue;
            }

            const char *mclass = ed->can_union ? "physical"
                               : ed->conflict_mask ? "conflict"
                               : (ed->evclass == PDC_CLASS_PRODUCT_FAMILY)
                                     ? "product_family" : "candidate";
            n += snprintf(line + n, LINE_BUF - n,
                "%s{\"a\":{\"layer\":\"%s\",\"index\":%u},"
                "\"b\":{\"layer\":\"%s\",\"index\":%u},"
                "\"evidence\":\"%s\",\"evidence_class\":\"%s\","
                "\"match_class\":\"%s\","
                "\"merged\":%s,\"corroborated\":%s,\"confidence\":%u",
                written ? "," : "",
                ed->kind_a == PDC_NODE_WIFI ? "wifi" : "ble", ed->idx_a,
                ed->kind_b == PDC_NODE_WIFI ? "wifi" : "ble", ed->idx_b,
                pdc_evidence_label(ed->evidence),
                pdc_class_label(ed->evclass), mclass,
                ed->can_union ? "true" : "false",
                ed->corroborated ? "true" : "false", ed->confidence);
            if (ed->cand_mask) {
                n += snprintf(line + n, LINE_BUF - n, ",\"candidate_evidence\":[");
                bool first = true;
                for (uint8_t b = 0; b < 16; b++) {
                    const char *cl = pdc_cand_label((uint16_t)(1u << b));
                    if (cl && (ed->cand_mask & (1u << b))) {
                        n += snprintf(line + n, LINE_BUF - n, "%s\"%s\"",
                                      first ? "" : ",", cl);
                        first = false;
                    }
                }
                n += snprintf(line + n, LINE_BUF - n, "]");
            }
            if (ed->conflict_mask) {
                n += snprintf(line + n, LINE_BUF - n, ",\"conflicts\":[");
                bool first = true;
                for (uint8_t b = 0; b < 16; b++) {
                    const char *cl = pdc_conflict_label((uint16_t)(1u << b));
                    if (cl && (ed->conflict_mask & (1u << b))) {
                        n += snprintf(line + n, LINE_BUF - n, "%s\"%s\"",
                                      first ? "" : ",", cl);
                        first = false;
                    }
                }
                n += snprintf(line + n, LINE_BUF - n, "]");
            }
            n += snprintf(line + n, LINE_BUF - n, "}");
            written++;
            if (n >= LINE_BUF - 320) break;
        }
        n += snprintf(line + n, LINE_BUF - n, "]}");

        if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
        line_unlock();
}

void capture_emit_device_clusters(uint16_t scan_index)
{
    uint8_t nc = pdc_cluster_count();
    for (uint8_t c = 0; c < nc; c++) {
        const pdc_cluster_t *cl = pdc_cluster_get(c);
        if (cl) emit_one_cluster(cl, c, scan_index, false);
    }

    uint8_t nv = pdc_vehicle_cluster_count();
    for (uint8_t c = 0; c < nv; c++) {
        const pdc_cluster_t *cl = pdc_vehicle_cluster_get(c);
        if (cl) emit_one_cluster(cl, c, scan_index, true);
    }
}

void capture_emit_ble_addr_stats(const ble_results_t *ble, uint16_t scan_index)
{
    if (!ble) return;
    s_last_scan = scan_index;

    uint16_t counts[4] = {0}, total = 0;
    uint16_t n = ble->count;
    if (n > BLE_MAX_DEVICES) n = BLE_MAX_DEVICES;
    for (uint16_t i = 0; i < n; i++) {
        const ble_device_t *d = &ble->devices[i];
        if (d->suppressed) continue;
        ble_addr_subtype_t s = d->addr_subtype;
        if (s <= BLE_ADDR_SUB_NRPA) counts[s]++;
        total++;
    }

    char *line = line_lock();
    if (!line) return;
    int n2 = snprintf(line, LINE_BUF,
        "{\"type\":\"ble_addr_stats\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"counts\":{",
        (long long)now_us(), scan_index);
    for (uint8_t a = BLE_ADDR_SUB_PUBLIC; a <= BLE_ADDR_SUB_NRPA; a++)
        n2 += snprintf(line + n2, LINE_BUF - n2, "%s\"%u\":%u",
                       a ? "," : "", a, counts[a]);
    n2 += snprintf(line + n2, LINE_BUF - n2, "},\"total\":%u}", total);
    if (n2 > 0 && n2 < LINE_BUF) capture_ring_write(line, (size_t)n2);
    line_unlock();
}

void capture_emit_crowd_density(const crowd_estimate_t *cd, uint16_t scan_index)
{
    if (!cd) return;
    s_last_scan = scan_index;

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"crowd_density\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"ble_person_devices\":%u,\"wifi_stations\":%u,\"probe_reqs\":%u,"
        "\"device_evidence\":%u,\"people_low\":%u,\"people_high\":%u,"
        "\"bucket\":\"%s\",\"confidence\":\"low\","
        "\"note\":\"Rough estimate from person-carried RF devices; MAC "
        "randomization, multi-device users, bags, neighbours/cars and walls "
        "distort it. Not an exact count.\"}",
        (long long)now_us(), scan_index,
        cd->ble_person_devices, cd->wifi_stations, cd->probe_reqs,
        cd->device_evidence, cd->people_low, cd->people_high,
        analyzer_crowd_bucket_label(cd->bucket));
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_law_enforcement_presence(const ps_result_t *ps, uint16_t scan_index)
{
    if (!ps) return;
    s_last_scan = scan_index;

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"law_enforcement_presence\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"presence\":\"%s\",\"confidence\":%u,\"matches\":%u,\"strong_matches\":%u,"
        "\"estimated_officers_low\":%u,\"estimated_officers_high\":%u,"
        "\"device_counts\":{\"body_camera\":%u,\"taser\":%u,\"in_car_camera\":%u,"
        "\"radio\":%u,\"vehicle_gateway\":%u,\"rugged_device\":%u,"
        "\"other_public_safety\":%u,\"unknown\":%u},"
        "\"pairing_model\":\"%s\",\"evidence\":[",
        (long long)now_us(), scan_index,
        public_safety_presence_label(ps->presence), ps->confidence,
        ps->matches, ps->strong_matches,
        ps->estimated_officers_low, ps->estimated_officers_high,
        ps->device_counts[PS_DEV_BODY_CAMERA], ps->device_counts[PS_DEV_TASER],
        ps->device_counts[PS_DEV_IN_CAR_CAMERA], ps->device_counts[PS_DEV_RADIO],
        ps->device_counts[PS_DEV_VEHICLE_GATEWAY], ps->device_counts[PS_DEV_RUGGED_DEVICE],
        ps->device_counts[PS_DEV_OTHER], ps->device_counts[PS_DEV_UNKNOWN],
        PS_PAIRING_MODEL);

    for (uint16_t i = 0; i < ps->evidence_count && n > 0 && n < LINE_BUF; i++) {
        const ps_evidence_t *e = &ps->evidence[i];
        n += snprintf(line + n, LINE_BUF - n,
            "%s{\"layer\":\"%s\",\"target\":\"%s\",\"source\":\"%s\","
            "\"label\":\"%s\",\"device_type\":\"%s\",\"confidence\":%u}",
            i ? "," : "", e->layer ? "ble" : "wifi", e->target, e->source,
            e->label, public_safety_device_type_label((ps_device_type_t)e->device_type),
            e->confidence);
    }

    if (n > 0 && n < LINE_BUF)
        n += snprintf(line + n, LINE_BUF - n,
            "],\"limitations\":[\"public_safety_vendors_have_non_law_enforcement_customers\","
            "\"passive_identifier_not_operator_identity\"]}");
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_medical_responder_presence(const mr_result_t *mr, uint16_t scan_index)
{
    if (!mr) return;
    s_last_scan = scan_index;

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"medical_responder_presence\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"presence\":\"%s\",\"confidence\":%u,\"could_be_first_responder\":%s,"
        "\"matches\":%u,\"strong_matches\":%u,"
        "\"device_counts\":{\"ambulance_gateway\":%u,\"ems_tablet\":%u,"
        "\"medical_monitor\":%u,\"radio_accessory\":%u,\"ems_camera\":%u,"
        "\"air_ambulance\":%u,\"hospital_ems\":%u,\"other_medical_responder\":%u,"
        "\"unknown\":%u},\"evidence\":[",
        (long long)now_us(), scan_index,
        medical_responder_presence_label(mr->presence), mr->confidence,
        mr->could_be_first_responder ? "true" : "false",
        mr->matches, mr->strong_matches,
        mr->device_counts[MR_DEV_AMBULANCE_GATEWAY], mr->device_counts[MR_DEV_EMS_TABLET],
        mr->device_counts[MR_DEV_MEDICAL_MONITOR], mr->device_counts[MR_DEV_RADIO_ACCESSORY],
        mr->device_counts[MR_DEV_EMS_CAMERA], mr->device_counts[MR_DEV_AIR_AMBULANCE],
        mr->device_counts[MR_DEV_HOSPITAL_EMS], mr->device_counts[MR_DEV_OTHER],
        mr->device_counts[MR_DEV_UNKNOWN]);

    for (uint16_t i = 0; i < mr->evidence_count && n > 0 && n < LINE_BUF; i++) {
        const mr_evidence_t *e = &mr->evidence[i];
        n += snprintf(line + n, LINE_BUF - n,
            "%s{\"layer\":\"%s\",\"target\":\"%s\",\"source\":\"%s\","
            "\"label\":\"%s\",\"device_type\":\"%s\",\"confidence\":%u}",
            i ? "," : "", e->layer ? "ble" : "wifi", e->target, e->source,
            e->label, medical_responder_device_type_label((mr_device_type_t)e->device_type),
            e->confidence);
    }

    if (n > 0 && n < LINE_BUF)
        n += snprintf(line + n, LINE_BUF - n,
            "],\"limitations\":[\"ems_names_can_overlap_with_non_ems_devices\","
            "\"passive_identifier_not_personnel_identity\","
            "\"weak_confidence_environment_hint\"]}");
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_environment_indicators(const environment_indicators_t *ei,
                                         uint16_t scan_index)
{
    if (!ei) return;
    s_last_scan = scan_index;

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"environment_indicators\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"camera_count\":%u,\"camera_conf\":%u,"
        "\"public_safety_count_low\":%u,\"public_safety_count_high\":%u,"
        "\"public_safety_conf\":%u,"
        "\"phone_like_count\":%u,\"phone_like_conf\":%u,"
        "\"medical_count\":%u,\"medical_conf\":%u,"
        "\"assumption_notice\":\"Counts are inferred from passive RF identifiers "
        "and confidence-scored evidence, not confirmed counts.\"}",
        (long long)now_us(), scan_index,
        ei->camera_count, ei->camera_conf,
        ei->public_safety_low, ei->public_safety_high, ei->public_safety_conf,
        ei->phone_like_count, ei->phone_like_conf,
        ei->medical_count, ei->medical_conf);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_channel_activity(const ap_score_t *scores, uint16_t count,
                                   uint16_t scan_index)
{
    if (!scores) return;
    s_last_scan = scan_index;

    struct { uint8_t ch; uint8_t band5; uint16_t aps; } d[48];
    uint8_t nd = 0;
    for (uint16_t i = 0; i < count; i++) {
        uint8_t ch = scores[i].channel;
        if (ch == 0 || scores[i].suppressed) continue;
        bool b5 = scores[i].band_5g;
        uint8_t k = 0;
        for (; k < nd; k++) if (d[k].ch == ch && d[k].band5 == b5) break;
        if (k == nd) {
            if (nd >= (uint8_t)(sizeof(d) / sizeof(d[0]))) continue;
            d[nd].ch = ch; d[nd].band5 = b5; d[nd].aps = 0; nd++;
        }
        d[k].aps++;
    }
    for (uint8_t i = 1; i < nd; i++)
        for (uint8_t j = i; j > 0 && d[j].ch < d[j - 1].ch; j--) {
            typeof(d[0]) t = d[j]; d[j] = d[j - 1]; d[j - 1] = t;
        }

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"channel_activity\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"count\":%u,\"channels\":[",
        (long long)now_us(), scan_index, nd);
    for (uint8_t i = 0; i < nd && n > 0 && n < LINE_BUF; i++)
        n += snprintf(line + n, LINE_BUF - n,
            "%s{\"ch\":%u,\"band\":\"%s\",\"aps\":%u}",
            i ? "," : "", d[i].ch, d[i].band5 ? "5" : "2.4", d[i].aps);
    if (n > 0 && n < LINE_BUF) n += snprintf(line + n, LINE_BUF - n, "]}");
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_pcap_capture(const pcap_meta_t *m, uint16_t scan_index)
{
    if (!m || !m->ran) return;
    s_last_scan = scan_index;

    const char *st = m->status == PCAP_READY   ? "complete"
                   : m->status == PCAP_PARTIAL ? "partial"
                   : m->status == PCAP_RUNNING ? "running"
                   : m->status == PCAP_FAILED  ? "failed" : "idle";

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"pcap_capture\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"status\":\"%s\",\"channels\":[",
        (long long)now_us(), scan_index, st);
    uint8_t nc = m->channel_count;
    if (nc > PCAP_MAX_CHANNELS) nc = PCAP_MAX_CHANNELS;
    for (uint8_t i = 0; i < nc && n > 0 && n < LINE_BUF; i++)
        n += snprintf(line + n, LINE_BUF - n, "%s%u", i ? "," : "", m->channels[i]);
    if (n > 0 && n < LINE_BUF)
        n += snprintf(line + n, LINE_BUF - n,
            "],\"seconds_per_channel\":%u,\"duration_s\":%u,\"packets\":%u,"
            "\"dropped\":%u,\"truncated\":%u,\"bytes\":%u,"
            "\"download\":\"/api/pcap/latest\"}",
            (unsigned)m->seconds_per_channel, (unsigned)m->duration_s,
            (unsigned)m->packets, (unsigned)m->dropped, (unsigned)m->truncated,
            (unsigned)m->bytes);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

static void emit_alert(const char *rule, const char *sev,
                       const char *target_kind, const char *target_ref,
                       const char *msg, uint16_t scan_index)
{
    char msg_esc[256];
    json_escape(msg ? msg : "", msg_esc, sizeof(msg_esc));
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"alert\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"rule_id\":\"%s\",\"severity\":\"%s\","
        "\"target_kind\":\"%s\",\"target_ref\":\"%s\",\"message\":\"%s\"}",
        (long long)now_us(), scan_index, rule, sev, target_kind, target_ref, msg_esc);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

static int collect_ap_threat_rules(const ap_score_t *ap, threat_rule_t *out)
{
    int n = 0;

    if (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS)
        out[n++] = (threat_rule_t){"known_malicious", "high", "wifi_ap",
            "Vendor on the known-malicious overlay"};
    if (ap->open_clone)
        out[n++] = (threat_rule_t){"open_clone", "high", "wifi_ap",
            "Open AP cloning a protected SSID"};
    if (ap->karma_suspect)
        out[n++] = (threat_rule_t){"karma_signature", "high", "wifi_ap",
            "AP responds to probe-requests for arbitrary SSIDs"};
    if (ap->deauth_flood)
        out[n++] = (threat_rule_t){"deauth_burst", "high", "wifi_ap",
            "Deauth frame burst observed"};
    if (ap->pwnagotchi)
        out[n++] = (threat_rule_t){"pwnagotchi", "high", "wifi_ap",
            "Pwnagotchi beacon (de:ad:be:ef:de:ad handshake harvester)"};
    if (ap->eui_flags & EUI_FLAG_INVESTIGATION)
        out[n++] = (threat_rule_t){"investigation", "high", "wifi_ap",
            "Identifier flagged for investigation"};

    if (ap->twin_detected)
        out[n++] = (threat_rule_t){"twin_detected", "medium", "wifi_ap",
            "Potential Evil-Twin pattern: same SSID + mismatched peer. Be cautious"};
    if (ap->eui_flags & (EUI_FLAG_FCC_COVERED | EUI_FLAG_SURVEILLANCE))
        out[n++] = (threat_rule_t){"surveillance_vendor", "medium", "wifi_ap",
            "Vendor on FCC-covered / surveillance list"};

    if (ap->vendor_mismatch)
        out[n++] = (threat_rule_t){"vendor_mismatch", "low", "wifi_ap",
            "Second vendor sharing this SSID — verify ownership"};

    if (ap->device_class == EUI_CLASS_SURVEILLANCE_OUI)
        out[n++] = (threat_rule_t){"surveillance_oui_hint", "low", "wifi_ap",
            "OUI appears on a surveillance-hardware list (unconfirmed)"};
    if (ap->has_wps)
        out[n++] = (threat_rule_t){"wps_active", "low", "wifi_ap",
            "WPS enabled and reachable"};
    if (ap->has_rsn && !ap->rsn_pmf_required)
        out[n++] = (threat_rule_t){"mfp_off", "low", "wifi_ap",
            "WPA2/3 AP not requiring management-frame protection"};
    return n;
}

static int collect_ble_threat_rules(const ble_device_t *d, threat_rule_t *out)
{
    int n = 0;
    uint16_t combined = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags
                      | d->uuid128_flags | d->name_rule_flags | d->apple_subtype_flags
                      | d->ms_subtype_flags | d->uuid32_flags | d->fastpair_flags
                      | d->uuid16_flags;
    bool attack_uuid = false;
    for (uint8_t i = 0; i < d->num_uuids16; i++) {
        uint16_t f = 0; uint8_t c = EUI_CLASS_UNKNOWN;
        eui_lookup_uuid16(d->uuids16[i], &f, &c);
        if (c == EUI_CLASS_ATTACK_SIGNAL) attack_uuid = true;
    }
    bool investigation = (combined & EUI_FLAG_INVESTIGATION)
                       || d->uuid128_class == EUI_CLASS_INVESTIGATION
                       || d->name_rule_class == EUI_CLASS_INVESTIGATION;
    bool surveillance = (combined & (EUI_FLAG_SURVEILLANCE | EUI_FLAG_FCC_COVERED))
                       || d->uuid128_class == EUI_CLASS_SURVEILLANCE_CAM;
    bool find_my_separated = d->is_airtag || d->apple_subtype == APPLE_SUB_FIND_MY_SEP;

    if (combined & EUI_FLAG_KNOWN_MALICIOUS)
        out[n++] = (threat_rule_t){"known_malicious", "high", "ble_device",
            "Identifier on the known-malicious overlay"};
    if (investigation)
        out[n++] = (threat_rule_t){"investigation", "high", "ble_device",
            "Identifier flagged for investigation"};
    if (attack_uuid)
        out[n++] = (threat_rule_t){"attack_signal", "high", "ble_device",
            "Advertises a service UUID associated with attack tooling"};

    if (surveillance)
        out[n++] = (threat_rule_t){"surveillance_vendor", "medium", "ble_device",
            "Identifier on FCC-covered / surveillance list"};

    if (d->device_class == EUI_CLASS_SURVEILLANCE_OUI)
        out[n++] = (threat_rule_t){"surveillance_oui_hint", "low", "ble_device",
            "OUI appears on a surveillance-hardware list (unconfirmed)"};

    if (find_my_separated)
        out[n++] = (threat_rule_t){"find_my_separated", "low", "tracker",
            "Tracker broadcasting separated-from-owner subtype"};
    if (d->mfg_company_id == 0x004C && d->apple_subtype == APPLE_SUB_AIRDROP)
        out[n++] = (threat_rule_t){"airdrop_discoverable", "low", "ble_device",
            "Apple AirDrop subtype broadcast"};
    return n;
}

static int append_threat_rule_ids(char *line, int n,
                                   const threat_rule_t *r, int count)
{
    int w = snprintf(line + n, LINE_BUF - n, ",\"threat_rule_ids\":[");
    if (w <= 0 || n + w >= LINE_BUF - 2) return -1;
    n += w;
    for (int i = 0; i < count; i++) {
        w = snprintf(line + n, LINE_BUF - n, "%s\"%s\"", i ? "," : "", r[i].rule_id);
        if (w <= 0 || n + w >= LINE_BUF - 2) return -1;
        n += w;
    }
    w = snprintf(line + n, LINE_BUF - n, "]");
    if (w <= 0 || n + w >= LINE_BUF - 2) return -1;
    return n + w;
}

void capture_emit_alerts_for_ap(const ap_score_t *ap, uint16_t scan_index)
{
    if (!ap || ap->suppressed) return;
    char bssid[24];
    append_mac(bssid, sizeof(bssid), ap->bssid);
    threat_rule_t rules[THREAT_RULES_MAX];
    int count = collect_ap_threat_rules(ap, rules);
    for (int i = 0; i < count; i++)
        emit_alert(rules[i].rule_id, rules[i].severity, rules[i].target_kind,
                   bssid, rules[i].message, scan_index);
}

void capture_emit_alerts_for_ble(const ble_device_t *d, uint16_t scan_index)
{
    if (!d || d->suppressed) return;
    char addr[24];
    append_mac(addr, sizeof(addr), d->addr);
    threat_rule_t rules[THREAT_RULES_MAX];
    int count = collect_ble_threat_rules(d, rules);
    for (int i = 0; i < count; i++)
        emit_alert(rules[i].rule_id, rules[i].severity, rules[i].target_kind,
                   addr, rules[i].message, scan_index);
}

void capture_emit_probe_req_log(const probe_req_log_aggregate_t *agg,
                                 uint16_t scan_index, bool include_detail)
{
    if (!agg) return;
    s_last_scan = scan_index;
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"probe_req_log\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"totals\":{\"total_probe_reqs\":%u,\"directed_probe_reqs\":%u,"
        "\"local_visible_probes\":%u,\"remote_saved_probes\":%u,"
        "\"detail_entries\":%u,\"detail_dropped\":%u},"
        "\"by_category\":{\"pii\":%u,\"corporate\":%u,\"hotel\":%u,\"airport\":%u,"
        "\"isp\":%u,\"generic\":%u,\"hidden\":%u,\"other\":%u}",
        (long long)now_us(), scan_index,
        agg->total_probe_reqs, agg->directed_probe_reqs,
        agg->local_visible_probes, agg->remote_saved_probes,
        agg->detail_entries, agg->detail_dropped,
        agg->counts[SSID_CAT_PII], agg->counts[SSID_CAT_CORPORATE],
        agg->counts[SSID_CAT_HOTEL], agg->counts[SSID_CAT_AIRPORT],
        agg->counts[SSID_CAT_ISP], agg->counts[SSID_CAT_GENERIC],
        agg->counts[SSID_CAT_HIDDEN], agg->counts[SSID_CAT_OTHER]);

    if (include_detail) {
        n += snprintf(line + n, LINE_BUF - n, ",\"detail\":[");
        uint16_t cnt = probe_req_log_entry_count();
        bool first = true;
        for (uint16_t i = 0; i < cnt; i++) {
            const probe_req_log_entry_t *e = probe_req_log_entry_at(i);
            if (!e) continue;
            char addr_token[24];
            append_mac(addr_token, sizeof(addr_token), e->src_mac);

            char ssid_buf[68];
            ssid_buf[0] = '"';
            json_escape(e->ssid, ssid_buf + 1, sizeof(ssid_buf) - 2);
            size_t l = strlen(ssid_buf);
            if (l + 1 < sizeof(ssid_buf)) { ssid_buf[l] = '"'; ssid_buf[l+1] = '\0'; }
            int wr = snprintf(line + n, LINE_BUF - n,
                "%s{\"ssid\":%s,\"src_mac\":\"%s\",\"category\":\"%s\","
                "\"first_seen_scan\":%u,\"last_seen_scan\":%u,\"hit_count\":%u,"
                "\"local_visible\":%s}",
                first ? "" : ",", ssid_buf, addr_token,
                ssid_cat_str(e->category),
                e->first_seen_scan, e->last_seen_scan, e->hit_count,
                e->local_visible ? "true" : "false");
            if (wr <= 0 || n + wr >= LINE_BUF - 3) break;
            n += wr;
            first = false;
        }
        n += snprintf(line + n, LINE_BUF - n, "]");
    }

    if (n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

static void detail_mac(const uint8_t mac[6], char *out, size_t n)
{
    append_mac(out, n, mac);
}

void capture_emit_seq_fingerprint_log(const seq_analyzer_aggregate_t *agg,
                                      uint16_t scan_index, bool include_detail)
{
    if (!agg) return;
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"seq_fingerprint_log\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"totals\":{\"total_probe_reqs\":%u,\"distinct_macs\":%u,"
        "\"linked_pairs\":%u,\"apparent_devices\":%u,"
        "\"chipset_seq12\":%u,\"chipset_seq11\":%u,\"entries_dropped\":%u}",
        (long long)now_us(), scan_index,
        agg->total_probe_reqs, agg->distinct_macs, agg->linked_pairs,
        agg->apparent_devices, agg->chipset_seq12, agg->chipset_seq11,
        agg->entries_dropped);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    if (include_detail) {
        n += snprintf(line + n, LINE_BUF - n, ",\"detail\":[");
        uint16_t cnt = seq_analyzer_entry_count();
        bool first = true;
        for (uint16_t i = 0; i < cnt; i++) {
            const seq_analyzer_entry_t *e = seq_analyzer_entry_at(i);
            if (!e) continue;
            char mac[24];
            detail_mac(e->mac, mac, sizeof(mac));
            int wr = snprintf(line + n, LINE_BUF - n,
                "%s{\"src_mac\":\"%s\",\"first_seq\":%u,\"last_seq\":%u,"
                "\"max_seq\":%u,\"hit_count\":%u,\"first_seen_scan\":%u,"
                "\"last_seen_scan\":%u,\"linked\":%s}",
                first ? "" : ",", mac, e->first_seq, e->last_seq, e->max_seq,
                e->hit_count, e->first_seen_scan, e->last_seen_scan,
                e->linked_into ? "true" : "false");
            if (wr <= 0 || n + wr >= LINE_BUF - 3) break;
            n += wr;
            first = false;
        }
        n += snprintf(line + n, LINE_BUF - n, "]");
    }

    if (n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_ie_signature_log(const ie_signature_aggregate_t *agg,
                                   uint16_t scan_index, bool include_detail)
{
    if (!agg) return;
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"ie_signature_log\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"totals\":{\"total_probe_reqs\":%u,\"distinct_macs\":%u,"
        "\"distinct_hashes\":%u,\"top_hash\":%u,\"top_hash_macs\":%u,"
        "\"recognized_macs\":%u,\"mismatched_macs\":%u,\"entries_dropped\":%u}",
        (long long)now_us(), scan_index,
        agg->total_probe_reqs, agg->distinct_macs, agg->distinct_hashes,
        (unsigned)agg->top_hash, agg->top_hash_macs, agg->recognized_macs,
        agg->mismatched_macs, agg->entries_dropped);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    if (include_detail) {
        n += snprintf(line + n, LINE_BUF - n, ",\"detail\":[");
        uint16_t cnt = ie_signature_entry_count();
        bool first = true;
        for (uint16_t i = 0; i < cnt; i++) {
            const ie_signature_entry_t *e = ie_signature_entry_at(i);
            if (!e) continue;
            char mac[24], iev[68], macv[68];
            detail_mac(e->mac, mac, sizeof(mac));
            json_escape(e->ie_vendor  ? e->ie_vendor  : "", iev,  sizeof(iev));
            json_escape(e->mac_vendor ? e->mac_vendor : "", macv, sizeof(macv));
            int wr = snprintf(line + n, LINE_BUF - n,
                "%s{\"src_mac\":\"%s\",\"ie_hash\":%u,\"hit_count\":%u,"
                "\"first_seen_scan\":%u,\"last_seen_scan\":%u,"
                "\"ie_vendor\":%s%s%s,\"mac_vendor\":%s%s%s,"
                "\"ie_class\":%u,\"mac_class\":%u,\"mismatch\":%s}",
                first ? "" : ",", mac, (unsigned)e->ie_hash, e->hit_count,
                e->first_seen_scan, e->last_seen_scan,
                iev[0]  ? "\"" : "", iev[0]  ? iev  : "null", iev[0]  ? "\"" : "",
                macv[0] ? "\"" : "", macv[0] ? macv : "null", macv[0] ? "\"" : "",
                e->ie_class, e->mac_class, e->mismatch ? "true" : "false");
            if (wr <= 0 || n + wr >= LINE_BUF - 3) break;
            n += wr;
            first = false;
        }
        n += snprintf(line + n, LINE_BUF - n, "]");
    }

    if (n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_anqp_log(const anqp_analyzer_aggregate_t *agg,
                           uint16_t scan_index, bool include_detail)
{
    if (!agg) return;
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"anqp_log\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"totals\":{\"total_queries\":%u,\"distinct_macs\":%u,"
        "\"universal_macs\":%u,\"laa_macs\":%u,\"entries_dropped\":%u}",
        (long long)now_us(), scan_index,
        agg->total_queries, agg->distinct_macs, agg->universal_macs,
        agg->laa_macs, agg->entries_dropped);
    if (n <= 0 || n >= LINE_BUF - 2) { line_unlock(); return; }

    if (include_detail) {
        n += snprintf(line + n, LINE_BUF - n, ",\"detail\":[");
        uint16_t cnt = anqp_analyzer_entry_count();
        bool first = true;
        for (uint16_t i = 0; i < cnt; i++) {
            const anqp_analyzer_entry_t *e = anqp_analyzer_entry_at(i);
            if (!e) continue;
            char mac[24];
            detail_mac(e->mac, mac, sizeof(mac));
            int wr = snprintf(line + n, LINE_BUF - n,
                "%s{\"src_mac\":\"%s\",\"universal\":%s,\"hit_count\":%u,"
                "\"first_seen_scan\":%u,\"last_seen_scan\":%u}",
                first ? "" : ",", mac, e->universal ? "true" : "false",
                e->hit_count, e->first_seen_scan, e->last_seen_scan);
            if (wr <= 0 || n + wr >= LINE_BUF - 3) break;
            n += wr;
            first = false;
        }
        n += snprintf(line + n, LINE_BUF - n, "]");
    }

    if (n >= LINE_BUF - 2) { line_unlock(); return; }
    line[n++] = '}';
    line[n]   = '\0';
    capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_footer(capture_end_reason_t reason,
                         uint32_t wifi_aps_seen, uint32_t ble_devices_seen,
                         uint32_t trackers_seen, uint32_t probe_reqs_seen,
                         uint32_t alerts_fired, uint32_t scans_completed)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"footer\",\"ts_us\":%lld,"
        "\"session\":{\"session_id\":\"%s\",\"end_us\":%lld,\"end_reason\":\"%s\"},"
        "\"counters\":{\"records_written\":%u,\"events_dropped\":%u,"
        "\"wifi_aps_seen\":%u,\"ble_devices_seen\":%u,\"trackers_seen\":%u,"
        "\"probe_reqs_seen\":%u,\"alerts_fired\":%u,\"scans_completed\":%u}}",
        (long long)now_us(),
        s_session_id, (long long)now_us(), end_reason_str(reason),
        (unsigned)st.records_total, (unsigned)st.records_dropped,
        (unsigned)wifi_aps_seen, (unsigned)ble_devices_seen,
        (unsigned)trackers_seen, (unsigned)probe_reqs_seen,
        (unsigned)alerts_fired, (unsigned)scans_completed);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_station_log(uint16_t scan_index)
{
    uint16_t total = sta_tracker_entry_count();

    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"station_log\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"total\":%u,\"cameras\":%u,\"stations\":[",
        (long long)now_us(), scan_index, (unsigned)total,
        (unsigned)sta_tracker_camera_count());
    if (n <= 0 || n >= LINE_BUF - 4) { line_unlock(); return; }

    uint16_t emitted = 0;
    for (uint16_t i = 0; i < total; i++) {
        const sta_entry_t *e = sta_tracker_at(i);
        if (!e) continue;
        char mac[24], bssid[24], vend[68];
        append_mac(mac,  sizeof(mac),  e->mac);
        append_mac(bssid, sizeof(bssid), e->bssid);
        json_escape(e->vendor ? e->vendor : "", vend, sizeof(vend));
        int wr = snprintf(line + n, LINE_BUF - n,
            "%s{\"mac\":\"%s\",\"vendor\":\"%s\",\"class\":%u,\"frames\":%u,"
            "\"up\":%u,\"dn\":%u,\"randomized\":%s,\"camera\":%s,"
            "\"rssi_best\":%d,\"channel\":%u,\"bssid\":\"%s\"}",
            emitted ? "," : "", mac, vend, (unsigned)e->device_class,
            (unsigned)e->frames, (unsigned)e->frames_uplink,
            (unsigned)e->frames_downlink, e->randomized ? "true" : "false",
            e->is_camera ? "true" : "false", (int)e->rssi_best,
            (unsigned)e->channel, bssid);
        if (wr <= 0 || n + wr >= LINE_BUF - 4) break;
        n += wr;
        emitted++;
    }
    n += snprintf(line + n, LINE_BUF - n, "]}");
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_csi(uint16_t scan_index)
{
    const wifi_csi_result_t *r = wifi_csi_probe_last();
    if (!r) return;
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"csi\",\"ts_us\":%lld,\"scan_index\":%u,"
        "\"supported\":%s,\"ran\":%s,\"channel\":%u,\"window_ms\":%u,"
        "\"cb_count\":%u,\"len_min\":%u,\"len_max\":%u,\"len_last\":%u,"
        "\"fwi_count\":%u,\"rssi_last\":%d}",
        (long long)now_us(), scan_index,
        r->supported ? "true" : "false", r->ran ? "true" : "false",
        (unsigned)r->channel, (unsigned)r->window_ms, (unsigned)r->cb_count,
        (unsigned)r->len_min, (unsigned)r->len_max, (unsigned)r->len_last,
        (unsigned)r->fwi_count, (int)r->rssi_last);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}

void capture_emit_pup_walk(const pup_walk_summary_t *w)
{
    if (!w) return;
    char mood[24];
    json_escape(w->mood, mood, sizeof(mood));
    char *line = line_lock();
    if (!line) return;
    int n = snprintf(line, LINE_BUF,
        "{\"type\":\"pup_walk\",\"ts_us\":%lld,\"walk_id\":%u,"
        "\"duration_sec\":%u,\"wifi_sweeps\":%u,\"ble_windows\":%u,"
        "\"wifi_unique_bssid\":%u,\"wifi_unique_ssid\":%u,"
        "\"ble_unique_devices\":%u,\"threat_events\":%u,\"safe_networks\":%u,"
        "\"interesting_sniffs\":%u,\"xp_awarded\":%u,\"mood\":\"%s\"}",
        (long long)now_us(), (unsigned)w->walk_id, (unsigned)w->duration_sec,
        (unsigned)w->wifi_sweeps, (unsigned)w->ble_windows,
        (unsigned)w->wifi_unique_bssid, (unsigned)w->wifi_unique_ssid,
        (unsigned)w->ble_unique_devices, (unsigned)w->threat_events,
        (unsigned)w->safe_networks, (unsigned)w->interesting_sniffs,
        (unsigned)w->xp_awarded, mood);
    if (n > 0 && n < LINE_BUF) capture_ring_write(line, (size_t)n);
    line_unlock();
}
