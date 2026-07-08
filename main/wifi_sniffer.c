#include "wifi_sniffer.h"
#include "frame_parser.h"
#include "probe_req_log.h"
#include "flock_detect.h"
#include "sta_tracker.h"
#include "seq_analyzer.h"
#include "ie_signature.h"
#include "anqp_analyzer.h"
#include "probe_frame_ring.h"
#include "eui_db.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "sc_sniff";

static EXT_RAM_BSS_ATTR sniffer_rec_t s_db[SNIFF_MAX_APS];
static uint16_t      s_count;
static volatile bool s_active;

#define SNIFF_HOP_SETTLE_MS 5u
#define SNIFF_HOP_MS        80u 
static volatile uint8_t  s_req_channel;
static volatile uint32_t s_hop_ms;
static volatile uint32_t s_drop_settling;
static volatile uint32_t s_drop_offchan;

static bool                s_capture_ctrl;
static sniffer_ctrl_stats_t s_ctrl;

static void bump_sat_u8(uint8_t *v)
{
    if (*v < 255) (*v)++;
}

static bool is_qos_subtype(uint8_t fc0)
{
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    return subtype >= 8;
}

static bool parse_data_frame_bssid(const uint8_t *p, uint16_t len, uint8_t out_bssid[6], uint16_t *llc_off_out)
{
    if (!p || len < 24) return false;

    uint8_t fc0 = p[0];
    uint8_t fc1 = p[1];
    uint8_t type = (fc0 >> 2) & 0x03;
    if (type != 2) return false;

    bool to_ds = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;

    uint16_t hdr_len = 24;
    if (to_ds && from_ds) return false;
    if (is_qos_subtype(fc0)) hdr_len += 2;
    if (len < hdr_len + 8) return false;

    if (!to_ds && !from_ds) {
        memcpy(out_bssid, &p[16], 6);
    } else if (to_ds && !from_ds) {
        memcpy(out_bssid, &p[4], 6);
    } else {
        memcpy(out_bssid, &p[10], 6);
    }

    *llc_off_out = hdr_len;
    return true;
}

static void copy_bounded(char *dst, size_t dst_size, const uint8_t *src, size_t src_len)
{
    if (src_len >= dst_size) src_len = dst_size - 1;
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

static void parse_cdp_payload(sniffer_rec_t *rec, const uint8_t *p, uint16_t len)
{
    if (len < 4) return;
    uint16_t pos = 4;
    while (pos + 4 <= len) {
        uint16_t type = ((uint16_t)p[pos] << 8) | p[pos + 1];
        uint16_t tl   = ((uint16_t)p[pos + 2] << 8) | p[pos + 3];
        if (tl < 4 || pos + tl > len) break;
        const uint8_t *v = p + pos + 4;
        uint16_t vl = tl - 4;
        if (type == 0x0001 && !rec->cdp_device_id[0]) {
            copy_bounded(rec->cdp_device_id, sizeof(rec->cdp_device_id), v, vl);
        }
        pos += tl;
    }

    static const uint8_t cisco_oui[3] = { 0x00, 0x00, 0x0C };
    rec->cdp_org_name = eui_lookup_cdp_org(cisco_oui, &rec->cdp_flags, &rec->cdp_class);
}

static void parse_lldp_payload(sniffer_rec_t *rec, const uint8_t *p, uint16_t len)
{
    uint16_t pos = 0;
    while (pos + 2 <= len) {
        uint16_t hdr = ((uint16_t)p[pos] << 8) | p[pos + 1];
        uint8_t  type = (hdr >> 9) & 0x7F;
        uint16_t tl   = hdr & 0x01FF;
        pos += 2;
        if (pos + tl > len) break;
        const uint8_t *v = p + pos;
        if (type == 0) break;
        if (type == 5 && !rec->lldp_system_name[0]) {
            copy_bounded(rec->lldp_system_name, sizeof(rec->lldp_system_name), v, tl);
        } else if (type == 127 && tl >= 4) {
            uint8_t oui[3] = { v[0], v[1], v[2] };
            if (!rec->lldp_org_name) {
                rec->lldp_org_name = eui_lookup_lldp_org(oui,
                                                          &rec->lldp_flags,
                                                          &rec->lldp_class);
            }
        }
        pos += tl;
    }
}

static void parse_dhcp_payload(sniffer_rec_t *rec, const uint8_t *p, uint16_t len)
{

    if (len < 244) return;
    if (p[236] != 99 || p[237] != 130 || p[238] != 83 || p[239] != 99) return;
    uint16_t pos = 240;
    while (pos < len) {
        uint8_t opt = p[pos++];
        if (opt == 0) continue;
        if (opt == 255) break;
        if (pos >= len) break;
        uint8_t ol = p[pos++];
        if (pos + ol > len) break;
        const uint8_t *v = p + pos;
        switch (opt) {
        case 60:
            if (!rec->dhcp_vendor_class[0]) {
                copy_bounded(rec->dhcp_vendor_class, sizeof(rec->dhcp_vendor_class), v, ol);
                eui_lookup_dhcp_vc(rec->dhcp_vendor_class,
                                   &rec->dhcp_flags, &rec->dhcp_class);
            }
            break;
        case 55:
            if (rec->dhcp_opt55_len == 0) {
                uint8_t cap = ol > sizeof(rec->dhcp_opt55) ? sizeof(rec->dhcp_opt55) : ol;
                memcpy(rec->dhcp_opt55, v, cap);
                rec->dhcp_opt55_len = cap;

                if (rec->dhcp_class == 0) {
                    eui_lookup_dhcp_fp(rec->dhcp_opt55, rec->dhcp_opt55_len,
                                       &rec->dhcp_flags, &rec->dhcp_class);
                }
            }
            break;
        default: break;
        }
        pos += ol;
    }
}

static void maybe_count_l2l3(sniffer_rec_t *rec, const uint8_t *p, uint16_t len, uint16_t llc_off)
{

    if (!rec || !p || len < llc_off + 8) return;
    const uint8_t *llc = &p[llc_off];

    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
    const uint8_t *snap = &llc[3];
    uint16_t pid = ((uint16_t)llc[6] << 8) | llc[7];
    const uint8_t *payload = &llc[8];
    uint16_t payload_len = (uint16_t)(len - (llc_off + 8));

    if (snap[0] == 0x00 && snap[1] == 0x00 && snap[2] == 0x0C && pid == 0x2000) {
        bump_sat_u8(&rec->cdp_count);
        parse_cdp_payload(rec, payload, payload_len);
        return;
    }

    if (snap[0] == 0x00 && snap[1] == 0x00 && snap[2] == 0x00 && pid == 0x88CC) {
        bump_sat_u8(&rec->lldp_count);
        parse_lldp_payload(rec, payload, payload_len);
        return;
    }

    if (!(snap[0] == 0x00 && snap[1] == 0x00 && snap[2] == 0x00 && pid == 0x0800)) return;
    if (len < llc_off + 8 + 20) return;
    const uint8_t *ip = &llc[8];
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20) return;
    if (len < llc_off + 8 + ihl + 8) return;
    if (ip[9] != 17) return;
    const uint8_t *udp = ip + ihl;
    uint16_t sport = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dport = ((uint16_t)udp[2] << 8) | udp[3];
    if (!((sport == 67 || sport == 68) && (dport == 67 || dport == 68))) return;
    bump_sat_u8(&rec->dhcp_count);

    if (len < llc_off + 8 + ihl + 8 + 240) return;
    parse_dhcp_payload(rec, udp + 8, (uint16_t)(len - (llc_off + 8 + ihl + 8)));
}

static sniffer_rec_t *find_or_alloc(const uint8_t bssid[6])
{
    for (uint16_t i = 0; i < s_count; i++) {
        if (memcmp(s_db[i].bssid, bssid, 6) == 0) return &s_db[i];
    }
    if (s_count < SNIFF_MAX_APS) {
        sniffer_rec_t *r = &s_db[s_count++];
        memset(r, 0, sizeof(*r));
        memcpy(r->bssid, bssid, 6);
        r->valid = true;
        return r;
    }
    return NULL;
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_active || !buf) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    uint8_t want_ch = s_req_channel;
    if (want_ch) {
        uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
        if (now_ms - s_hop_ms < SNIFF_HOP_SETTLE_MS) { s_drop_settling++; return; }
        if (pkt->rx_ctrl.channel != want_ch)         { s_drop_offchan++;  return; }
    }

    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len <= 4) return;
    len -= 4;

    if (type == WIFI_PKT_CTRL) {
        if (!s_capture_ctrl || len < 1) return;
        uint8_t subtype = (pkt->payload[0] >> 4) & 0x0F;
        switch (subtype) {
        case 0x8: s_ctrl.bar++;    break;
        case 0x9: s_ctrl.ba++;     break;
        case 0xA: s_ctrl.pspoll++; break;
        case 0xB: s_ctrl.rts++;    break;
        case 0xC: s_ctrl.cts++;    break;
        case 0xD: s_ctrl.ack++;    break;
        default:  s_ctrl.other++;  break;
        }
        s_ctrl.total++;
        return;
    }

    if (type == WIFI_PKT_DATA) {

        sta_tracker_observe_frame(pkt->payload, len, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
        uint8_t bssid[6];
        uint16_t llc_off = 0;
        if (!parse_data_frame_bssid(pkt->payload, len, bssid, &llc_off)) return;
        sniffer_rec_t *rec = find_or_alloc(bssid);
        if (!rec) return;
        maybe_count_l2l3(rec, pkt->payload, len, llc_off);
        return;
    }

    if (type != WIFI_PKT_MGMT) return;

    parsed_mgmt_t fr;
    if (!frame_parse_mgmt(pkt->payload, len, &fr)) return;

    if (fr.type == MGMT_PROBE_REQ) {
        probe_req_log_observe(fr.ssid, fr.bssid);
        flock_detect_observe_probe(fr.bssid, fr.ssid);
        seq_analyzer_observe_probe_req(fr.bssid, fr.seq_num);
        ie_signature_observe_probe_req(fr.bssid, fr.ie_pattern_hash);

        probe_frame_t pf = {
            .seq_num = fr.seq_num,
            .ie_hash = fr.ie_pattern_hash,
            .rssi    = pkt->rx_ctrl.rssi,
            .channel = pkt->rx_ctrl.channel,
            .ts_ms   = (uint32_t)(esp_timer_get_time() / 1000),
            .is_anqp = false,
        };
        memcpy(pf.src_mac, fr.bssid, 6);
        strlcpy(pf.ssid, fr.ssid, sizeof(pf.ssid));
        probe_frame_ring_add(&pf);
        return;
    }

    if (fr.type == MGMT_ANQP) {
        anqp_analyzer_observe_query(fr.bssid);
        probe_frame_t pf = {
            .rssi    = pkt->rx_ctrl.rssi,
            .channel = pkt->rx_ctrl.channel,
            .ts_ms   = (uint32_t)(esp_timer_get_time() / 1000),
            .is_anqp = true,
        };
        memcpy(pf.src_mac, fr.bssid, 6);
        probe_frame_ring_add(&pf);
        return;
    }

    sniffer_rec_t *rec = find_or_alloc(fr.bssid);
    if (!rec) return;

    if (fr.has_rid && !rec->has_rid) {
        rec->has_rid = true;
        rec->drone   = fr.rid;
    }

    switch (fr.type) {
    case MGMT_BEACON:

        if (fr.ssid[0] && !rec->ssid[0])
            strlcpy(rec->ssid, fr.ssid, sizeof(rec->ssid));

        for (uint8_t k = 0; k < fr.vendor_ie_count && rec->vendor_ie_count < 4; k++) {
            bool dup = false;
            for (uint8_t m = 0; m < rec->vendor_ie_count; m++) {
                if (memcmp(rec->vendor_ie_ouis[m], fr.vendor_ie_ouis[k], 3) == 0) {
                    dup = true; break;
                }
            }
            if (!dup) memcpy(rec->vendor_ie_ouis[rec->vendor_ie_count++], fr.vendor_ie_ouis[k], 3);
        }
        __attribute__((fallthrough));
    case MGMT_PROBE_RESP:

        if (fr.type == MGMT_PROBE_RESP && rec->ssid[0] && fr.ssid[0]
            && strcmp(fr.ssid, rec->ssid) != 0) {
            bool dup = false;
            for (uint8_t k = 0; k < rec->probe_resp_count; k++) {
                if (strcmp(rec->probe_resp_ssids[k], fr.ssid) == 0) { dup = true; break; }
            }
            if (!dup && rec->probe_resp_count < 4) {
                strlcpy(rec->probe_resp_ssids[rec->probe_resp_count++], fr.ssid,
                        sizeof(rec->probe_resp_ssids[0]));
                rec->karma_suspect = true;
            }
        }
        if (fr.beacon_interval)  rec->beacon_interval  = fr.beacon_interval;
        if (fr.has_rsn)          rec->has_rsn           = true;
        if (fr.rsn_pmf_required) rec->rsn_pmf_required  = true;
        if (fr.rsn_pmf_capable)  rec->rsn_pmf_capable   = true;
        if (fr.has_wps)          rec->has_wps            = true;
        if (fr.rsn_malformed)    rec->rsn_malformed      = true;

        if (fr.wps_manufacturer[0] && !rec->wps_manufacturer[0])
            strlcpy(rec->wps_manufacturer, fr.wps_manufacturer, sizeof(rec->wps_manufacturer));
        if (fr.wps_model_name[0] && !rec->wps_model_name[0])
            strlcpy(rec->wps_model_name, fr.wps_model_name, sizeof(rec->wps_model_name));
        if (fr.country_code[0] && !rec->country_code[0]) {
            rec->country_code[0] = fr.country_code[0];
            rec->country_code[1] = fr.country_code[1];
            rec->country_code[2] = '\0';
        }
        if (fr.has_rsn && rec->rsn_group_suite == 0) {
            memcpy(rec->rsn_group_oui, fr.rsn_group_oui, 3);
            rec->rsn_group_suite = fr.rsn_group_suite;
        }
        if (fr.ie_pattern_hash && !rec->ie_pattern_hash)
            rec->ie_pattern_hash = fr.ie_pattern_hash;

        rec->beacon_seen = true;
        rec->privacy     = fr.privacy;
        rec->channel     = pkt->rx_ctrl.channel;
        if (rec->beacon_count == 0 || pkt->rx_ctrl.rssi > rec->rssi)
            rec->rssi = pkt->rx_ctrl.rssi;
        rec->beacon_count++;
        break;

    case MGMT_DEAUTH:
    case MGMT_DISASSOC:
        if (rec->deauth_count < 255) rec->deauth_count++;
        break;

    default:
        break;
    }
}

esp_err_t wifi_sniffer_run(const scan_results_t *results, uint32_t dwell_ms, bool capture_ctrl)
{
    if (!results) return ESP_ERR_INVALID_ARG;

    memset(s_db, 0, sizeof(s_db));
    s_count = 0;
    s_req_channel = 0;
    s_drop_settling = 0;
    s_drop_offchan = 0;
    memset(&s_ctrl, 0, sizeof(s_ctrl));
    s_capture_ctrl = capture_ctrl;

    uint8_t channels[WIFI_SCAN_MAX_APS];
    uint8_t n_ch = 0;

    for (uint16_t i = 0; i < results->count; i++) {
        uint8_t ch = results->entries[i].channel;
        bool dup = false;
        for (uint8_t j = 0; j < n_ch; j++) {
            if (channels[j] == ch) { dup = true; break; }
        }
        if (!dup && n_ch < WIFI_SCAN_MAX_APS) channels[n_ch++] = ch;
    }

    if (n_ch == 0) return ESP_OK;

    ESP_LOGI(TAG, "sniff: %u channels, %u ms hop, %lu ms/channel budget (loopback)",
             n_ch, SNIFF_HOP_MS, (unsigned long)dwell_ms);

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
    if (capture_ctrl) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filt);
    if (capture_ctrl) {
        wifi_promiscuous_filter_t cfilt = { .filter_mask =
            WIFI_PROMIS_CTRL_FILTER_MASK_RTS  | WIFI_PROMIS_CTRL_FILTER_MASK_CTS    |
            WIFI_PROMIS_CTRL_FILTER_MASK_ACK  | WIFI_PROMIS_CTRL_FILTER_MASK_BA     |
            WIFI_PROMIS_CTRL_FILTER_MASK_BAR  | WIFI_PROMIS_CTRL_FILTER_MASK_PSPOLL };
        esp_wifi_set_promiscuous_ctrl_filter(&cfilt);
    }
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);
    s_active = true;
    esp_wifi_set_promiscuous(true);

    uint32_t total_ms = (uint32_t)n_ch * dwell_ms;
    uint32_t start_ms = (uint32_t)(esp_timer_get_time() / 1000);
    for (uint32_t i = 0;
         i < n_ch || (uint32_t)(esp_timer_get_time() / 1000) - start_ms < total_ms;
         i++) {
        uint8_t ch = channels[i % n_ch];

        s_hop_ms = (uint32_t)(esp_timer_get_time() / 1000);
        s_req_channel = ch;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(SNIFF_HOP_MS));
    }

    s_req_channel = 0;
    s_active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    for (uint16_t i = 0; i < s_count; i++) {
        const sniffer_rec_t *r = &s_db[i];
        ESP_LOGI(TAG,
                 "SNIF[%u] bssid=%02X:%02X:%02X:%02X:%02X:%02X ssid=\"%s\" bc=%lu deauth=%u rsn=%u pmf_req=%u wps=%u malformed=%u karma=%u ie=%u lldp=%u cdp=%u dhcp=%u",
                 (unsigned)i,
                 r->bssid[0], r->bssid[1], r->bssid[2], r->bssid[3], r->bssid[4], r->bssid[5],
                 r->ssid[0] ? r->ssid : "<unknown>",
                 (unsigned long)r->beacon_count, (unsigned)r->deauth_count,
                 r->has_rsn ? 1u : 0u, r->rsn_pmf_required ? 1u : 0u,
                 r->has_wps ? 1u : 0u, r->rsn_malformed ? 1u : 0u,
                 r->karma_suspect ? 1u : 0u, (unsigned)r->vendor_ie_count,
                 (unsigned)r->lldp_count, (unsigned)r->cdp_count, (unsigned)r->dhcp_count);
    }

    ESP_LOGI(TAG, "sniff hop-guard: dropped %lu settling, %lu off-channel",
             (unsigned long)s_drop_settling, (unsigned long)s_drop_offchan);
    if (s_capture_ctrl) {
        ESP_LOGI(TAG,
                 "sniff ctrl: rts=%lu cts=%lu ack=%lu ba=%lu bar=%lu pspoll=%lu other=%lu total=%lu",
                 (unsigned long)s_ctrl.rts, (unsigned long)s_ctrl.cts,
                 (unsigned long)s_ctrl.ack, (unsigned long)s_ctrl.ba,
                 (unsigned long)s_ctrl.bar, (unsigned long)s_ctrl.pspoll,
                 (unsigned long)s_ctrl.other, (unsigned long)s_ctrl.total);
    }
    ESP_LOGI(TAG, "sniff done: %u BSSIDs observed", s_count);
    return ESP_OK;
}

const sniffer_ctrl_stats_t *wifi_sniffer_ctrl_stats(void) { return &s_ctrl; }

static void sta_window_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_active || !buf || type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len <= 4) return;
    len -= 4;
    sta_tracker_observe_frame(pkt->payload, len, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel);
}

esp_err_t wifi_sniffer_sta_window(uint8_t channel, uint32_t ms)
{
    sta_tracker_begin_scan();

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(sta_window_cb);
    s_active = true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    vTaskDelay(pdMS_TO_TICKS(ms));

    s_active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    sta_tracker_finalize();
    ESP_LOGI(TAG, "sta-window: ch=%u %lums -> %u stations (%u cameras)",
             (unsigned)channel, (unsigned long)ms,
             (unsigned)sta_tracker_count(), (unsigned)sta_tracker_camera_count());
    return ESP_OK;
}

const sniffer_rec_t *wifi_sniffer_get(const uint8_t bssid[6])
{
    for (uint16_t i = 0; i < s_count; i++) {
        if (s_db[i].valid && memcmp(s_db[i].bssid, bssid, 6) == 0)
            return &s_db[i];
    }
    return NULL;
}

uint16_t wifi_sniffer_bssid_count(void) { return s_count; }

const sniffer_rec_t *wifi_sniffer_at(uint16_t idx)
{
    if (idx >= s_count) return NULL;
    return &s_db[idx];
}
