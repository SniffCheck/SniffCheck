#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_attr.h"

#include "wifi_scanner.h"
#include "wifi_sniffer.h"
#include "analyzer.h"
#include "ble_scanner.h"
#include "ble_advise.h"
#include "probe_req_log.h"
#include "seq_analyzer.h"
#include "ie_signature.h"
#include "anqp_analyzer.h"
#include "probe_frame_ring.h"
#include "ble_adv_ring.h"
#include "flock_detect.h"
#include "sta_tracker.h"
#include "physical_device_cluster.h"
#include "public_safety_detect.h"
#include "medical_responder_detect.h"
#include "eui_db.h"
#include "capture_ring.h"
#include "capture_writer.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "pup_trophy.h"

#include "arm_scan.h"

static const char *TAG = "arm-scan";

#define SNIFF_DWELL_MS          600
#define WIFI_ADV_ACTIVE_SWEEPS  4
#define WIFI_ADV_MAX_MS         60000
#define BLE_ADV_SCAN_MS         30000
#define WIFI_WARDRIVE_5G_EVERY  4
#define WALK_BLE_WINDOW_MS      3000
#define WALK_MAX_SEC            (30 * 60)

#define CL_SCANSET_MAX  (192 * 1024)
static EXT_RAM_BSS_ATTR uint8_t s_ss_a[CL_SCANSET_MAX];
static EXT_RAM_BSS_ATTR uint8_t s_ss_b[CL_SCANSET_MAX];
static uint8_t *volatile s_ss_front = s_ss_a;
static uint32_t volatile s_ss_len   = 0;

static EXT_RAM_BSS_ATTR scan_results_t s_results;
static EXT_RAM_BSS_ATTR ap_score_t     s_scores[ANALYZER_MAX_APS];
static EXT_RAM_BSS_ATTR ble_results_t  s_ble;
static EXT_RAM_BSS_ATTR ble_results_t  s_ble_win;

static uint16_t s_scan_idx;
static environment_indicators_t s_env_ind;

static const uint8_t CHAN_UNION[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
};
#define ARM_SCAN_DWELL_LITE_MS 80
#define ARM_SCAN_DWELL_ADV_MS  160

static uint8_t  s_arm_index    = 1;
static uint8_t  s_plan_narms   = 2;
static uint8_t  s_plan_slot    = 0;
static uint16_t s_dwell_lite   = ARM_SCAN_DWELL_LITE_MS;
static uint16_t s_dwell_adv    = ARM_SCAN_DWELL_ADV_MS;
static uint8_t  s_ble_every_n  = 0;
static bool     s_incl_dfs     = true;

void arm_scan_set_plan(const cl_plan_t *p)
{
    if (!p) return;
    s_plan_narms  = (p->n_arms < 1) ? 1 : p->n_arms;
    s_plan_slot   = (p->arm_slot < s_plan_narms) ? p->arm_slot : 0;
    if (p->dwell_ms)     s_dwell_lite = p->dwell_ms;
    if (p->dwell_adv_ms) s_dwell_adv  = p->dwell_adv_ms;
    s_ble_every_n = p->ble_every_n;
    s_incl_dfs    = (p->flags & CL_PLAN_FLAG_DFS) != 0;
    ESP_LOGI(TAG, "plan set: slot %u/%u dwell %u/%u ms ble_every_n=%u dfs=%d",
             s_plan_slot, s_plan_narms, s_dwell_lite, s_dwell_adv,
             s_ble_every_n, s_incl_dfs);
}

static uint8_t arm_channel_plan(uint8_t *chans)
{
    uint8_t nc = 0;
    uint8_t stride = (s_plan_narms < 1) ? 1 : s_plan_narms;
    for (uint8_t i = s_plan_slot; i < sizeof(CHAN_UNION); i += stride) {
        uint8_t ch = CHAN_UNION[i];
        if (!s_incl_dfs && ch >= 52 && ch <= 144) continue;
        chans[nc++] = ch;
    }
    return nc;
}

void arm_scan_init(uint8_t arm_index)
{
    s_arm_index = (arm_index == 2) ? 2 : 1;
    s_plan_slot = (s_arm_index == 2) ? 1 : 0;
    ESP_ERROR_CHECK(wifi_scanner_init());
    ESP_ERROR_CHECK(ble_scanner_init());
    probe_req_log_init();
    seq_analyzer_init();
    ie_signature_init();
    anqp_analyzer_init();
    probe_frame_ring_init();
    ble_adv_ring_init();
    if (eui_db_init() != ESP_OK)
        ESP_LOGW(TAG, "EUI DB unavailable — vendor lookup disabled");

    virtual_pup_init(1);
    virtual_pup_walk_init();
    pup_trophy_init();

    ESP_ERROR_CHECK(capture_ring_init(2 * 1024 * 1024, 1 * 1024 * 1024));
    capture_writer_init(1);
    ESP_LOGI(TAG, "arm scan stack ready");
}

static void pack_scanset(void)
{
    uint8_t *back = (s_ss_front == s_ss_a) ? s_ss_b : s_ss_a;
    uint32_t off = 0;
    static char line[3200];

    capture_ring_reader_t rd;
    capture_ring_reader_open(&rd);
    size_t n;
    while ((n = capture_ring_reader_next(&rd, line, sizeof(line))) > 0) {
        if (off + n + 1 > CL_SCANSET_MAX) {
            ESP_LOGW(TAG, "scanset truncated at %u bytes", (unsigned)off);
            break;
        }
        memcpy(back + off, line, n);
        off += n;
        back[off++] = '\n';
    }
    s_ss_len   = off;
    s_ss_front = back;
    ESP_LOGI(TAG, "packed scanset: %u bytes", (unsigned)off);
}

const uint8_t *arm_scanset_ptr(void) { return s_ss_front; }
uint32_t       arm_scanset_len(void) { return s_ss_len; }

static void ble_accumulate(ble_results_t *dst, const ble_results_t *win)
{
    for (uint16_t i = 0; i < win->count; i++) {
        const ble_device_t *s = &win->devices[i];
        bool known = false;
        for (uint16_t j = 0; j < dst->count; j++) {
            if (memcmp(dst->devices[j].addr, s->addr, 6) == 0) {
                if (s->rssi > dst->devices[j].rssi) dst->devices[j] = *s;
                known = true;
                break;
            }
        }
        if (!known && dst->count < BLE_MAX_DEVICES) dst->devices[dst->count++] = *s;
    }
}

static esp_err_t arm_sweep_interleaved(const uint8_t *chans, uint8_t nchan,
                                       uint16_t dwell, uint32_t ble_ms, bool deep)
{
    s_results.count = 0;
    s_ble.count     = 0;
    ble_adv_ring_set_retention_mode(deep);
    ble_adv_ring_begin_scan();

    uint8_t every     = s_ble_every_n ? s_ble_every_n : nchan;
    uint8_t n_windows = (nchan + every - 1) / every;
    if (n_windows == 0) n_windows = 1;
    uint32_t per_win  = ble_ms / n_windows;
    if (per_win < 400) per_win = 400;

    for (uint8_t base = 0; base < nchan; base += every) {
        uint8_t cnt = (nchan - base < every) ? (uint8_t)(nchan - base) : every;
        esp_err_t e = wifi_scan_channels_append(&s_results, chans + base, cnt, dwell);
        if (e != ESP_OK) return e;
        ble_scan_run_ex(&s_ble_win, per_win, deep, deep);
        ble_accumulate(&s_ble, &s_ble_win);
    }
    ESP_LOGI(TAG, "interleaved sweep: %u APs + %u BLE over %u ch (BLE every %u hops @ %u ms)",
             (unsigned)s_results.count, (unsigned)s_ble.count, (unsigned)nchan,
             (unsigned)every, (unsigned)per_win);
    return ESP_OK;
}

void arm_scan_run(bool adv, uint16_t *wifi_seen, uint16_t *ble_seen)
{
    bool deep = adv;
    s_scan_idx++;

    memset(&s_results, 0, sizeof(s_results));
    memset(s_scores,   0, sizeof(s_scores));
    memset(&s_ble,     0, sizeof(s_ble));

    capture_ring_clear_volatile();
    capture_emit_header();
    capture_emit_codebook();

    uint8_t chans[sizeof(CHAN_UNION)];
    uint8_t nchan   = arm_channel_plan(chans);
    uint16_t dwell  = deep ? s_dwell_adv : s_dwell_lite;
    uint32_t ble_ms = deep ? BLE_ADV_SCAN_MS : BLE_SCAN_MS;
    bool interleave = (s_ble_every_n > 0);

    esp_err_t werr = interleave
        ? arm_sweep_interleaved(chans, nchan, dwell, ble_ms, deep)
        : wifi_scan_run_channels(&s_results, chans, nchan, dwell);
    if (werr != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi scan failed");
        if (wifi_seen) *wifi_seen = 0;
        if (ble_seen)  *ble_seen  = 0;
        pack_scanset();
        return;
    }

    bool retain = adv;
    probe_req_log_set_retention_mode(retain);
    seq_analyzer_set_retention_mode(retain);
    ie_signature_set_retention_mode(retain);
    anqp_analyzer_set_retention_mode(retain);
    probe_frame_ring_set_retention_mode(retain);
    probe_req_log_begin_scan();
    flock_detect_begin_scan();
    sta_tracker_begin_scan();
    seq_analyzer_begin_scan();
    ie_signature_begin_scan();
    anqp_analyzer_begin_scan();
    probe_frame_ring_begin_scan();

    wifi_sniffer_run(&s_results, SNIFF_DWELL_MS, adv);

    for (uint16_t i = 0; i < s_results.count; i++)
        probe_req_log_add_beacon_ssid(s_results.entries[i].ssid);
    uint16_t sniff_n = wifi_sniffer_bssid_count();
    for (uint16_t i = 0; i < sniff_n; i++) {
        const sniffer_rec_t *r = wifi_sniffer_at(i);
        if (r && r->ssid[0]) probe_req_log_add_beacon_ssid(r->ssid);
    }

    for (uint16_t i = 0; i < sniff_n && s_results.count < WIFI_SCAN_MAX_APS; i++) {
        const sniffer_rec_t *r = wifi_sniffer_at(i);
        if (!r || !r->beacon_seen) continue;
        bool known = false;
        for (uint16_t j = 0; j < s_results.count; j++)
            if (memcmp(s_results.entries[j].bssid, r->bssid, 6) == 0) { known = true; break; }
        if (known) continue;
        ap_record_t *e = &s_results.entries[s_results.count++];
        memset(e, 0, sizeof(*e));
        strlcpy(e->ssid, r->ssid, sizeof(e->ssid));
        memcpy(e->bssid, r->bssid, 6);
        e->rssi = r->rssi; e->channel = r->channel; e->band_5g = (r->channel >= 36);
        e->auth = r->has_rsn ? WIFI_AUTH_WPA2_PSK
                             : (r->privacy ? WIFI_AUTH_WEP : WIFI_AUTH_OPEN);
    }

    probe_req_log_finalize();
    sta_tracker_finalize();
    seq_analyzer_finalize();
    ie_signature_finalize();
    anqp_analyzer_finalize();

    uint16_t score_count = 0;
    analyzer_run(&s_results, NULL, s_scores, &score_count);

    if (!interleave) {
        ble_adv_ring_set_retention_mode(retain);
        ble_adv_ring_begin_scan();
        ble_scan_run_ex(&s_ble, ble_ms, deep, deep);
    }

    analyzer_run(&s_results, &s_ble, s_scores, &score_count);
    analyzer_xref_ble(s_scores, score_count, &s_ble);
    pdc_build(s_scores, score_count, &s_ble);

    for (uint16_t i = 0; i < score_count; i++) {
        capture_emit_wifi_ap(&s_scores[i], s_scan_idx);
        capture_emit_alerts_for_ap(&s_scores[i], s_scan_idx);
    }
    for (uint16_t i = 0; i < s_ble.count; i++) {
        capture_emit_ble_device(&s_ble.devices[i], s_scan_idx);
        capture_emit_tracker_if_applicable(&s_ble.devices[i], s_scan_idx);
        capture_emit_drone_rid_if_applicable(&s_ble.devices[i], s_scan_idx);
        capture_emit_alerts_for_ble(&s_ble.devices[i], s_scan_idx);
    }
    {
        uint16_t sn = wifi_sniffer_bssid_count();
        for (uint16_t i = 0; i < sn; i++) {
            const sniffer_rec_t *sr = wifi_sniffer_at(i);
            if (sr && sr->has_rid) capture_emit_drone_rid_wifi(sr, s_scan_idx);
        }
    }
    capture_emit_device_clusters(s_scan_idx);
    capture_emit_ble_addr_stats(&s_ble, s_scan_idx);
    capture_emit_probe_req_log(probe_req_log_get(), s_scan_idx, adv);
    capture_emit_seq_fingerprint_log(seq_analyzer_get(), s_scan_idx, adv);
    capture_emit_ie_signature_log(ie_signature_get(), s_scan_idx, adv);
    capture_emit_anqp_log(anqp_analyzer_get(), s_scan_idx, adv);
    capture_emit_station_log(s_scan_idx);
    capture_emit_channel_activity(s_scores, score_count, s_scan_idx);

    {
        crowd_estimate_t crowd;
        analyzer_crowd_estimate(&s_ble, sta_tracker_count(),
                                probe_req_log_get()->total_probe_reqs, &crowd);
        capture_emit_crowd_density(&crowd, s_scan_idx);
    }
    {
        ps_result_t ps;
        public_safety_begin(&ps);
        for (uint16_t i = 0; i < score_count; i++)
            if (!s_scores[i].suppressed) public_safety_eval_wifi(&s_scores[i], &ps);
        for (uint16_t i = 0; i < s_ble.count; i++)
            if (!s_ble.devices[i].suppressed) public_safety_eval_ble(&s_ble.devices[i], &ps);
        public_safety_finalize(&ps);
        capture_emit_law_enforcement_presence(&ps, s_scan_idx);
    }
    {
        mr_result_t mr;
        medical_responder_begin(&mr);
        for (uint16_t i = 0; i < score_count; i++)
            if (!s_scores[i].suppressed) medical_responder_eval_wifi(&s_scores[i], &mr);
        for (uint16_t i = 0; i < s_ble.count; i++)
            if (!s_ble.devices[i].suppressed) medical_responder_eval_ble(&s_ble.devices[i], &mr);
        medical_responder_finalize(&mr);
        capture_emit_medical_responder_presence(&mr, s_scan_idx);
    }
    {
        uint16_t cams = sta_tracker_camera_count();
        for (uint16_t i = 0; i < score_count; i++) {
            const ap_score_t *ap = &s_scores[i];
            if (ap->suppressed) continue;
            if ((ap->eui_flags & EUI_FLAG_SURVEILLANCE) ||
                ap->device_class == EUI_CLASS_SURVEILLANCE_CAM) cams++;
        }
        for (uint16_t i = 0; i < s_ble.count; i++) {
            const ble_device_t *d = &s_ble.devices[i];
            if (d->suppressed) continue;
            uint16_t fl = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags | d->uuid16_flags;
            if ((fl & EUI_FLAG_SURVEILLANCE) ||
                ble_effective_class(d) == EUI_CLASS_SURVEILLANCE_CAM) cams++;
        }
        const crowd_estimate_t *cd = analyzer_last_crowd();
        const ps_result_t      *ps = public_safety_last();
        const mr_result_t      *mr = medical_responder_last();
        s_env_ind = (environment_indicators_t){0};
        s_env_ind.camera_count       = cams;
        s_env_ind.camera_conf        = cams ? 70 : 0;
        s_env_ind.public_safety_low  = ps->estimated_officers_low;
        s_env_ind.public_safety_high = ps->estimated_officers_high;
        s_env_ind.public_safety_conf = ps->confidence;
        s_env_ind.phone_like_count   = cd->device_evidence;
        s_env_ind.phone_like_conf    = cd->device_evidence ? 40 : 0;
        s_env_ind.medical_count      = mr->matches;
        s_env_ind.medical_conf       = mr->confidence;
        capture_emit_environment_indicators(&s_env_ind, s_scan_idx);
    }

    pack_scanset();
    if (wifi_seen) *wifi_seen = score_count;
    if (ble_seen)  *ble_seen  = s_ble.count;
    ESP_LOGI(TAG, "scan done: wifi=%u ble=%u (adv=%d)", score_count, s_ble.count, adv);
}

void arm_walk_start(void)
{
    virtual_pup_walk_start();
}

void arm_walk_sweep(uint16_t *wifi_unique, uint16_t *ble_unique, uint32_t *dur_sec)
{
    static uint32_t walk_slice = 0;
    static EXT_RAM_BSS_ATTR scan_results_t walk_wifi;
    static EXT_RAM_BSS_ATTR ap_score_t     walk_scores[ANALYZER_MAX_APS];
    static EXT_RAM_BSS_ATTR ble_results_t  walk_ble;

    bool include_5g = (walk_slice++ % WIFI_WARDRIVE_5G_EVERY) == 0;
    memset(&walk_wifi, 0, sizeof(walk_wifi));
    if (wifi_scan_run_wardrive(&walk_wifi, include_5g) == ESP_OK) {
        uint16_t wc = 0;
        memset(walk_scores, 0, sizeof(walk_scores));
        analyzer_run(&walk_wifi, NULL, walk_scores, &wc);
        for (uint16_t i = 0; i < wc; i++) {
            const ap_score_t *ap = &walk_scores[i];
            bool safe = ap->auth != WIFI_AUTH_OPEN && ap->auth != WIFI_AUTH_WEP;
            virtual_pup_walk_note_wifi_ap(ap, safe);
        }
        virtual_pup_walk_end_wifi_sweep();
    }
    memset(&walk_ble, 0, sizeof(walk_ble));
    if (ble_scan_run_ex(&walk_ble, WALK_BLE_WINDOW_MS, true, false) == ESP_OK) {
        for (uint16_t i = 0; i < walk_ble.count; i++)
            virtual_pup_walk_note_ble_device(&walk_ble.devices[i]);
        virtual_pup_walk_end_ble_window();
    }

    pup_walk_summary_t cur;
    virtual_pup_walk_get_current(&cur);
    if (wifi_unique) *wifi_unique = cur.wifi_unique_bssid;
    if (ble_unique)  *ble_unique  = cur.ble_unique_devices;
    if (dur_sec)     *dur_sec     = cur.duration_sec;
}

void arm_walk_finish(bool *capped, uint16_t *wifi_seen, uint16_t *ble_seen)
{
    pup_walk_summary_t done = {0};
    uint16_t wc = 0, bc = 0;

    capture_ring_clear_volatile();
    capture_emit_header();
    capture_emit_codebook();

    if (virtual_pup_walk_end(&done)) {
        virtual_pup_grant_xp(done.xp_awarded);
        s_scan_idx++;
        wc = virtual_pup_walk_wifi_count();
        bc = virtual_pup_walk_ble_count();
        for (uint16_t i = 0; i < wc; i++) {
            const ap_score_t *ap = virtual_pup_walk_wifi_at(i);
            if (ap) {
                capture_emit_wifi_ap_walk(ap, s_scan_idx, done.walk_id);
                capture_emit_alerts_for_ap(ap, s_scan_idx);
            }
        }
        for (uint16_t i = 0; i < bc; i++) {
            const ble_device_t *d = virtual_pup_walk_ble_at(i);
            if (d) {
                capture_emit_ble_device_walk(d, s_scan_idx, done.walk_id);
                capture_emit_tracker_if_applicable(d, s_scan_idx);
                capture_emit_drone_rid_if_applicable(d, s_scan_idx);
                capture_emit_alerts_for_ble(d, s_scan_idx);
            }
        }
        capture_emit_pup_walk(&done);
    }
    virtual_pup_walk_release();

    pack_scanset();
    if (capped)    *capped    = (done.duration_sec >= WALK_MAX_SEC);
    if (wifi_seen) *wifi_seen = wc;
    if (ble_seen)  *ble_seen  = bc;
    ESP_LOGI(TAG, "walk done: wifi=%u ble=%u dur=%us", wc, bc, (unsigned)done.duration_sec);
}
