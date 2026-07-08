

#include "virtual_pup_walk.h"
#include "analyzer.h"

#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "nvs.h"
#include <stddef.h>
#include <string.h>

static const char *TAG = "vp_walk";

#define PW_NS        "uicfg"
#define PW_K_ID      "pw_id"
#define PW_K_DUR     "pw_dur"
#define PW_K_WIFI    "pw_wb"
#define PW_K_SSID    "pw_ws"
#define PW_K_BLE     "pw_bd"
#define PW_K_SWEEP   "pw_sw"
#define PW_K_WIN     "pw_wn"
#define PW_K_THR     "pw_th"
#define PW_K_SAFE    "pw_sf"
#define PW_K_INT     "pw_in"
#define PW_K_XP      "pw_xp"
#define PW_K_MOOD    "pw_md"

#define WALK_MAX_BSSID       2048
#define WALK_MAX_BLE         2048
#define WALK_MAX_SSID        2048
#define WALK_WIFI_HASH_SLOTS 4096
#define WALK_BLE_HASH_SLOTS  4096
#define WALK_SSID_HASH_SLOTS 4096

typedef struct {
    ap_score_t    wifi[WALK_MAX_BSSID];
    ble_device_t  ble[WALK_MAX_BLE];
    uint16_t      wifi_n;
    uint16_t      ble_n;
    uint16_t      wifi_index[WALK_WIFI_HASH_SLOTS];
    uint16_t      ble_index[WALK_BLE_HASH_SLOTS];
    uint32_t      ssid_hash[WALK_SSID_HASH_SLOTS];
    uint16_t      ssid_n;
    bool          high_threat;
} walk_sets_t;

static walk_sets_t       *s_sets;
static pup_walk_summary_t s_cur;
static pup_walk_summary_t s_last;

static inline uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    if (!s) return h;
    while (*s) { h ^= (uint8_t)*s++; h *= 16777619u; }
    return h ? h : 1u;
}

static uint32_t mac_hash(const uint8_t mac[6])
{
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    return h;
}

static int16_t mac_index_find(uint16_t index[], uint16_t slots,
                              const void *records, size_t record_size,
                              size_t mac_offset, const uint8_t mac[6])
{
    uint16_t pos = (uint16_t)(mac_hash(mac) & (slots - 1));
    for (uint16_t probe = 0; probe < slots; probe++) {
        uint16_t v = index[pos];
        if (!v) return -1;
        const uint8_t *base = (const uint8_t *)records + ((size_t)(v - 1) * record_size);
        if (memcmp(base + mac_offset, mac, 6) == 0) return (int16_t)(v - 1);
        pos = (uint16_t)((pos + 1) & (slots - 1));
    }
    return -1;
}

static bool mac_index_insert(uint16_t index[], uint16_t slots,
                             uint16_t retained_idx, const uint8_t mac[6])
{
    uint16_t pos = (uint16_t)(mac_hash(mac) & (slots - 1));
    for (uint16_t probe = 0; probe < slots; probe++) {
        if (!index[pos]) {
            index[pos] = (uint16_t)(retained_idx + 1);
            return true;
        }
        pos = (uint16_t)((pos + 1) & (slots - 1));
    }
    return false;
}

static bool ssid_hash_add(uint32_t v)
{
    if (!s_sets) return false;
    if (!v) v = 1u;
    uint16_t pos = (uint16_t)(v & (WALK_SSID_HASH_SLOTS - 1));
    for (uint16_t probe = 0; probe < WALK_SSID_HASH_SLOTS; probe++) {
        if (s_sets->ssid_hash[pos] == v) return false;
        if (!s_sets->ssid_hash[pos]) {
            if (s_sets->ssid_n >= WALK_MAX_SSID) return false;
            s_sets->ssid_hash[pos] = v;
            s_sets->ssid_n++;
            return true;
        }
        pos = (uint16_t)((pos + 1) & (WALK_SSID_HASH_SLOTS - 1));
    }
    return false;
}

static void save_last(void)
{
    nvs_handle_t h;
    if (nvs_open(PW_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u32(h, PW_K_ID,    s_last.walk_id);
    nvs_set_u32(h, PW_K_DUR,   s_last.duration_sec);
    nvs_set_u16(h, PW_K_WIFI,  s_last.wifi_unique_bssid);
    nvs_set_u16(h, PW_K_SSID,  s_last.wifi_unique_ssid);
    nvs_set_u16(h, PW_K_BLE,   s_last.ble_unique_devices);
    nvs_set_u16(h, PW_K_SWEEP, s_last.wifi_sweeps);
    nvs_set_u16(h, PW_K_WIN,   s_last.ble_windows);
    nvs_set_u16(h, PW_K_THR,   s_last.threat_events);
    nvs_set_u16(h, PW_K_SAFE,  s_last.safe_networks);
    nvs_set_u16(h, PW_K_INT,   s_last.interesting_sniffs);
    nvs_set_u16(h, PW_K_XP,    s_last.xp_awarded);
    nvs_set_str(h, PW_K_MOOD,  s_last.mood);
    nvs_commit(h);
    nvs_close(h);
}

void virtual_pup_walk_init(void)
{
    memset(&s_cur,  0, sizeof(s_cur));
    memset(&s_last, 0, sizeof(s_last));
    strcpy(s_last.mood, "content");

    nvs_handle_t h;
    if (nvs_open(PW_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, PW_K_ID,    &s_last.walk_id);
        nvs_get_u32(h, PW_K_DUR,   &s_last.duration_sec);
        nvs_get_u16(h, PW_K_WIFI,  &s_last.wifi_unique_bssid);
        nvs_get_u16(h, PW_K_SSID,  &s_last.wifi_unique_ssid);
        nvs_get_u16(h, PW_K_BLE,   &s_last.ble_unique_devices);
        nvs_get_u16(h, PW_K_SWEEP, &s_last.wifi_sweeps);
        nvs_get_u16(h, PW_K_WIN,   &s_last.ble_windows);
        nvs_get_u16(h, PW_K_THR,   &s_last.threat_events);
        nvs_get_u16(h, PW_K_SAFE,  &s_last.safe_networks);
        nvs_get_u16(h, PW_K_INT,   &s_last.interesting_sniffs);
        nvs_get_u16(h, PW_K_XP,    &s_last.xp_awarded);
        size_t mlen = sizeof(s_last.mood);
        nvs_get_str(h, PW_K_MOOD,  s_last.mood, &mlen);
        nvs_close(h);
    }
}

void virtual_pup_walk_start(void)
{
    virtual_pup_walk_release();
    s_sets = heap_caps_calloc(1, sizeof(walk_sets_t), MALLOC_CAP_SPIRAM);
    if (!s_sets)
        ESP_LOGE(TAG, "walk sets alloc failed (%u B) — unique tracking off",
                 (unsigned)sizeof(walk_sets_t));
    memset(&s_cur,  0, sizeof(s_cur));
    s_cur.active     = true;
    s_cur.walk_id    = s_last.walk_id + 1;
    s_cur.started_ms = now_ms();
    strcpy(s_cur.mood, "curious");
    ESP_LOGI(TAG, "walk %u started", (unsigned)s_cur.walk_id);
}

void virtual_pup_walk_note_wifi_ap(const ap_score_t *ap, bool safe_candidate)
{
    if (!s_cur.active || !ap || ap->suppressed) return;

    if (s_sets) {
        int16_t idx = mac_index_find(s_sets->wifi_index, WALK_WIFI_HASH_SLOTS,
                                     s_sets->wifi, sizeof(s_sets->wifi[0]),
                                     offsetof(ap_score_t, bssid), ap->bssid);
        if (idx >= 0) {
            s_sets->wifi[idx] = *ap;
        } else if (s_sets->wifi_n < WALK_MAX_BSSID &&
                   mac_index_insert(s_sets->wifi_index, WALK_WIFI_HASH_SLOTS,
                                    s_sets->wifi_n, ap->bssid)) {
            s_sets->wifi[s_sets->wifi_n] = *ap;
            s_sets->wifi_n++;
            s_cur.wifi_unique_bssid = s_sets->wifi_n;
        }

        if (ap->ssid[0] && ssid_hash_add(fnv1a(ap->ssid)))
            s_cur.wifi_unique_ssid = s_sets->ssid_n;

        if (ap->threat_level >= THREAT_HIGH) s_sets->high_threat = true;
    }

    if (ap->threat_level >= THREAT_MEDIUM) s_cur.threat_events++;
    else if (ap->threat_level == THREAT_LOW) s_cur.interesting_sniffs++;
    if (safe_candidate) s_cur.safe_networks++;
}

void virtual_pup_walk_note_ble_device(const ble_device_t *d)
{
    if (!s_cur.active || !d || d->suppressed) return;

    if (s_sets) {
        int16_t idx = mac_index_find(s_sets->ble_index, WALK_BLE_HASH_SLOTS,
                                     s_sets->ble, sizeof(s_sets->ble[0]),
                                     offsetof(ble_device_t, addr), d->addr);
        if (idx >= 0) {
            s_sets->ble[idx] = *d;
        } else if (s_sets->ble_n < WALK_MAX_BLE &&
                   mac_index_insert(s_sets->ble_index, WALK_BLE_HASH_SLOTS,
                                    s_sets->ble_n, d->addr)) {
            s_sets->ble[s_sets->ble_n] = *d;
            s_sets->ble_n++;
            s_cur.ble_unique_devices = s_sets->ble_n;
        }

        if (d->threat_level >= THREAT_HIGH) s_sets->high_threat = true;
    }

    if (d->threat_level >= THREAT_MEDIUM) s_cur.threat_events++;
    else if (d->threat_level == THREAT_LOW) s_cur.interesting_sniffs++;
}

void virtual_pup_walk_end_wifi_sweep(void) { if (s_cur.active) s_cur.wifi_sweeps++; }
void virtual_pup_walk_end_ble_window(void) { if (s_cur.active) s_cur.ble_windows++; }

bool virtual_pup_walk_is_active(void) { return s_cur.active; }

void virtual_pup_walk_get_current(pup_walk_summary_t *out)
{
    if (!out) return;
    *out = s_cur;
    if (s_cur.active)
        out->duration_sec = (now_ms() - s_cur.started_ms) / 1000;
}

void virtual_pup_walk_get_last(pup_walk_summary_t *out)
{
    if (out) *out = s_last;
}

uint16_t virtual_pup_walk_wifi_count(void) { return s_sets ? s_sets->wifi_n : 0; }
uint16_t virtual_pup_walk_ble_count(void)  { return s_sets ? s_sets->ble_n : 0; }

const ap_score_t *virtual_pup_walk_wifi_at(uint16_t idx)
{
    return (s_sets && idx < s_sets->wifi_n) ? &s_sets->wifi[idx] : NULL;
}

const ble_device_t *virtual_pup_walk_ble_at(uint16_t idx)
{
    return (s_sets && idx < s_sets->ble_n) ? &s_sets->ble[idx] : NULL;
}

void virtual_pup_walk_release(void)
{
    if (!s_sets) return;
    heap_caps_free(s_sets);
    s_sets = NULL;
}

static uint16_t compute_xp(const pup_walk_summary_t *w, bool high_threat)
{
    uint32_t xp = 2;
    uint32_t mins = w->duration_sec / 60;
    xp += mins > 15 ? 15 : mins;
    xp += w->wifi_sweeps > 10 ? 10 : w->wifi_sweeps;
    xp += w->ble_windows > 10 ? 10 : w->ble_windows;
    uint32_t obs = w->wifi_unique_bssid + w->ble_unique_devices;
    if (obs > 25) obs = 25;
    xp += obs / 5;
    if (w->safe_networks > 0) xp += 2;
    if (high_threat)          xp += 3;
    xp += 1;
    if (xp > 35) xp = 35;
    return (uint16_t)xp;
}

bool virtual_pup_walk_end(pup_walk_summary_t *out)
{
    if (!s_cur.active) return false;
    s_cur.active       = false;
    s_cur.ended_ms     = now_ms();
    s_cur.duration_sec = (s_cur.ended_ms - s_cur.started_ms) / 1000;
    s_cur.xp_awarded   = compute_xp(&s_cur, s_sets && s_sets->high_threat);

    if (s_cur.threat_events > 0)
        strcpy(s_cur.mood, "alert");
    else if (s_cur.safe_networks > 0 || s_cur.interesting_sniffs > 0)
        strcpy(s_cur.mood, "happy");
    else
        strcpy(s_cur.mood, "content");

    s_last = s_cur;
    save_last();
    ESP_LOGI(TAG, "walk %u ended: %us wifi=%u/%u ble=%u thr=%u xp=%u (%s)",
             (unsigned)s_last.walk_id, (unsigned)s_last.duration_sec,
             s_last.wifi_unique_bssid, s_last.wifi_unique_ssid,
             s_last.ble_unique_devices, s_last.threat_events,
             s_last.xp_awarded, s_last.mood);
    if (out) *out = s_last;
    return true;
}
