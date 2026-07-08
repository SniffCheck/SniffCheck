#include "sta_tracker.h"

#include <string.h>
#include "eui_db.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "sc_sta";

static sta_entry_t s_stas[STA_TRACKER_MAX];
static uint16_t    s_count;
static uint16_t    s_camera_count;

void sta_tracker_begin_scan(void)
{
    s_count = 0;
    s_camera_count = 0;
    memset(s_stas, 0, sizeof(s_stas));
}

static bool extract_client(const uint8_t *p, uint16_t len, uint8_t out[6],
                           uint8_t bssid[6], int8_t *dir)
{
    if (!p || len < 24) return false;
    uint8_t fc0 = p[0], fc1 = p[1];
    if (((fc0 >> 2) & 0x03) != 2) return false;

    bool to_ds   = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    if (to_ds && from_ds) return false;

    const uint8_t *c;
    if (to_ds && !from_ds)      { c = &p[10]; memcpy(bssid, &p[4],  6); *dir = +1; }
    else if (!to_ds && from_ds) { c = &p[4];  memcpy(bssid, &p[10], 6); *dir = -1; }
    else                        { c = &p[10]; memcpy(bssid, &p[16], 6); *dir =  0; }

    if (c[0] & 0x01) return false;
    memcpy(out, c, 6);
    return true;
}

void sta_tracker_observe_frame(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t channel)
{
    uint8_t mac[6], bssid[6];
    int8_t  dir;
    if (!extract_client(frame, len, mac, bssid, &dir)) return;

    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);

    sta_entry_t *e = NULL;
    for (uint16_t i = 0; i < s_count; i++) {
        if (memcmp(s_stas[i].mac, mac, 6) == 0) { e = &s_stas[i]; break; }
    }
    if (!e) {
        if (s_count >= STA_TRACKER_MAX) return;
        e = &s_stas[s_count++];
        memset(e, 0, sizeof(*e));
        memcpy(e->mac, mac, 6);
        e->device_class = EUI_CLASS_UNKNOWN;
        e->randomized = (mac[0] & 0x02) != 0;
        e->first_seen_ms = now_ms;
        e->rssi_best = rssi;
    }

    if (e->frames < UINT32_MAX) e->frames++;
    e->last_seen_ms = now_ms;
    e->rssi_last = rssi;
    if (rssi > e->rssi_best) e->rssi_best = rssi;
    e->channel = channel;
    if (dir > 0 && e->frames_uplink   < UINT32_MAX) e->frames_uplink++;
    if (dir < 0 && e->frames_downlink < UINT32_MAX) e->frames_downlink++;
    memcpy(e->bssid, bssid, 6);
    e->bssid_valid = true;
}

void sta_tracker_finalize(void)
{
    s_camera_count = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        sta_entry_t *e = &s_stas[i];
        if (e->randomized) continue;

        uint16_t flags = 0;
        uint8_t  cls = EUI_CLASS_UNKNOWN, mlen = 0;
        e->vendor = eui_lookup_mac(e->mac, &flags, &cls, &mlen);
        e->eui_flags = flags;
        e->device_class = cls;

        if ((flags & EUI_FLAG_SURVEILLANCE) || cls == EUI_CLASS_SURVEILLANCE_CAM) {
            e->is_camera = true;
            s_camera_count++;
            ESP_LOGW(TAG,
                     "possible camera on Wi-Fi: %02X:%02X:%02X:%02X:%02X:%02X "
                     "vendor=%s frames=%u",
                     e->mac[0], e->mac[1], e->mac[2],
                     e->mac[3], e->mac[4], e->mac[5],
                     e->vendor ? e->vendor : "?", (unsigned)e->frames);
        }
    }
}

uint16_t sta_tracker_count(void)        { return s_count; }
uint16_t sta_tracker_camera_count(void) { return s_camera_count; }
uint16_t sta_tracker_entry_count(void)  { return s_count; }

const sta_entry_t *sta_tracker_at(uint16_t idx)
{
    return (idx < s_count) ? &s_stas[idx] : NULL;
}
