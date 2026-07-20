#include "dp_sniffer.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_log.h"

static const char *TAG = "dp_sniffer";

#define OBS_QUEUE_DEPTH  48

#define LIVE_MAX 40
typedef struct { uint8_t mac[6]; int8_t rssi; int64_t last_us; bool used; } live_t;
static live_t s_live[LIVE_MAX];
static portMUX_TYPE s_live_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool s_track;

static void live_update(const uint8_t mac[6], int8_t rssi)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL_ISR(&s_live_mux);
    int free_slot = -1, oldest = 0; int64_t oldest_us = INT64_MAX;
    for (int i = 0; i < LIVE_MAX; i++) {
        if (!s_live[i].used) { if (free_slot < 0) free_slot = i; continue; }
        if (memcmp(s_live[i].mac, mac, 6) == 0) {
            s_live[i].rssi = rssi; s_live[i].last_us = now;
            portEXIT_CRITICAL_ISR(&s_live_mux);
            return;
        }
        if (s_live[i].last_us < oldest_us) { oldest_us = s_live[i].last_us; oldest = i; }
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    memcpy(s_live[slot].mac, mac, 6);
    s_live[slot].rssi = rssi; s_live[slot].last_us = now; s_live[slot].used = true;
    portEXIT_CRITICAL_ISR(&s_live_mux);
}

#define SEEN_BITS   4096
#define SEEN_BYTES  (SEEN_BITS / 8)

static QueueHandle_t s_q;
static uint8_t       s_seen[SEEN_BYTES];
static volatile uint32_t s_unique;
static uint8_t       s_channel = 1;

static uint32_t mac_hash(const uint8_t mac[6])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    return h & (SEEN_BITS - 1);
}

static bool seen_test_and_set(const uint8_t mac[6])
{
    uint32_t b = mac_hash(mac);
    uint8_t  m = 1u << (b & 7);
    uint8_t *p = &s_seen[b >> 3];
    if (*p & m) return false;
    *p |= m;
    return true;
}

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint8_t subtype = (p[0] >> 4) & 0x0F;
    dp_obs_t o = { .rssi = pkt->rx_ctrl.rssi, .channel = pkt->rx_ctrl.channel };

    if (subtype == 0x08 || subtype == 0x05) {
        o.kind = DP_OBS_WIFI_AP;
        memcpy(o.mac, p + 16, 6);
        int tags = 24 + 12;
        if (len >= tags + 2 && p[tags] == 0) {
            int sl = p[tags + 1];
            if (sl > (int)sizeof(o.ssid)) sl = sizeof(o.ssid);
            if (tags + 2 + sl <= len) { memcpy(o.ssid, p + tags + 2, sl); o.ssid_len = sl; }
        }
    } else if (subtype == 0x04) {
        o.kind = DP_OBS_WIFI_STA;
        memcpy(o.mac, p + 10, 6);
    } else {
        return;
    }

    if (s_track) live_update(o.mac, o.rssi);

    if (!seen_test_and_set(o.mac)) return;
    s_unique++;
    BaseType_t hp = pdFALSE;
    xQueueSendFromISR(s_q, &o, &hp);
    if (hp) portYIELD_FROM_ISR();
}

void dp_sniffer_init(void)
{
    if (!s_q) s_q = xQueueCreate(OBS_QUEUE_DEPTH, sizeof(dp_obs_t));
    dp_sniffer_reset_seen();
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
}

void dp_sniffer_start(void)
{
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous(true);
    ESP_LOGI(TAG, "sniffing ch %u", s_channel);
}

void dp_sniffer_stop(void)
{
    esp_wifi_set_promiscuous(false);
}

void dp_sniffer_set_channel(uint8_t ch)
{
    s_channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

bool dp_sniffer_next(dp_obs_t *out, uint32_t timeout_ms)
{
    if (!s_q) return false;
    return xQueueReceive(s_q, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void dp_sniffer_reset_seen(void)
{
    memset(s_seen, 0, sizeof(s_seen));
    s_unique = 0;
    if (s_q) xQueueReset(s_q);
    portENTER_CRITICAL(&s_live_mux);
    memset(s_live, 0, sizeof(s_live));
    portEXIT_CRITICAL(&s_live_mux);
}

uint32_t dp_sniffer_unique_count(void) { return s_unique; }

void dp_sniffer_set_tracking(bool on) { s_track = on; }

bool dp_sniffer_rssi_for(const uint8_t mac[6], int8_t *rssi, int64_t *last_us)
{
    bool found = false;
    portENTER_CRITICAL(&s_live_mux);
    for (int i = 0; i < LIVE_MAX; i++) {
        if (s_live[i].used && memcmp(s_live[i].mac, mac, 6) == 0) {
            if (rssi)    *rssi = s_live[i].rssi;
            if (last_us) *last_us = s_live[i].last_us;
            found = true;
            break;
        }
    }
    portEXIT_CRITICAL(&s_live_mux);
    return found;
}
