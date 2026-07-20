#include "dp_ble.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"

void ble_store_config_init(void);

static const char *TAG = "dp_ble";

#define OBS_QUEUE_DEPTH 48
#define SEEN_BITS   4096
#define SEEN_BYTES  (SEEN_BITS / 8)
#define LIVE_MAX    48

static QueueHandle_t     s_q;
static SemaphoreHandle_t s_sync;
static uint8_t           s_seen[SEEN_BYTES];
static volatile uint32_t s_unique;
static volatile bool     s_scanning;
static uint8_t           s_own_addr_type;

typedef struct { uint8_t mac[6]; int8_t rssi; int64_t last_us; bool used; } live_t;
static live_t s_live[LIVE_MAX];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

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
    *p |= m; return true;
}

static void live_update(const uint8_t mac[6], int8_t rssi)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_mux);
    int freeslot = -1, oldest = 0; int64_t oldest_us = INT64_MAX;
    for (int i = 0; i < LIVE_MAX; i++) {
        if (!s_live[i].used) { if (freeslot < 0) freeslot = i; continue; }
        if (memcmp(s_live[i].mac, mac, 6) == 0) {
            s_live[i].rssi = rssi; s_live[i].last_us = now;
            portEXIT_CRITICAL(&s_mux); return;
        }
        if (s_live[i].last_us < oldest_us) { oldest_us = s_live[i].last_us; oldest = i; }
    }
    int slot = freeslot >= 0 ? freeslot : oldest;
    memcpy(s_live[slot].mac, mac, 6);
    s_live[slot].rssi = rssi; s_live[slot].last_us = now; s_live[slot].used = true;
    portEXIT_CRITICAL(&s_mux);
}

static void addr_be(uint8_t out[6], const uint8_t le[6])
{
    for (int i = 0; i < 6; i++) out[i] = le[5 - i];
}

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type != BLE_GAP_EVENT_DISC) return 0;
    const struct ble_gap_disc_desc *d = &event->disc;
    uint8_t be[6];
    addr_be(be, d->addr.val);

    live_update(be, d->rssi);
    if (!seen_test_and_set(be)) return 0;
    s_unique++;

    dp_obs_t o = { .rssi = d->rssi, .channel = 0, .kind = DP_OBS_BLE };
    memcpy(o.mac, be, 6);
    if (s_q) xQueueSend(s_q, &o, 0);
    return 0;
}

static void start_disc(void)
{
    struct ble_gap_disc_params p = {
        .itvl = 0, .window = 0, .filter_policy = 0,
        .limited = 0, .passive = 1,
        .filter_duplicates = 0,
    };
    int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &p, gap_event_cb, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY)
        ESP_LOGW(TAG, "ble_gap_disc rc=%d", rc);
}

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    ble_hs_id_infer_auto(0, &s_own_addr_type);
    xSemaphoreGive(s_sync);
}
static void on_reset(int reason) { ESP_LOGW(TAG, "BLE reset; reason=%d", reason); }

static void host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t dp_ble_init(void)
{
    if (!s_q)    s_q = xQueueCreate(OBS_QUEUE_DEPTH, sizeof(dp_obs_t));
    if (!s_sync) s_sync = xSemaphoreCreateBinary();
    if (!s_q || !s_sync) return ESP_ERR_NO_MEM;

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) { ESP_LOGE(TAG, "nimble_port_init: %s", esp_err_to_name(err)); return err; }

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    ble_store_config_init();
    nimble_port_freertos_init(host_task);

    if (xSemaphoreTake(s_sync, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "NimBLE sync timeout");
        return ESP_ERR_TIMEOUT;
    }
    ESP_LOGI(TAG, "BLE observer ready");
    return ESP_OK;
}

void dp_ble_start(void)
{
    if (s_scanning) return;
    s_scanning = true;
    start_disc();
    ESP_LOGI(TAG, "BLE passive scan started");
}

void dp_ble_stop(void)
{
    if (!s_scanning) return;
    s_scanning = false;
    ble_gap_disc_cancel();
}

bool dp_ble_next(dp_obs_t *out, uint32_t timeout_ms)
{
    if (!s_q) return false;
    return xQueueReceive(s_q, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void dp_ble_reset_seen(void)
{
    memset(s_seen, 0, sizeof(s_seen));
    s_unique = 0;
    if (s_q) xQueueReset(s_q);
    portENTER_CRITICAL(&s_mux);
    memset(s_live, 0, sizeof(s_live));
    portEXIT_CRITICAL(&s_mux);
}

uint32_t dp_ble_unique_count(void) { return s_unique; }

bool dp_ble_rssi_for(const uint8_t mac[6], int8_t *rssi, int64_t *last_us)
{
    bool found = false;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < LIVE_MAX; i++)
        if (s_live[i].used && memcmp(s_live[i].mac, mac, 6) == 0) {
            if (rssi) *rssi = s_live[i].rssi;
            if (last_us) *last_us = s_live[i].last_us;
            found = true; break;
        }
    portEXIT_CRITICAL(&s_mux);
    return found;
}

int dp_ble_live_snapshot(dp_obs_t *out, int max, uint32_t max_age_ms)
{
    int64_t now = esp_timer_get_time();
    int n = 0;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < LIVE_MAX && n < max; i++) {
        if (!s_live[i].used) continue;
        if (now - s_live[i].last_us > (int64_t)max_age_ms * 1000) continue;
        memset(&out[n], 0, sizeof(out[n]));
        memcpy(out[n].mac, s_live[i].mac, 6);
        out[n].rssi = s_live[i].rssi;
        out[n].kind = DP_OBS_BLE;
        n++;
    }
    portEXIT_CRITICAL(&s_mux);
    return n;
}
