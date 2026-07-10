#include "download_mode.h"
#include "download_http.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "sc_dl";

#define CFG_NS          "uicfg"
#define PASS_LEN        8
#define DEFAULT_CH      6
#define MAX_CLIENTS     2

static const char PASS_ALPHABET[] =
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
    "23456789";
#define ALPHA_N (sizeof(PASS_ALPHABET) - 1)

typedef enum { DL_CMD_ENABLE = 0, DL_CMD_DISABLE, DL_CMD_EXTEND } dl_cmd_kind_t;
typedef struct {
    dl_cmd_kind_t        kind;
    capture_end_reason_t reason;
    uint32_t             extend_s;
} dl_cmd_t;

#define SESSION_CAP_S  (60u * 60u)

static SemaphoreHandle_t s_mutex;
static QueueHandle_t     s_queue;
static esp_timer_handle_t s_timeout_timer;
static esp_netif_t       *s_ap_netif;

static download_state_t s_state          = DL_PASSIVE_SCAN;
static char             s_ssid[16]        = {0};
static char             s_pass[PASS_LEN + 1] = {0};
static uint8_t          s_timeout_min     = 15;
static uint8_t          s_channel         = DEFAULT_CH;
static volatile uint8_t s_client_count    = 0;
static int64_t          s_deadline_us     = 0;

/* The AP passphrase is generated once per boot and reused for every AP
 * re-enable within that boot, so a client that reconnects after a scan uses
 * the same credentials. It lives only in RAM — it is never written to NVS, so
 * it does not persist across reboots (each power-cycle mints a fresh one). */
static bool s_pass_generated = false;

static void gen_passphrase(void)
{
    if (s_pass_generated) return;
    const uint32_t limit = 256u - (256u % ALPHA_N);
    for (int i = 0; i < PASS_LEN; i++) {
        uint8_t b;
        do { b = (uint8_t)(esp_random() & 0xFF); } while (b >= limit);
        s_pass[i] = PASS_ALPHABET[b % ALPHA_N];
    }
    s_pass[PASS_LEN] = '\0';
    s_pass_generated = true;
}

static void build_ssid(void)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_ssid, sizeof(s_ssid), "SniffCheck-%02X%02X", mac[4], mac[5]);
}

static void persist_timeout(void)
{
    nvs_handle_t h;
    if (nvs_open(CFG_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "dl_timeout", s_timeout_min);
        nvs_commit(h);
        nvs_close(h);
    }
}

static void load_timeout(void)
{
    nvs_handle_t h;
    if (nvs_open(CFG_NS, NVS_READONLY, &h) == ESP_OK) {
        uint8_t m = s_timeout_min;
        if (nvs_get_u8(h, "dl_timeout", &m) == ESP_OK &&
            (m == 15 || m == 30 || m == 60)) {
            s_timeout_min = m;
        }
        nvs_close(h);
    }
}

static void wifi_evt(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base != WIFI_EVENT) return;
    if (id == WIFI_EVENT_AP_STACONNECTED) {
        if (s_client_count < 0xFF) s_client_count++;
        ESP_LOGI(TAG, "client joined (%u)", (unsigned)s_client_count);
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        if (s_client_count > 0) s_client_count--;
        ESP_LOGI(TAG, "client left (%u)", (unsigned)s_client_count);
    }
}

static void timeout_cb(void *arg)
{
    ESP_LOGI(TAG, "timeout reached");
    download_mode_request_disable(CAP_END_TIMEOUT);
}

static void ap_start(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_state = DL_AP_STARTING;
    s_client_count = 0;
    build_ssid();
    gen_passphrase();
    uint8_t ch = (s_channel >= 1 && s_channel <= 13) ? s_channel : DEFAULT_CH;
    char ssid_cpy[16];   char pass_cpy[PASS_LEN + 1];
    strlcpy(ssid_cpy, s_ssid, sizeof(ssid_cpy));
    strlcpy(pass_cpy, s_pass, sizeof(pass_cpy));
    xSemaphoreGive(s_mutex);

    wifi_config_t cfg = {0};
    strlcpy((char *)cfg.ap.ssid, ssid_cpy, sizeof(cfg.ap.ssid));
    cfg.ap.ssid_len       = strlen(ssid_cpy);
    strlcpy((char *)cfg.ap.password, pass_cpy, sizeof(cfg.ap.password));
    cfg.ap.channel        = ch;
    cfg.ap.authmode       = WIFI_AUTH_WPA2_PSK;
    cfg.ap.max_connection = MAX_CLIENTS;
    cfg.ap.ssid_hidden    = 0;
    cfg.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_state = DL_AP_ACTIVE;
    s_deadline_us = esp_timer_get_time() + (int64_t)s_timeout_min * 60 * 1000000LL;
    xSemaphoreGive(s_mutex);

    esp_timer_stop(s_timeout_timer);
    esp_timer_start_once(s_timeout_timer, (uint64_t)s_timeout_min * 60 * 1000000ULL);

    download_http_start();

    ESP_LOGI(TAG, "AP up: %s ch=%u timeout=%umin", ssid_cpy, (unsigned)ch,
             (unsigned)s_timeout_min);
}

static void ap_stop(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_state = DL_AP_STOPPING;
    xSemaphoreGive(s_mutex);

    download_http_stop();

    esp_timer_stop(s_timeout_timer);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    /* Keep s_pass: the same per-boot passphrase is reused on the next AP
     * re-enable so a client can reconnect after a scan with unchanged
     * credentials. It is RAM-only and never persisted across reboots. */
    s_client_count = 0;
    s_deadline_us  = 0;
    s_state = DL_PASSIVE_SCAN;
    xSemaphoreGive(s_mutex);

    ESP_LOGI(TAG, "AP down — back to passive scan");
}

static void ap_extend(uint32_t add_s)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_state != DL_AP_ACTIVE || s_deadline_us == 0) {
        xSemaphoreGive(s_mutex);
        return;
    }
    int64_t now = esp_timer_get_time();
    int64_t rem = s_deadline_us - now;
    if (rem < 0) rem = 0;
    int64_t new_rem = rem + (int64_t)add_s * 1000000LL;
    const int64_t cap = (int64_t)SESSION_CAP_S * 1000000LL;
    if (new_rem > cap) new_rem = cap;
    s_deadline_us = now + new_rem;
    xSemaphoreGive(s_mutex);

    esp_timer_stop(s_timeout_timer);
    esp_timer_start_once(s_timeout_timer, (uint64_t)new_rem);
    ESP_LOGI(TAG, "session extended: %u s remaining",
             (unsigned)(new_rem / 1000000LL));
}

static void dl_task(void *arg)
{
    dl_cmd_t cmd;
    for (;;) {
        if (xQueueReceive(s_queue, &cmd, portMAX_DELAY) != pdTRUE) continue;
        download_state_t st = download_mode_get_state();
        if (cmd.kind == DL_CMD_ENABLE) {
            if (st == DL_PASSIVE_SCAN) ap_start();
        } else if (cmd.kind == DL_CMD_EXTEND) {
            ap_extend(cmd.extend_s);
        } else {
            if (st == DL_AP_ACTIVE || st == DL_AP_STARTING) ap_stop();
        }
    }
}

void download_mode_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    configASSERT(s_mutex);
    s_queue = xQueueCreate(4, sizeof(dl_cmd_t));
    configASSERT(s_queue);

    load_timeout();

    s_ap_netif = esp_netif_create_default_wifi_ap();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_evt, NULL, NULL));

    const esp_timer_create_args_t targs = {
        .callback = timeout_cb,
        .name     = "sc_dl_to",
    };
    ESP_ERROR_CHECK(esp_timer_create(&targs, &s_timeout_timer));

    xTaskCreate(dl_task, "sc_dl", 4096, NULL, 5, NULL);
}

void download_mode_request_enable(void)
{
    dl_cmd_t c = { .kind = DL_CMD_ENABLE, .reason = CAP_END_USER_DISABLE };
    xQueueSend(s_queue, &c, 0);
}

void download_mode_request_disable(capture_end_reason_t reason)
{
    dl_cmd_t c = { .kind = DL_CMD_DISABLE, .reason = reason };
    xQueueSend(s_queue, &c, 0);
}

uint32_t download_mode_extend_seconds(uint32_t seconds)
{
    uint32_t cur = download_mode_get_seconds_remaining();
    if (cur == 0) return 0;
    dl_cmd_t c = { .kind = DL_CMD_EXTEND, .extend_s = seconds };
    xQueueSend(s_queue, &c, 0);
    uint32_t pred = cur + seconds;
    return pred > SESSION_CAP_S ? SESSION_CAP_S : pred;
}

bool download_mode_is_active(void)
{
    return download_mode_get_state() != DL_PASSIVE_SCAN;
}

download_state_t download_mode_get_state(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    download_state_t st = s_state;
    xSemaphoreGive(s_mutex);
    return st;
}

const char *download_mode_get_ssid(void)       { return s_ssid; }
const char *download_mode_get_passphrase(void) { return s_pass; }
uint8_t     download_mode_get_client_count(void) { return s_client_count; }

uint32_t download_mode_get_seconds_remaining(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int64_t deadline = s_deadline_us;
    download_state_t st = s_state;
    xSemaphoreGive(s_mutex);
    if (st != DL_AP_ACTIVE || deadline == 0) return 0;
    int64_t rem = deadline - esp_timer_get_time();
    if (rem <= 0) return 0;
    return (uint32_t)(rem / 1000000LL);
}

void download_mode_set_timeout_minutes(uint8_t m)
{
    if (m != 15 && m != 30 && m != 60) return;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_timeout_min = m;
    xSemaphoreGive(s_mutex);
    persist_timeout();
}

uint8_t download_mode_get_timeout_minutes(void)
{
    return s_timeout_min;
}

void download_mode_set_channel(uint8_t ch)
{
    if (ch >= 1 && ch <= 13) s_channel = ch;
}
