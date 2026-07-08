#include "wifi_scanner.h"
#include "esp_wifi.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "sc_scan";

#define WIFI_ADV_ACTIVE_DWELL_MS   180u
#define WIFI_ADV_PASSIVE_DWELL_MS  250u

#define WIFI_WARDRIVE_DWELL_MS     110u
#define WIFI_DEEP_2G_DWELL_MS      300u

esp_err_t wifi_scanner_init(void)
{
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "wifi init");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "wifi sta mode");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start");

    wifi_country_t country = {
        .cc = "US", .schan = 1, .nchan = 11,
        .policy = WIFI_COUNTRY_POLICY_MANUAL,
    };
    esp_err_t cerr = esp_wifi_set_country(&country);
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG, "set country (DFS) failed: %s", esp_err_to_name(cerr));
    }

#if CONFIG_SOC_WIFI_SUPPORT_5G

    wifi_band_mode_t band_mode = WIFI_BAND_MODE_2G_ONLY;
    ESP_RETURN_ON_ERROR(esp_wifi_get_band_mode(&band_mode), TAG, "get band mode");
    if (band_mode != WIFI_BAND_MODE_AUTO) {
        ESP_RETURN_ON_ERROR(esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO), TAG, "set band auto");
        ESP_RETURN_ON_ERROR(esp_wifi_get_band_mode(&band_mode), TAG, "verify band mode");
    }
    ESP_LOGI(TAG, "band mode: %u (1=2G,2=5G,3=auto)", (unsigned)band_mode);
#endif

    ESP_LOGI(TAG, "Wi-Fi scanner ready");
    return ESP_OK;
}

static esp_err_t prepare_scan(bool two_g_only)
{
    wifi_mode_t mode;
    ESP_RETURN_ON_ERROR(esp_wifi_get_mode(&mode), TAG, "get mode");
    if (mode != WIFI_MODE_STA) {
        ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "set sta mode");
    }
#if CONFIG_SOC_WIFI_SUPPORT_5G
    wifi_band_mode_t want = two_g_only ? WIFI_BAND_MODE_2G_ONLY : WIFI_BAND_MODE_AUTO;
    wifi_band_mode_t band_mode = WIFI_BAND_MODE_2G_ONLY;
    ESP_RETURN_ON_ERROR(esp_wifi_get_band_mode(&band_mode), TAG, "get band mode");
    if (band_mode != want) {
        ESP_RETURN_ON_ERROR(esp_wifi_set_band_mode(want), TAG, "set band mode");
    }
#else
    (void)two_g_only;
#endif
    return ESP_OK;
}

static void merge_record(scan_results_t *out, const wifi_ap_record_t *r)
{
    for (uint16_t i = 0; i < out->count; i++) {
        if (memcmp(out->entries[i].bssid, r->bssid, 6) == 0) {
            if (r->rssi > out->entries[i].rssi) out->entries[i].rssi = r->rssi;
            if (!out->entries[i].ssid[0] && r->ssid[0])
                strlcpy(out->entries[i].ssid, (const char *)r->ssid,
                        sizeof(out->entries[i].ssid));
            return;
        }
    }
    if (out->count >= WIFI_SCAN_MAX_APS) return;
    ap_record_t *e = &out->entries[out->count++];
    strlcpy(e->ssid, (const char *)r->ssid, sizeof(e->ssid));
    memcpy(e->bssid, r->bssid, 6);
    e->rssi    = r->rssi;
    e->channel = r->primary;
    e->band_5g = (r->primary >= 36);
    e->auth    = r->authmode;
}

static esp_err_t scan_sweep(scan_results_t *out, const wifi_scan_opts_t *opts)
{
    ESP_RETURN_ON_ERROR(prepare_scan(opts && opts->band_2g_only), TAG, "prepare");

    wifi_scan_config_t  cfg   = {0};
    wifi_scan_config_t *cfgp  = NULL;
    if (opts) {
        cfg.show_hidden = opts->show_hidden;
        if (opts->passive) {
            cfg.scan_type = WIFI_SCAN_TYPE_PASSIVE;
            if (opts->dwell_ms) cfg.scan_time.passive = opts->dwell_ms;
        } else {
            cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
            if (opts->dwell_ms) {

                cfg.scan_time.active.min = opts->dwell_ms;
                cfg.scan_time.active.max = opts->dwell_ms;
            }
        }
        cfgp = &cfg;
    }
    ESP_RETURN_ON_ERROR(esp_wifi_scan_start(cfgp, true), TAG, "scan start");

    uint16_t ap_num = 0;
    ESP_RETURN_ON_ERROR(esp_wifi_scan_get_ap_num(&ap_num), TAG, "get ap num");
    uint16_t num = (ap_num < WIFI_SCAN_MAX_APS) ? ap_num : WIFI_SCAN_MAX_APS;

    static wifi_ap_record_t raw[WIFI_SCAN_MAX_APS];
    memset(raw, 0, sizeof(raw));
    ESP_RETURN_ON_ERROR(esp_wifi_scan_get_ap_records(&num, raw), TAG, "get records");
    esp_wifi_clear_ap_list();

    for (uint16_t i = 0; i < num; i++) merge_record(out, &raw[i]);
    return ESP_OK;
}

static void log_results(const scan_results_t *out)
{
    for (uint16_t i = 0; i < out->count; i++) {
        const ap_record_t *e = &out->entries[i];
        ESP_LOGI(TAG, "AP[%u] ssid=\"%s\" bssid=%02X:%02X:%02X:%02X:%02X:%02X rssi=%d ch=%u band=%s auth=%d",
                 (unsigned)i, e->ssid[0] ? e->ssid : "<hidden>",
                 e->bssid[0], e->bssid[1], e->bssid[2],
                 e->bssid[3], e->bssid[4], e->bssid[5],
                 (int)e->rssi, (unsigned)e->channel,
                 e->band_5g ? "5G" : "2G", (int)e->auth);
    }
}

#define WIFI_LITE_DWELL_MS  150u

esp_err_t wifi_scan_run(scan_results_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    const wifi_scan_opts_t lite_opts = {
        .show_hidden = true, .passive = false,
        .dwell_ms = WIFI_LITE_DWELL_MS, .band_2g_only = false,
    };
    ESP_RETURN_ON_ERROR(scan_sweep(out, &lite_opts), TAG, "sweep");
    log_results(out);
    ESP_LOGI(TAG, "scan done: %u APs (1 sweep)", (unsigned)out->count);
    return ESP_OK;
}

esp_err_t wifi_scan_run_broad(scan_results_t *out, uint8_t active_sweeps, uint32_t max_ms)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    if (active_sweeps == 0) active_sweeps = 1;
    memset(out, 0, sizeof(*out));

    TickType_t t0 = xTaskGetTickCount();

    const wifi_scan_opts_t wardrive_opts = {
        .show_hidden = true, .passive = false,
        .dwell_ms = WIFI_DEEP_2G_DWELL_MS, .band_2g_only = true,
    };
    esp_err_t derr = scan_sweep(out, &wardrive_opts);
    if (derr != ESP_OK) {
        ESP_LOGW(TAG, "2.4 GHz max-dwell pass failed (%s); continuing", esp_err_to_name(derr));
    }

    const wifi_scan_opts_t active_opts = {
        .show_hidden = true, .passive = false, .dwell_ms = WIFI_ADV_ACTIVE_DWELL_MS,
    };
    uint8_t s = 0;
    for (; s < active_sweeps; s++) {
        esp_err_t err = scan_sweep(out, &active_opts);
        if (err != ESP_OK) {
            if (s == 0) return err;
            ESP_LOGW(TAG, "active sweep %u failed (%s); using partial results",
                     (unsigned)s, esp_err_to_name(err));
            break;
        }
        if (out->count >= WIFI_SCAN_MAX_APS) { s++; break; }
        if (pdTICKS_TO_MS(xTaskGetTickCount() - t0) >= max_ms) { s++; break; }
    }

    bool did_passive = false;
    if (out->count < WIFI_SCAN_MAX_APS &&
        pdTICKS_TO_MS(xTaskGetTickCount() - t0) < max_ms) {
        const wifi_scan_opts_t passive_opts = {
            .show_hidden = true, .passive = true, .dwell_ms = WIFI_ADV_PASSIVE_DWELL_MS,
        };
        esp_err_t err = scan_sweep(out, &passive_opts);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "passive full-band sweep failed (%s); active results kept",
                     esp_err_to_name(err));
        } else {
            did_passive = true;
        }
    }

    log_results(out);
    ESP_LOGI(TAG, "broad scan done: %u APs (%u active sweeps + %s passive, %lu ms)",
             (unsigned)out->count, (unsigned)s, did_passive ? "1" : "0",
             (unsigned long)pdTICKS_TO_MS(xTaskGetTickCount() - t0));
    return ESP_OK;
}

esp_err_t wifi_scan_run_wardrive(scan_results_t *out, bool include_5g)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    const wifi_scan_opts_t opts = {
        .show_hidden  = true,
        .passive      = false,
        .dwell_ms     = WIFI_WARDRIVE_DWELL_MS,
        .band_2g_only = !include_5g,
    };
    esp_err_t err = scan_sweep(out, &opts);

    if (!include_5g) (void)prepare_scan(false);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "wardrive sweep failed (%s)", esp_err_to_name(err));
        return err;
    }
    log_results(out);
    ESP_LOGI(TAG, "wardrive scan done: %u APs (%s)",
             (unsigned)out->count, include_5g ? "2.4+5 GHz" : "2.4 GHz only");
    return ESP_OK;
}
