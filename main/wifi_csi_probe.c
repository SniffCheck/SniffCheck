#include "wifi_csi_probe.h"

#include "sdkconfig.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "sc_csi";

#if CONFIG_ESP_WIFI_CSI_ENABLED
static wifi_csi_result_t s_result = { .supported = true };
#else
static wifi_csi_result_t s_result = { .supported = false };
#endif

#if CONFIG_ESP_WIFI_CSI_ENABLED

static volatile uint32_t s_cb_count;
static volatile uint32_t s_len_min;
static volatile uint32_t s_len_max;
static volatile uint32_t s_len_last;
static volatile uint32_t s_fwi_count;
static volatile int32_t  s_rssi_last;
static volatile uint8_t  s_chan_last;

static void csi_cb(void *ctx, wifi_csi_info_t *info)
{
    (void)ctx;
    if (!info) return;
    s_cb_count++;
    uint32_t len = info->len;
    s_len_last = len;
    if (s_len_min == 0 || len < s_len_min) s_len_min = len;
    if (len > s_len_max) s_len_max = len;
    if (info->first_word_invalid) s_fwi_count++;
    s_rssi_last = info->rx_ctrl.rssi;
    s_chan_last = info->rx_ctrl.channel;

}

esp_err_t wifi_csi_probe_run(uint8_t channel, uint32_t window_ms)
{
    s_cb_count = 0;
    s_len_min = 0; s_len_max = 0; s_len_last = 0;
    s_fwi_count = 0; s_rssi_last = 0; s_chan_last = 0;

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    wifi_csi_config_t cfg;
    esp_err_t err = esp_wifi_get_csi_config(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "get_csi_config failed: %s", esp_err_to_name(err));
        esp_wifi_set_promiscuous(false);
        return err;
    }
    err = esp_wifi_set_csi_config(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_csi_config failed: %s", esp_err_to_name(err));
        esp_wifi_set_promiscuous(false);
        return err;
    }

    esp_wifi_set_csi_rx_cb(csi_cb, NULL);
    err = esp_wifi_set_csi(true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_csi(true) failed: %s", esp_err_to_name(err));
        esp_wifi_set_csi_rx_cb(NULL, NULL);
        esp_wifi_set_promiscuous(false);
        return err;
    }

    ESP_LOGI(TAG, "CSI spike: capturing %lu ms on ch %u ...",
             (unsigned long)window_ms, (unsigned)channel);
    vTaskDelay(pdMS_TO_TICKS(window_ms));

    esp_wifi_set_csi(false);
    esp_wifi_set_csi_rx_cb(NULL, NULL);
    esp_wifi_set_promiscuous(false);

    s_result = (wifi_csi_result_t){
        .supported = true, .ran = true,
        .channel = channel, .window_ms = window_ms,
        .cb_count = s_cb_count, .len_min = s_len_min, .len_max = s_len_max,
        .len_last = s_len_last, .fwi_count = s_fwi_count, .rssi_last = s_rssi_last,
    };

    ESP_LOGI(TAG,
             "CSI spike result: cb=%lu len[min=%lu max=%lu last=%lu] fwi=%lu "
             "rssi=%ld ch=%u -> %s",
             (unsigned long)s_cb_count, (unsigned long)s_len_min,
             (unsigned long)s_len_max, (unsigned long)s_len_last,
             (unsigned long)s_fwi_count, (long)s_rssi_last, (unsigned)s_chan_last,
             s_cb_count ? "GO: CSI callbacks firing" : "NO-GO: no CSI callbacks");
    return ESP_OK;
}

#else 

esp_err_t wifi_csi_probe_run(uint8_t channel, uint32_t window_ms)
{
    (void)channel; (void)window_ms;
    s_result = (wifi_csi_result_t){ .supported = false, .ran = false };
    ESP_LOGW(TAG,
             "CSI disabled. Enable CONFIG_ESP_WIFI_CSI_ENABLED in sdkconfig "
             "(Component config -> Wi-Fi -> WiFi CSI) and rebuild. If the option "
             "is absent for esp32c5, the SOC does not expose CSI -> 32d is NO-GO.");
    return ESP_ERR_NOT_SUPPORTED;
}

#endif 

const wifi_csi_result_t *wifi_csi_probe_last(void) { return &s_result; }
