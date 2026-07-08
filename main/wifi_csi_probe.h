#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool     supported;
    bool     ran;
    uint8_t  channel;
    uint32_t window_ms;
    uint32_t cb_count;
    uint32_t len_min;
    uint32_t len_max;
    uint32_t len_last;
    uint32_t fwi_count;
    int32_t  rssi_last;
} wifi_csi_result_t;

esp_err_t wifi_csi_probe_run(uint8_t channel, uint32_t window_ms);

const wifi_csi_result_t *wifi_csi_probe_last(void);
