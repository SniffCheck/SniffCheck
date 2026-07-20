#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "dp_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t dp_ble_init(void);

void dp_ble_start(void);
void dp_ble_stop(void);

bool dp_ble_next(dp_obs_t *out, uint32_t timeout_ms);

void dp_ble_reset_seen(void);

uint32_t dp_ble_unique_count(void);

bool dp_ble_rssi_for(const uint8_t mac[6], int8_t *rssi, int64_t *last_us);

int dp_ble_live_snapshot(dp_obs_t *out, int max, uint32_t max_age_ms);

#ifdef __cplusplus
}
#endif
