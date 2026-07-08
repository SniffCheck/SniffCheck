#pragma once

#include "esp_wifi.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#define WIFI_SCAN_MAX_APS  128

typedef struct {
    char             ssid[33];
    uint8_t          bssid[6];
    int8_t           rssi;
    uint8_t          channel;
    bool             band_5g;
    wifi_auth_mode_t auth;
} ap_record_t;

typedef struct {
    ap_record_t entries[WIFI_SCAN_MAX_APS];
    uint16_t    count;
} scan_results_t;

typedef struct {
    bool     show_hidden;
    bool     passive;
    uint16_t dwell_ms;
    bool     band_2g_only;
} wifi_scan_opts_t;

esp_err_t wifi_scanner_init(void);

esp_err_t wifi_scan_run(scan_results_t *out);

esp_err_t wifi_scan_run_broad(scan_results_t *out, uint8_t active_sweeps, uint32_t max_ms);

esp_err_t wifi_scan_run_wardrive(scan_results_t *out, bool include_5g);
