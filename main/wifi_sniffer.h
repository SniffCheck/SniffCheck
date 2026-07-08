#pragma once

#include "esp_err.h"
#include "wifi_scanner.h"
#include "drone_rid.h"
#include <stdint.h>
#include <stdbool.h>

#define SNIFF_MAX_APS  128 

typedef struct {
    uint8_t  bssid[6];
    bool     valid;
    uint16_t beacon_interval;
    bool     beacon_seen;
    bool     privacy;
    int8_t   rssi;
    uint8_t  channel;
    bool     has_rsn;
    bool     rsn_pmf_required;
    bool     rsn_pmf_capable;
    bool     has_wps;
    bool     rsn_malformed;
    uint8_t  deauth_count;
    uint32_t beacon_count;
    char     ssid[33];
    char     probe_resp_ssids[4][33];
    uint8_t  probe_resp_count;
    bool     karma_suspect;
    uint8_t  vendor_ie_ouis[4][3];
    uint8_t  vendor_ie_count;
    uint8_t  lldp_count;
    uint8_t  cdp_count;
    uint8_t  dhcp_count;

    char     cdp_device_id[33];
    char     lldp_system_name[33];
    char     dhcp_vendor_class[33];
    uint8_t  dhcp_opt55[16];
    uint8_t  dhcp_opt55_len;
    uint16_t cdp_flags;
    uint16_t lldp_flags;
    uint16_t dhcp_flags;
    uint8_t  cdp_class;
    uint8_t  lldp_class;
    uint8_t  dhcp_class;
    const char *cdp_org_name;
    const char *lldp_org_name;

    char     wps_manufacturer[33];
    char     wps_model_name[33];
    char     country_code[3];
    uint32_t ie_pattern_hash;
    uint8_t  rsn_group_oui[3];
    uint8_t  rsn_group_suite;

    bool        has_rid;
    drone_rid_t drone;
} sniffer_rec_t;

typedef struct {
    uint32_t rts;
    uint32_t cts;
    uint32_t ack;
    uint32_t ba;
    uint32_t bar;
    uint32_t pspoll;
    uint32_t other;
    uint32_t total;
} sniffer_ctrl_stats_t;

esp_err_t wifi_sniffer_run(const scan_results_t *results, uint32_t dwell_ms, bool capture_ctrl);

const sniffer_ctrl_stats_t *wifi_sniffer_ctrl_stats(void);

esp_err_t wifi_sniffer_sta_window(uint8_t channel, uint32_t ms);

const sniffer_rec_t *wifi_sniffer_get(const uint8_t bssid[6]);

uint16_t wifi_sniffer_bssid_count(void);

const sniffer_rec_t *wifi_sniffer_at(uint16_t idx);
