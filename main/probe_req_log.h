#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    SSID_CAT_PII       = 0,
    SSID_CAT_CORPORATE = 1,
    SSID_CAT_HOTEL     = 2,
    SSID_CAT_AIRPORT   = 3,
    SSID_CAT_ISP       = 4,
    SSID_CAT_GENERIC   = 5,
    SSID_CAT_HIDDEN    = 6,
    SSID_CAT_OTHER     = 7,
    SSID_CAT_COUNT     = 8
} ssid_category_t;

typedef struct {
    uint16_t counts[SSID_CAT_COUNT];
    uint16_t total_probe_reqs;
    uint16_t directed_probe_reqs;
    uint16_t detail_entries;
    uint16_t detail_dropped;

    uint16_t local_visible_probes;
    uint16_t remote_saved_probes;
} probe_req_log_aggregate_t;

typedef struct {
    char            ssid[33];
    uint8_t         src_mac[6];
    ssid_category_t category;
    uint16_t        first_seen_scan;
    uint16_t        last_seen_scan;
    uint16_t        hit_count;

    bool            local_visible;
    bool            used;
} probe_req_log_entry_t;

void probe_req_log_init(void);

void probe_req_log_set_retention_mode(bool retain_detail);

void probe_req_log_begin_scan(void);

void probe_req_log_observe(const char *ssid, const uint8_t src_mac[6]);

void probe_req_log_add_beacon_ssid(const char *ssid);

void probe_req_log_finalize(void);

const probe_req_log_aggregate_t *probe_req_log_get(void);

uint16_t probe_req_log_entry_count(void);
const probe_req_log_entry_t *probe_req_log_entry_at(uint16_t idx);

const char *ssid_category_label(ssid_category_t cat);
