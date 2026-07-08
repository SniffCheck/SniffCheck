#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint16_t total_probe_reqs;
    uint16_t distinct_macs;
    uint16_t distinct_hashes;
    uint32_t top_hash;
    uint16_t top_hash_macs;
    uint16_t recognized_macs;
    uint16_t mismatched_macs;
    uint16_t entries_dropped;
} ie_signature_aggregate_t;

typedef struct {
    uint8_t     mac[6];
    uint32_t    ie_hash;
    uint16_t    first_seen_scan;
    uint16_t    last_seen_scan;
    uint16_t    hit_count;
    const char *ie_vendor;
    const char *mac_vendor;
    uint8_t     ie_class;
    uint8_t     mac_class;
    bool        mismatch;
    bool        used;
} ie_signature_entry_t;

void ie_signature_init(void);

void ie_signature_set_retention_mode(bool retain_detail);

void ie_signature_begin_scan(void);

void ie_signature_observe_probe_req(const uint8_t mac[6], uint32_t ie_hash);

void ie_signature_finalize(void);

const ie_signature_aggregate_t *ie_signature_get(void);

uint16_t ie_signature_entry_count(void);
const ie_signature_entry_t *ie_signature_entry_at(uint16_t idx);
