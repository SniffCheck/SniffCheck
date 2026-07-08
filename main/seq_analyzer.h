#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint16_t total_probe_reqs;
    uint16_t distinct_macs;
    uint16_t linked_pairs;
    uint16_t apparent_devices;
    uint16_t chipset_seq12;
    uint16_t chipset_seq11;
    uint16_t entries_dropped;
} seq_analyzer_aggregate_t;

typedef struct {
    uint8_t  mac[6];
    uint16_t first_seq;
    uint16_t last_seq;
    uint16_t max_seq;
    uint16_t hit_count;
    uint16_t first_seen_scan;
    uint16_t last_seen_scan;
    bool     linked_into;
    bool     used;
} seq_analyzer_entry_t;

void seq_analyzer_init(void);

void seq_analyzer_set_retention_mode(bool retain_detail);

void seq_analyzer_begin_scan(void);

void seq_analyzer_observe_probe_req(const uint8_t mac[6], uint16_t seq_num);

void seq_analyzer_finalize(void);

const seq_analyzer_aggregate_t *seq_analyzer_get(void);

uint16_t seq_analyzer_entry_count(void);
const seq_analyzer_entry_t *seq_analyzer_entry_at(uint16_t idx);
