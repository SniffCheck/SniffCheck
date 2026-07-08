#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint16_t total_queries;
    uint16_t distinct_macs;
    uint16_t universal_macs;
    uint16_t laa_macs;
    uint16_t entries_dropped;
} anqp_analyzer_aggregate_t;

typedef struct {
    uint8_t  mac[6];
    uint16_t first_seen_scan;
    uint16_t last_seen_scan;
    uint16_t hit_count;
    bool     universal;
    bool     used;
} anqp_analyzer_entry_t;

void anqp_analyzer_init(void);

void anqp_analyzer_set_retention_mode(bool retain_detail);

void anqp_analyzer_begin_scan(void);

void anqp_analyzer_observe_query(const uint8_t mac[6]);

void anqp_analyzer_finalize(void);

const anqp_analyzer_aggregate_t *anqp_analyzer_get(void);

uint16_t anqp_analyzer_entry_count(void);
const anqp_analyzer_entry_t *anqp_analyzer_entry_at(uint16_t idx);
