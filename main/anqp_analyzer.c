#include "anqp_analyzer.h"
#include "esp_attr.h"
#include <string.h>

#define ANQP_DETAIL_CAP  64

static EXT_RAM_BSS_ATTR anqp_analyzer_entry_t s_detail[ANQP_DETAIL_CAP];
static uint16_t                  s_detail_count;
static uint16_t                  s_scan_index;
static bool                      s_retain_detail;
static anqp_analyzer_aggregate_t s_agg;

void anqp_analyzer_init(void)
{
    memset(s_detail, 0, sizeof(s_detail));
    s_detail_count  = 0;
    s_scan_index    = 0;
    s_retain_detail = false;
    memset(&s_agg, 0, sizeof(s_agg));
}

void anqp_analyzer_set_retention_mode(bool retain_detail)
{
    s_retain_detail = retain_detail;
}

void anqp_analyzer_begin_scan(void)
{
    s_scan_index++;
}

static inline void inc_capped(uint16_t *c)
{
    if (*c < UINT16_MAX) (*c)++;
}

static anqp_analyzer_entry_t *find_or_evict(const uint8_t mac[6])
{
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used && memcmp(s_detail[i].mac, mac, 6) == 0) {
            return &s_detail[i];
        }
    }
    if (s_detail_count < ANQP_DETAIL_CAP) {
        return &s_detail[s_detail_count++];
    }
    uint16_t victim = 0;
    uint16_t oldest = s_detail[0].last_seen_scan;
    for (uint16_t i = 1; i < ANQP_DETAIL_CAP; i++) {
        if (s_detail[i].last_seen_scan < oldest) {
            oldest = s_detail[i].last_seen_scan;
            victim = i;
        }
    }
    inc_capped(&s_agg.entries_dropped);
    return &s_detail[victim];
}

void anqp_analyzer_observe_query(const uint8_t mac[6])
{
    if (!mac) return;
    inc_capped(&s_agg.total_queries);

    if (!s_retain_detail) return;

    anqp_analyzer_entry_t *e = find_or_evict(mac);
    if (!e) return;

    bool fresh = !e->used || memcmp(e->mac, mac, 6) != 0;
    if (fresh) {
        memset(e, 0, sizeof(*e));
        e->used            = true;
        memcpy(e->mac, mac, 6);

        e->universal       = (mac[0] & 0x02) == 0;
        e->first_seen_scan = s_scan_index;
    }
    e->last_seen_scan = s_scan_index;
    inc_capped(&e->hit_count);
}

void anqp_analyzer_finalize(void)
{
    s_agg.distinct_macs   = 0;
    s_agg.universal_macs  = 0;
    s_agg.laa_macs        = 0;

    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        inc_capped(&s_agg.distinct_macs);
        if (s_detail[i].universal) inc_capped(&s_agg.universal_macs);
        else                       inc_capped(&s_agg.laa_macs);
    }
}

const anqp_analyzer_aggregate_t *anqp_analyzer_get(void)
{
    return &s_agg;
}

uint16_t anqp_analyzer_entry_count(void)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used) n++;
    }
    return n;
}

const anqp_analyzer_entry_t *anqp_analyzer_entry_at(uint16_t idx)
{
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (seen == idx) return &s_detail[i];
        seen++;
    }
    return NULL;
}
