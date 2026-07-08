#include "seq_analyzer.h"
#include "esp_attr.h"
#include <string.h>

#define SEQ_DETAIL_CAP      64
#define SEQ_LINK_WINDOW     32
#define SEQ_MASK         0x0FFF

static EXT_RAM_BSS_ATTR seq_analyzer_entry_t s_detail[SEQ_DETAIL_CAP];
static uint16_t                 s_detail_count;
static uint16_t                 s_scan_index;
static bool                     s_retain_detail;
static seq_analyzer_aggregate_t s_agg;

void seq_analyzer_init(void)
{
    memset(s_detail, 0, sizeof(s_detail));
    s_detail_count   = 0;
    s_scan_index     = 0;
    s_retain_detail  = false;
    memset(&s_agg, 0, sizeof(s_agg));
}

void seq_analyzer_set_retention_mode(bool retain_detail)
{
    s_retain_detail = retain_detail;
}

void seq_analyzer_begin_scan(void)
{
    s_scan_index++;

    for (uint16_t i = 0; i < s_detail_count; i++) {
        s_detail[i].linked_into = false;
    }
}

static inline void inc_capped(uint16_t *c)
{
    if (*c < UINT16_MAX) (*c)++;
}

static seq_analyzer_entry_t *find_or_evict(const uint8_t mac[6])
{
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used && memcmp(s_detail[i].mac, mac, 6) == 0) {
            return &s_detail[i];
        }
    }
    if (s_detail_count < SEQ_DETAIL_CAP) {
        return &s_detail[s_detail_count++];
    }
    uint16_t victim = 0;
    uint16_t oldest = s_detail[0].last_seen_scan;
    for (uint16_t i = 1; i < SEQ_DETAIL_CAP; i++) {
        if (s_detail[i].last_seen_scan < oldest) {
            oldest = s_detail[i].last_seen_scan;
            victim = i;
        }
    }
    inc_capped(&s_agg.entries_dropped);
    return &s_detail[victim];
}

void seq_analyzer_observe_probe_req(const uint8_t mac[6], uint16_t seq_num)
{
    if (!mac) return;
    inc_capped(&s_agg.total_probe_reqs);

    if (!s_retain_detail) return;

    seq_num &= SEQ_MASK;

    seq_analyzer_entry_t *e = find_or_evict(mac);
    if (!e) return;

    bool fresh = !e->used || e->hit_count == 0;
    if (fresh) {
        memset(e, 0, sizeof(*e));
        e->used            = true;
        memcpy(e->mac, mac, 6);
        e->first_seq       = seq_num;
        e->max_seq         = seq_num;
        e->first_seen_scan = s_scan_index;
    } else if (seq_num > e->max_seq) {
        e->max_seq = seq_num;
    }
    e->last_seq       = seq_num;
    e->last_seen_scan = s_scan_index;
    inc_capped(&e->hit_count);
}

static bool seq_continues(uint16_t a_last, uint16_t b_first)
{
    uint16_t delta = (uint16_t)((b_first - a_last) & SEQ_MASK);
    return delta >= 1 && delta <= SEQ_LINK_WINDOW;
}

static uint16_t abs_diff(uint16_t a, uint16_t b)
{
    return (a > b) ? (uint16_t)(a - b) : (uint16_t)(b - a);
}

void seq_analyzer_finalize(void)
{

    s_agg.distinct_macs     = 0;
    s_agg.linked_pairs      = 0;
    s_agg.chipset_seq11     = 0;
    s_agg.chipset_seq12     = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        s_agg.distinct_macs++;
        if (s_detail[i].max_seq > 2047) s_agg.chipset_seq12++;
        else                            s_agg.chipset_seq11++;
    }

    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        for (uint16_t j = 0; j < s_detail_count; j++) {
            if (i == j) continue;
            seq_analyzer_entry_t *b = &s_detail[j];
            if (!b->used || b->linked_into) continue;
            if (abs_diff(s_detail[i].last_seen_scan, b->first_seen_scan) > 1) continue;
            if (seq_continues(s_detail[i].last_seq, b->first_seq)) {
                b->linked_into = true;
                inc_capped(&s_agg.linked_pairs);
                break;
            }
        }
    }
    s_agg.apparent_devices =
        (s_agg.distinct_macs > s_agg.linked_pairs)
        ? (uint16_t)(s_agg.distinct_macs - s_agg.linked_pairs)
        : 0;

}

const seq_analyzer_aggregate_t *seq_analyzer_get(void)
{
    return &s_agg;
}

uint16_t seq_analyzer_entry_count(void)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used) n++;
    }
    return n;
}

const seq_analyzer_entry_t *seq_analyzer_entry_at(uint16_t idx)
{
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (seen == idx) return &s_detail[i];
        seen++;
    }
    return NULL;
}
