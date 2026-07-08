#include "ie_signature.h"
#include "eui_db.h"
#include "esp_attr.h"
#include <string.h>

#define IE_DETAIL_CAP   64

static EXT_RAM_BSS_ATTR ie_signature_entry_t s_detail[IE_DETAIL_CAP];
static uint16_t                 s_detail_count;
static uint16_t                 s_scan_index;
static bool                     s_retain_detail;
static ie_signature_aggregate_t s_agg;

void ie_signature_init(void)
{
    memset(s_detail, 0, sizeof(s_detail));
    s_detail_count  = 0;
    s_scan_index    = 0;
    s_retain_detail = false;
    memset(&s_agg, 0, sizeof(s_agg));
}

void ie_signature_set_retention_mode(bool retain_detail)
{
    s_retain_detail = retain_detail;
}

void ie_signature_begin_scan(void)
{
    s_scan_index++;
}

static inline void inc_capped(uint16_t *c)
{
    if (*c < UINT16_MAX) (*c)++;
}

static ie_signature_entry_t *find_or_evict(const uint8_t mac[6], uint32_t ie_hash)
{
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used
            && s_detail[i].ie_hash == ie_hash
            && memcmp(s_detail[i].mac, mac, 6) == 0) {
            return &s_detail[i];
        }
    }
    if (s_detail_count < IE_DETAIL_CAP) {
        return &s_detail[s_detail_count++];
    }
    uint16_t victim = 0;
    uint16_t oldest = s_detail[0].last_seen_scan;
    for (uint16_t i = 1; i < IE_DETAIL_CAP; i++) {
        if (s_detail[i].last_seen_scan < oldest) {
            oldest = s_detail[i].last_seen_scan;
            victim = i;
        }
    }
    inc_capped(&s_agg.entries_dropped);
    return &s_detail[victim];
}

void ie_signature_observe_probe_req(const uint8_t mac[6], uint32_t ie_hash)
{
    if (!mac) return;
    inc_capped(&s_agg.total_probe_reqs);

    if (!s_retain_detail) return;
    if (ie_hash == 0) return;

    ie_signature_entry_t *e = find_or_evict(mac, ie_hash);
    if (!e) return;

    bool fresh = !e->used
                 || memcmp(e->mac, mac, 6) != 0
                 || e->ie_hash != ie_hash;
    if (fresh) {
        memset(e, 0, sizeof(*e));
        e->used            = true;
        memcpy(e->mac, mac, 6);
        e->ie_hash         = ie_hash;
        e->first_seen_scan = s_scan_index;
    }
    e->last_seen_scan = s_scan_index;
    inc_capped(&e->hit_count);
}

void ie_signature_finalize(void)
{
    s_agg.distinct_macs    = 0;
    s_agg.distinct_hashes  = 0;
    s_agg.top_hash         = 0;
    s_agg.top_hash_macs    = 0;
    s_agg.recognized_macs  = 0;
    s_agg.mismatched_macs  = 0;

    for (uint16_t i = 0; i < s_detail_count; i++) {
        ie_signature_entry_t *e = &s_detail[i];
        if (!e->used) continue;

        uint16_t ie_f = 0;  uint8_t ie_c = EUI_CLASS_UNKNOWN;
        e->ie_vendor = eui_lookup_ie_signature(e->ie_hash, &ie_f, &ie_c);
        e->ie_class  = ie_c;

        uint16_t mac_f = 0; uint8_t mac_c = EUI_CLASS_UNKNOWN; uint8_t ml = 0;
        e->mac_vendor = eui_lookup_mac(e->mac, &mac_f, &mac_c, &ml);
        e->mac_class  = mac_c;

        e->mismatch = (e->ie_vendor && e->mac_vendor
                       && e->ie_class != EUI_CLASS_UNKNOWN
                       && e->mac_class != EUI_CLASS_UNKNOWN
                       && e->ie_class != e->mac_class);
    }

    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        bool dup = false;
        for (uint16_t j = 0; j < i; j++) {
            if (s_detail[j].used
                && memcmp(s_detail[j].mac, s_detail[i].mac, 6) == 0) {
                dup = true; break;
            }
        }
        if (dup) continue;
        inc_capped(&s_agg.distinct_macs);

        bool any_recognized = false;
        bool any_mismatch   = false;
        for (uint16_t j = 0; j < s_detail_count; j++) {
            if (!s_detail[j].used) continue;
            if (memcmp(s_detail[j].mac, s_detail[i].mac, 6) != 0) continue;
            if (s_detail[j].ie_vendor) any_recognized = true;
            if (s_detail[j].mismatch)  any_mismatch   = true;
        }
        if (any_recognized) inc_capped(&s_agg.recognized_macs);
        if (any_mismatch)   inc_capped(&s_agg.mismatched_macs);
    }

    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        uint32_t h = s_detail[i].ie_hash;
        bool seen_hash = false;
        for (uint16_t j = 0; j < i; j++) {
            if (s_detail[j].used && s_detail[j].ie_hash == h) {
                seen_hash = true; break;
            }
        }
        if (seen_hash) continue;
        inc_capped(&s_agg.distinct_hashes);

        uint16_t mac_count = 0;
        for (uint16_t j = 0; j < s_detail_count; j++) {
            if (!s_detail[j].used || s_detail[j].ie_hash != h) continue;
            bool mac_dup = false;
            for (uint16_t k = 0; k < j; k++) {
                if (s_detail[k].used
                    && s_detail[k].ie_hash == h
                    && memcmp(s_detail[k].mac, s_detail[j].mac, 6) == 0) {
                    mac_dup = true; break;
                }
            }
            if (!mac_dup) mac_count++;
        }
        if (mac_count > s_agg.top_hash_macs) {
            s_agg.top_hash      = h;
            s_agg.top_hash_macs = mac_count;
        }
    }
}

const ie_signature_aggregate_t *ie_signature_get(void)
{
    return &s_agg;
}

uint16_t ie_signature_entry_count(void)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used) n++;
    }
    return n;
}

const ie_signature_entry_t *ie_signature_entry_at(uint16_t idx)
{
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (seen == idx) return &s_detail[i];
        seen++;
    }
    return NULL;
}
