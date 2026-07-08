

#include "probe_req_log.h"
#include "esp_attr.h"
#include <ctype.h>
#include <string.h>

#define SSID_DETAIL_CAP    64

#define SSID_BEACON_CAP    32

static probe_req_log_aggregate_t s_agg;

static EXT_RAM_BSS_ATTR probe_req_log_entry_t s_detail[SSID_DETAIL_CAP];
static uint16_t                 s_detail_count;
static uint16_t                 s_scan_index;
static bool                     s_retain_detail;

static EXT_RAM_BSS_ATTR char    s_beacon_ssids[SSID_BEACON_CAP][33];
static uint8_t  s_beacon_count;

static inline void inc_capped(uint16_t *c);

typedef struct {
    const char     *token;
    ssid_category_t cat;
} pattern_t;

static const pattern_t s_patterns[] = {

    {"iphone",        SSID_CAT_PII},
    {"ipad",          SSID_CAT_PII},
    {"macbook",       SSID_CAT_PII},
    {"galaxy",        SSID_CAT_PII},
    {"-pixel",        SSID_CAT_PII},
    {"_pixel",        SSID_CAT_PII},
    {"-laptop",       SSID_CAT_PII},
    {"_laptop",       SSID_CAT_PII},
    {"-phone",        SSID_CAT_PII},
    {"_phone",        SSID_CAT_PII},
    {"-pc",           SSID_CAT_PII},
    {"_pc",           SSID_CAT_PII},
    {"'s ",           SSID_CAT_PII},
    {"'s_",           SSID_CAT_PII},
    {"-fitbit",       SSID_CAT_PII},

    {"-corp",         SSID_CAT_CORPORATE},
    {"_corp",         SSID_CAT_CORPORATE},
    {"corp-",         SSID_CAT_CORPORATE},
    {"-internal",     SSID_CAT_CORPORATE},
    {"_internal",     SSID_CAT_CORPORATE},
    {"office-",       SSID_CAT_CORPORATE},
    {"google-",       SSID_CAT_CORPORATE},
    {"-mfa",          SSID_CAT_CORPORATE},
    {"-prod",         SSID_CAT_CORPORATE},

    {"hilton",        SSID_CAT_HOTEL},
    {"marriott",      SSID_CAT_HOTEL},
    {"hyatt",         SSID_CAT_HOTEL},
    {"westin",        SSID_CAT_HOTEL},
    {"holiday inn",   SSID_CAT_HOTEL},
    {"holidayinn",    SSID_CAT_HOTEL},
    {"hampton",       SSID_CAT_HOTEL},
    {"sheraton",      SSID_CAT_HOTEL},
    {"ihg",           SSID_CAT_HOTEL},
    {"radisson",      SSID_CAT_HOTEL},
    {"hotel-",        SSID_CAT_HOTEL},
    {"hotel_",        SSID_CAT_HOTEL},
    {"_hotel",        SSID_CAT_HOTEL},

    {"airport",       SSID_CAT_AIRPORT},
    {"_aero",         SSID_CAT_AIRPORT},
    {"boingo",        SSID_CAT_AIRPORT},
    {"_lax",          SSID_CAT_AIRPORT},
    {"_jfk",          SSID_CAT_AIRPORT},
    {"_sfo",          SSID_CAT_AIRPORT},

    {"xfinity",       SSID_CAT_ISP},
    {"attwifi",       SSID_CAT_ISP},
    {"eduroam",       SSID_CAT_ISP},
    {"spectrum",      SSID_CAT_ISP},
    {"comcast",       SSID_CAT_ISP},
    {"verizon",       SSID_CAT_ISP},
    {"cox-wifi",      SSID_CAT_ISP},
    {"optimum-",      SSID_CAT_ISP},

    {"guest",         SSID_CAT_GENERIC},
    {"free wifi",     SSID_CAT_GENERIC},
    {"free_wifi",     SSID_CAT_GENERIC},
    {"public",        SSID_CAT_GENERIC},
    {"visitor",       SSID_CAT_GENERIC},
    {"hotspot",       SSID_CAT_GENERIC},
    {"starbucks",     SSID_CAT_GENERIC},
    {"mcdonalds",     SSID_CAT_GENERIC},
    {"target_wifi",   SSID_CAT_GENERIC},
    {"_open",         SSID_CAT_GENERIC},
};
#define N_PATTERNS (sizeof(s_patterns) / sizeof(s_patterns[0]))

static bool ci_contains(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0]) return false;
    size_t nlen = strlen(needle);
    for (const char *h = hay; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] &&
               (char)tolower((unsigned char)h[i]) ==
               (char)tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

void probe_req_log_init(void)
{
    memset(&s_agg, 0, sizeof(s_agg));
    memset(s_detail, 0, sizeof(s_detail));
    memset(s_beacon_ssids, 0, sizeof(s_beacon_ssids));
    s_detail_count   = 0;
    s_scan_index     = 0;
    s_retain_detail  = false;
    s_beacon_count   = 0;
}

void probe_req_log_set_retention_mode(bool retain_detail)
{
    s_retain_detail = retain_detail;
}

void probe_req_log_begin_scan(void)
{
    s_scan_index++;

    s_beacon_count = 0;
}

void probe_req_log_add_beacon_ssid(const char *ssid)
{
    if (!ssid || !ssid[0]) return;
    if (s_beacon_count >= SSID_BEACON_CAP) return;
    for (uint8_t i = 0; i < s_beacon_count; i++) {
        if (strncmp(s_beacon_ssids[i], ssid, sizeof(s_beacon_ssids[0])) == 0) {
            return;
        }
    }
    strncpy(s_beacon_ssids[s_beacon_count], ssid,
            sizeof(s_beacon_ssids[0]) - 1);
    s_beacon_ssids[s_beacon_count][sizeof(s_beacon_ssids[0]) - 1] = '\0';
    s_beacon_count++;
}

static bool ssid_in_beacon_set(const char *ssid)
{
    if (!ssid || !ssid[0]) return false;
    for (uint8_t i = 0; i < s_beacon_count; i++) {
        if (strncmp(s_beacon_ssids[i], ssid, sizeof(s_beacon_ssids[0])) == 0) {
            return true;
        }
    }
    return false;
}

void probe_req_log_finalize(void)
{
    s_agg.local_visible_probes = 0;
    s_agg.remote_saved_probes  = 0;
    if (!s_retain_detail) return;

    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (s_detail[i].category == SSID_CAT_HIDDEN || !s_detail[i].ssid[0]) {
            s_detail[i].local_visible = false;
            continue;
        }
        bool local = ssid_in_beacon_set(s_detail[i].ssid);
        s_detail[i].local_visible = local;
        if (local) inc_capped(&s_agg.local_visible_probes);
        else       inc_capped(&s_agg.remote_saved_probes);
    }
}

static inline void inc_capped(uint16_t *c)
{
    if (c && *c < UINT16_MAX) (*c)++;
}

static probe_req_log_entry_t *find_or_evict(const char *ssid,
                                           const uint8_t mac[6])
{
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (strncmp(s_detail[i].ssid, ssid, sizeof(s_detail[i].ssid)) == 0 &&
            memcmp(s_detail[i].src_mac, mac, 6) == 0) {
            return &s_detail[i];
        }
    }
    if (s_detail_count < SSID_DETAIL_CAP) {
        return &s_detail[s_detail_count++];
    }

    uint16_t victim = 0;
    uint16_t oldest = s_detail[0].last_seen_scan;
    for (uint16_t i = 1; i < SSID_DETAIL_CAP; i++) {
        if (s_detail[i].last_seen_scan < oldest) {
            oldest = s_detail[i].last_seen_scan;
            victim = i;
        }
    }
    inc_capped(&s_agg.detail_dropped);
    return &s_detail[victim];
}

void probe_req_log_observe(const char *ssid, const uint8_t src_mac[6])
{
    inc_capped(&s_agg.total_probe_reqs);

    ssid_category_t cat;
    bool hidden = (!ssid || !ssid[0]);

    if (hidden) {
        cat = SSID_CAT_HIDDEN;
        inc_capped(&s_agg.counts[SSID_CAT_HIDDEN]);
    } else {
        inc_capped(&s_agg.directed_probe_reqs);
        cat = SSID_CAT_OTHER;
        for (size_t i = 0; i < N_PATTERNS; i++) {
            if (ci_contains(ssid, s_patterns[i].token)) {
                cat = s_patterns[i].cat;
                break;
            }
        }
        inc_capped(&s_agg.counts[cat]);
    }

    if (!s_retain_detail) return;
    if (!src_mac) return;

    const char *ssid_key = hidden ? "" : ssid;

    probe_req_log_entry_t *e = find_or_evict(ssid_key, src_mac);
    if (!e) return;

    if (!e->used || e->hit_count == 0) {
        memset(e, 0, sizeof(*e));
        e->used = true;
        strncpy(e->ssid, ssid_key, sizeof(e->ssid) - 1);
        e->ssid[sizeof(e->ssid) - 1] = '\0';
        memcpy(e->src_mac, src_mac, 6);
        e->category        = cat;
        e->first_seen_scan = s_scan_index;
    }
    e->last_seen_scan = s_scan_index;
    inc_capped(&e->hit_count);

    s_agg.detail_entries = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (s_detail[i].used) s_agg.detail_entries++;
    }
}

const probe_req_log_aggregate_t *probe_req_log_get(void)
{
    return &s_agg;
}

uint16_t probe_req_log_entry_count(void)
{
    return s_agg.detail_entries;
}

const probe_req_log_entry_t *probe_req_log_entry_at(uint16_t idx)
{
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_detail_count; i++) {
        if (!s_detail[i].used) continue;
        if (seen == idx) return &s_detail[i];
        seen++;
    }
    return NULL;
}

const char *ssid_category_label(ssid_category_t cat)
{
    switch (cat) {
        case SSID_CAT_PII:       return "PII";
        case SSID_CAT_CORPORATE: return "Corporate";
        case SSID_CAT_HOTEL:     return "Hotel";
        case SSID_CAT_AIRPORT:   return "Airport";
        case SSID_CAT_ISP:       return "ISP";
        case SSID_CAT_GENERIC:   return "OpenChain";
        case SSID_CAT_HIDDEN:    return "Hidden";
        case SSID_CAT_OTHER:     return "Other";
        default:                 return "?";
    }
}
