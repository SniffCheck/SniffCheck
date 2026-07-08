#include "probe_frame_ring.h"
#include "esp_attr.h"
#include <string.h>

#define PROBE_FRAME_RING_CAP 128

static EXT_RAM_BSS_ATTR probe_frame_t s_ring[PROBE_FRAME_RING_CAP];
static uint16_t s_head;
static uint16_t s_count;
static uint16_t s_scan_idx;
static bool     s_retain;

void probe_frame_ring_init(void)
{
    memset(s_ring, 0, sizeof(s_ring));
    s_head     = 0;
    s_count    = 0;
    s_scan_idx = 0;
    s_retain   = false;
}

void probe_frame_ring_set_retention_mode(bool retain)
{
    s_retain = retain;
}

void probe_frame_ring_begin_scan(void)
{
    s_scan_idx++;
}

void probe_frame_ring_add(const probe_frame_t *f)
{
    if (!s_retain || !f) return;

    probe_frame_t *slot = &s_ring[s_head];
    *slot = *f;
    slot->ssid[sizeof(slot->ssid) - 1] = '\0';
    slot->scan_idx = s_scan_idx;
    slot->used     = true;

    s_head = (uint16_t)((s_head + 1) % PROBE_FRAME_RING_CAP);
    if (s_count < PROBE_FRAME_RING_CAP) s_count++;
}

static const probe_frame_t *phys_at(uint16_t logical)
{
    if (logical >= s_count) return NULL;
    uint16_t start = (uint16_t)((s_head + PROBE_FRAME_RING_CAP - s_count) % PROBE_FRAME_RING_CAP);
    uint16_t phys  = (uint16_t)((start + logical) % PROBE_FRAME_RING_CAP);
    return &s_ring[phys];
}

uint16_t probe_frame_ring_count(void)
{
    return s_count;
}

const probe_frame_t *probe_frame_ring_at(uint16_t idx)
{
    return phys_at(idx);
}

static bool match_mac(const probe_frame_t *e, const uint8_t mac[6], bool anqp_only)
{
    if (e->is_anqp != anqp_only) return false;
    return memcmp(e->src_mac, mac, 6) == 0;
}

uint16_t probe_frame_ring_count_for_mac(const uint8_t mac[6], bool anqp_only)
{
    if (!mac) return 0;
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const probe_frame_t *e = phys_at(i);
        if (e && match_mac(e, mac, anqp_only)) n++;
    }
    return n;
}

const probe_frame_t *probe_frame_ring_nth_for_mac(const uint8_t mac[6], bool anqp_only, uint16_t n)
{
    if (!mac) return NULL;
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const probe_frame_t *e = phys_at(i);
        if (e && match_mac(e, mac, anqp_only)) {
            if (seen == n) return e;
            seen++;
        }
    }
    return NULL;
}

static bool match_ssid_mac(const probe_frame_t *e, const char *ssid, const uint8_t mac[6])
{
    if (e->is_anqp) return false;
    if (memcmp(e->src_mac, mac, 6) != 0) return false;
    return strncmp(e->ssid, ssid ? ssid : "", sizeof(e->ssid)) == 0;
}

uint16_t probe_frame_ring_count_for_ssid_mac(const char *ssid, const uint8_t mac[6])
{
    if (!mac) return 0;
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const probe_frame_t *e = phys_at(i);
        if (e && match_ssid_mac(e, ssid, mac)) n++;
    }
    return n;
}

const probe_frame_t *probe_frame_ring_nth_for_ssid_mac(const char *ssid, const uint8_t mac[6], uint16_t n)
{
    if (!mac) return NULL;
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const probe_frame_t *e = phys_at(i);
        if (e && match_ssid_mac(e, ssid, mac)) {
            if (seen == n) return e;
            seen++;
        }
    }
    return NULL;
}
