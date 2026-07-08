#include "flock_detect.h"

#include <string.h>
#include "esp_log.h"

static const char *TAG = "sc_flock";

static const uint8_t FLOCK_OUI[][3] = {
    {0x70,0xc9,0x4e}, {0x3c,0x91,0x80}, {0xd8,0xf3,0xbc}, {0x80,0x30,0x49},
    {0xb8,0x35,0x32},
    {0x14,0x5a,0xfc}, {0x74,0x4c,0xa1},
    {0x08,0x3a,0x88},
    {0x9c,0x2f,0x9d}, {0xc0,0x35,0x32}, {0x94,0x08,0x53}, {0xe4,0xaa,0xea},
    {0xf4,0x6a,0xdd}, {0xf8,0xa2,0xd6}, {0x24,0xb2,0xb9}, {0x00,0xf4,0x8d},
    {0xd0,0x39,0x57}, {0xe8,0xd0,0xfc},
    {0xe0,0x4f,0x43},
    {0xb8,0x1e,0xa4}, {0x70,0x08,0x94},
    {0x58,0x8e,0x81},
    {0xec,0x1b,0xbd},
    {0x3c,0x71,0xbf},
    {0x58,0x00,0xe3},
    {0x90,0x35,0xea},
    {0x5c,0x93,0xa2}, {0x64,0x6e,0x69},
    {0x48,0x27,0xea},
    {0xa4,0xcf,0x12},
    {0x82,0x6b,0xf2},
};
#define FLOCK_OUI_COUNT (sizeof(FLOCK_OUI) / sizeof(FLOCK_OUI[0]))

#define FLOCK_MAX_DISTINCT 16

static uint16_t s_hits;
static uint8_t  s_distinct_macs[FLOCK_MAX_DISTINCT][6];
static uint16_t s_distinct_count;

bool flock_oui_match(const uint8_t mac[6])
{
    if (!mac) return false;
    for (size_t i = 0; i < FLOCK_OUI_COUNT; i++) {
        if (mac[0] == FLOCK_OUI[i][0] &&
            mac[1] == FLOCK_OUI[i][1] &&
            mac[2] == FLOCK_OUI[i][2]) {
            return true;
        }
    }
    return false;
}

void flock_detect_begin_scan(void)
{
    s_hits = 0;
    s_distinct_count = 0;
    memset(s_distinct_macs, 0, sizeof(s_distinct_macs));
}

static bool note_distinct(const uint8_t mac[6])
{
    for (uint16_t i = 0; i < s_distinct_count; i++) {
        if (memcmp(s_distinct_macs[i], mac, 6) == 0) return false;
    }
    if (s_distinct_count < FLOCK_MAX_DISTINCT) {
        memcpy(s_distinct_macs[s_distinct_count], mac, 6);
        s_distinct_count++;
    }
    return true;
}

void flock_detect_observe_probe(const uint8_t src_mac[6], const char *ssid)
{
    if (!src_mac) return;

    bool wildcard = (ssid == NULL) || (ssid[0] == '\0');
    if (!wildcard) return;
    if (!flock_oui_match(src_mac)) return;

    s_hits++;
    bool is_new = note_distinct(src_mac);
    if (is_new) {
        ESP_LOGW(TAG,
                 "possible Flock: wildcard probe from %02X:%02X:%02X:%02X:%02X:%02X "
                 "(OUI in Flock set; candidate, shared OEM prefix)",
                 src_mac[0], src_mac[1], src_mac[2],
                 src_mac[3], src_mac[4], src_mac[5]);
    }
}

uint16_t flock_detect_hits(void)     { return s_hits; }
uint16_t flock_detect_distinct(void) { return s_distinct_count; }
