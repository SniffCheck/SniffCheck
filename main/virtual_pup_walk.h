#pragma once

#include "analyzer.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool     active;
    uint32_t walk_id;
    uint32_t started_ms;
    uint32_t ended_ms;
    uint32_t duration_sec;
    uint16_t wifi_sweeps;
    uint16_t ble_windows;
    uint16_t wifi_unique_bssid;
    uint16_t wifi_unique_ssid;
    uint16_t ble_unique_devices;
    uint16_t threat_events;
    uint16_t safe_networks;
    uint16_t interesting_sniffs;
    uint16_t xp_awarded;
    char     mood[12];
} pup_walk_summary_t;

void virtual_pup_walk_init(void);

void virtual_pup_walk_start(void);

void virtual_pup_walk_note_wifi_ap(const ap_score_t *ap, bool safe_candidate);
void virtual_pup_walk_note_ble_device(const ble_device_t *d);

void virtual_pup_walk_end_wifi_sweep(void);
void virtual_pup_walk_end_ble_window(void);

bool virtual_pup_walk_is_active(void);

void virtual_pup_walk_get_current(pup_walk_summary_t *out);

bool virtual_pup_walk_end(pup_walk_summary_t *out);

void virtual_pup_walk_get_last(pup_walk_summary_t *out);

uint16_t virtual_pup_walk_wifi_count(void);
uint16_t virtual_pup_walk_ble_count(void);
const ap_score_t *virtual_pup_walk_wifi_at(uint16_t idx);
const ble_device_t *virtual_pup_walk_ble_at(uint16_t idx);

void virtual_pup_walk_release(void);

#ifdef __cplusplus
}
#endif
