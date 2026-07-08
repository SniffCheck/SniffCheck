#pragma once

#include <stdint.h>
#include <stdbool.h>

#define STA_TRACKER_MAX 64

typedef struct {
    uint8_t     mac[6];
    const char *vendor;
    uint16_t    eui_flags;
    uint8_t     device_class;
    uint32_t    frames;
    bool        randomized;
    bool        is_camera;

    uint8_t     bssid[6];
    bool        bssid_valid;
    uint32_t    frames_uplink;
    uint32_t    frames_downlink;
    int8_t      rssi_last;
    int8_t      rssi_best;
    uint8_t     channel;
    uint32_t    first_seen_ms;
    uint32_t    last_seen_ms;
} sta_entry_t;

void sta_tracker_begin_scan(void);

void sta_tracker_observe_frame(const uint8_t *frame, uint16_t len, int8_t rssi, uint8_t channel);

void sta_tracker_finalize(void);

uint16_t sta_tracker_count(void);
uint16_t sta_tracker_camera_count(void);

uint16_t sta_tracker_entry_count(void);
const sta_entry_t *sta_tracker_at(uint16_t idx);
