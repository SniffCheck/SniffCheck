#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t  src_mac[6];
    char     ssid[33];
    uint16_t seq_num;
    uint32_t ie_hash;
    int8_t   rssi;
    uint8_t  channel;
    uint16_t scan_idx;
    uint32_t ts_ms;
    bool     is_anqp;
    bool     used;
} probe_frame_t;

void probe_frame_ring_init(void);

void probe_frame_ring_set_retention_mode(bool retain);

void probe_frame_ring_begin_scan(void);

void probe_frame_ring_add(const probe_frame_t *f);

uint16_t              probe_frame_ring_count(void);
const probe_frame_t  *probe_frame_ring_at(uint16_t idx);

uint16_t              probe_frame_ring_count_for_mac(const uint8_t mac[6], bool anqp_only);
const probe_frame_t  *probe_frame_ring_nth_for_mac(const uint8_t mac[6], bool anqp_only, uint16_t n);

uint16_t              probe_frame_ring_count_for_ssid_mac(const char *ssid, const uint8_t mac[6]);
const probe_frame_t  *probe_frame_ring_nth_for_ssid_mac(const char *ssid, const uint8_t mac[6], uint16_t n);
