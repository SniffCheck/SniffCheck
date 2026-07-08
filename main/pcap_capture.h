

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#define PCAP_MAX_CHANNELS 32

typedef enum {
    PCAP_IDLE = 0,
    PCAP_RUNNING,
    PCAP_READY,
    PCAP_PARTIAL,
    PCAP_FAILED,
} pcap_status_t;

typedef struct {
    bool          ran;
    pcap_status_t status;
    uint8_t       channels[PCAP_MAX_CHANNELS];
    uint8_t       channel_count;
    uint16_t      seconds_per_channel;
    uint32_t      duration_s;
    uint32_t      packets;
    uint32_t      dropped;
    uint32_t      truncated;
    uint32_t      bytes;
    uint32_t      scan_id;
} pcap_meta_t;

esp_err_t pcap_capture_init(void);

esp_err_t pcap_capture_run(const uint8_t *channels, uint8_t n,
                           uint16_t secs, uint32_t scan_id);

const pcap_meta_t *pcap_capture_meta(void);

const uint8_t *pcap_capture_data(size_t *len_out);
