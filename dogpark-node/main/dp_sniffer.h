#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dogpark_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  kind;
    uint8_t  ssid_len;
    char     ssid[32];
} dp_obs_t;

void dp_sniffer_init(void);

void dp_sniffer_start(void);
void dp_sniffer_stop(void);

void dp_sniffer_set_channel(uint8_t ch);

bool dp_sniffer_next(dp_obs_t *out, uint32_t timeout_ms);

void dp_sniffer_reset_seen(void);

uint32_t dp_sniffer_unique_count(void);

void dp_sniffer_set_tracking(bool on);

bool dp_sniffer_rssi_for(const uint8_t mac[6], int8_t *rssi, int64_t *last_us);

#ifdef __cplusplus
}
#endif
