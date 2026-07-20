#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "dogpark_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t     src_mac[6];
    int8_t      rssi;
    dp_header_t hdr;
    uint8_t     payload[DP_PAYLOAD_MAX];
    uint8_t     payload_len;
} dp_rx_frame_t;

esp_err_t dp_espnow_init(void);

void dp_espnow_suspend(void);
esp_err_t dp_espnow_resume(void);

void dp_espnow_self_mac(uint8_t mac_out[6]);

bool dp_espnow_rx(dp_rx_frame_t *out, uint32_t timeout_ms);

esp_err_t dp_espnow_send(const uint8_t *dst_mac,
                         dp_msg_type_t type,
                         uint8_t extra_flags,
                         uint32_t session_id,
                         uint16_t node_id,
                         uint16_t seq,
                         const void *payload,
                         uint8_t payload_len);

esp_err_t dp_espnow_add_peer(const uint8_t mac[6]);
esp_err_t dp_espnow_del_peer(const uint8_t mac[6]);

uint16_t dp_crc16(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
