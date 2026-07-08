#pragma once

#include <stdint.h>
#include <stdbool.h>

#define BLE_ADV_DATA_MAX 31

typedef struct {
    uint8_t  addr[6];
    int8_t   rssi;
    int8_t   tx_power;
    uint8_t  prim_phy;
    uint8_t  props;
    uint8_t  data_len;
    uint8_t  data[BLE_ADV_DATA_MAX];
    uint16_t scan_idx;
    uint32_t ts_ms;
    bool     used;
} ble_adv_frame_t;

void ble_adv_ring_init(void);
void ble_adv_ring_set_retention_mode(bool retain);
void ble_adv_ring_begin_scan(void);
void ble_adv_ring_add(const ble_adv_frame_t *f);

uint16_t               ble_adv_ring_count(void);
const ble_adv_frame_t *ble_adv_ring_at(uint16_t idx);

uint16_t               ble_adv_ring_count_for_addr(const uint8_t addr[6]);
const ble_adv_frame_t *ble_adv_ring_nth_for_addr(const uint8_t addr[6], uint16_t n);
