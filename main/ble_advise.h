#pragma once

#include "ble_scanner.h"
#include <stdint.h>

uint8_t ble_lite_reasons(const ble_device_t *d, char lines[2][64]);

uint8_t ble_effective_class(const ble_device_t *d);

#define BLE_CLASS_CONF_OK   50
#define BLE_CLASS_CONF_HIGH 80 
uint8_t ble_effective_class_certain(const ble_device_t *d);

char ble_class_conf_letter(const ble_device_t *d);
char ble_vendor_conf_letter(const ble_device_t *d);

const char *ble_class_source_label(uint8_t source);
