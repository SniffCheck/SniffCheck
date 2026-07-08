#pragma once

#include "ble_scanner.h"
#include <stdint.h>
#include <stddef.h>

#define APPLE_SUB_IBEACON          0x02
#define APPLE_SUB_AIRDROP          0x05
#define APPLE_SUB_HOMEKIT          0x06
#define APPLE_SUB_AIRPODS_PROX     0x07
#define APPLE_SUB_HEY_SIRI         0x08
#define APPLE_SUB_AIRPLAY          0x09
#define APPLE_SUB_MAGIC_SWITCH     0x0B
#define APPLE_SUB_HANDOFF          0x0C
#define APPLE_SUB_TETHERING_TGT    0x0D
#define APPLE_SUB_TETHERING_SRC    0x0E
#define APPLE_SUB_NEARBY_ACTION    0x0F
#define APPLE_SUB_NEARBY_INFO      0x10
#define APPLE_SUB_AIRTAG           0x12
#define APPLE_SUB_FIND_MY_SEP      0x16

void apple_continuity_decode(ble_device_t *d, const uint8_t *payload, size_t len);

const char *apple_subtype_label(uint8_t subtype);

const char *apple_nearby_state_label(uint8_t state_nibble);

const char *apple_airtag_state_label(uint8_t status_byte, uint8_t adv_length);

typedef enum {
    APPLE_DEVCAT_UNKNOWN = 0,
    APPLE_DEVCAT_IPHONE,
    APPLE_DEVCAT_IPAD,
    APPLE_DEVCAT_MACBOOK,
    APPLE_DEVCAT_WATCH,
    APPLE_DEVCAT_HOMEPOD,
} apple_devcat_t;

apple_devcat_t apple_hey_siri_devcat(uint16_t device_class);

const char *apple_devcat_label(apple_devcat_t cat);
