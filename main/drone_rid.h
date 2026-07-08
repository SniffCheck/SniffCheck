#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DRONE_RID_MSG_BASIC_ID     (1u << 0)
#define DRONE_RID_MSG_LOCATION     (1u << 1)
#define DRONE_RID_MSG_AUTH         (1u << 2)
#define DRONE_RID_MSG_SELF_ID      (1u << 3)
#define DRONE_RID_MSG_SYSTEM       (1u << 4)
#define DRONE_RID_MSG_OPERATOR_ID  (1u << 5)

#define DRONE_RID_BEARER_BLE          1
#define DRONE_RID_BEARER_WIFI_BEACON  2
#define DRONE_RID_BEARER_WIFI_NAN     3 

typedef struct {
    char    id[21];
    uint8_t ua_type;
    uint8_t id_type;
    uint8_t bearer;
    char    mfr_code[5];

    int32_t lat;
    int32_t lon;
    int32_t alt_m;
    int16_t speed;
    int16_t track;

    int32_t op_lat;
    int32_t op_lon;
    bool    has_op_loc;

    char    op_id[21];
    char    self_id[24];

    bool    auth_present;
    uint8_t msg_mask;
} drone_rid_t;

bool drone_rid_decode(const uint8_t *svc_data, size_t len, drone_rid_t *out);

bool drone_rid_decode_wifi_beacon(const uint8_t *ie, size_t len, drone_rid_t *out);

bool drone_rid_decode_wifi_nan(const uint8_t *frame, size_t len, drone_rid_t *out);

const char *drone_rid_bearer_label(uint8_t bearer);

int drone_op_separation_m(const drone_rid_t *d);

const char *drone_ua_type_label(uint8_t ua_type);
