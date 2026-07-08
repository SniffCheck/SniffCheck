#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "drone_rid.h"

typedef enum {
    MGMT_BEACON     = 0,
    MGMT_PROBE_RESP = 1,
    MGMT_PROBE_REQ  = 2,
    MGMT_DEAUTH     = 3,
    MGMT_DISASSOC   = 4,
    MGMT_OTHER      = 5,
    MGMT_ANQP       = 6,
    MGMT_NOT_MGMT   = 7,
} mgmt_type_t;

typedef struct {
    mgmt_type_t type;
    uint8_t     bssid[6];
    char        ssid[33];
    uint16_t    beacon_interval;
    bool        has_rsn;
    bool        privacy;
    bool        rsn_pmf_required;
    bool        rsn_pmf_capable;
    bool        rsn_malformed;
    bool        has_wps;
    uint8_t     ds_channel;
    uint8_t     vendor_ie_ouis[4][3];
    uint8_t     vendor_ie_count;
    const char *vendor_ie_names[4];

    char        country_code[3];
    uint8_t     rsn_group_oui[3];
    uint8_t     rsn_group_suite;
    char        wps_manufacturer[33];
    char        wps_model_name[33];
    char        wps_device_name[33];
    uint32_t    ie_pattern_hash;

    uint16_t    seq_num;

    bool        has_rid;
    drone_rid_t rid;
} parsed_mgmt_t;

bool frame_parse_mgmt(const uint8_t *data, uint16_t len, parsed_mgmt_t *out);
