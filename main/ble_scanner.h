#pragma once

#include "esp_err.h"
#include "drone_rid.h"
#include <stdint.h>
#include <stdbool.h>

#define BLE_MAX_DEVICES  192

#define BLE_SCAN_MS       2000

#define BLE_SNAPSHOT_SCAN_MS  5000

typedef enum {
    BLE_ADDR_SUB_PUBLIC = 0,
    BLE_ADDR_SUB_STATIC_RANDOM,
    BLE_ADDR_SUB_RPA,
    BLE_ADDR_SUB_NRPA,
} ble_addr_subtype_t;

typedef enum {
    BLE_CLASS_SRC_NONE = 0,
    BLE_CLASS_SRC_MFG_RULE,
    BLE_CLASS_SRC_UUID128,
    BLE_CLASS_SRC_APPLE_SUBTYPE,
    BLE_CLASS_SRC_MS_SUBTYPE,
    BLE_CLASS_SRC_BT_COMPANY,
    BLE_CLASS_SRC_MAC_OUI,
    BLE_CLASS_SRC_NAME_RULE,
    BLE_CLASS_SRC_DRONE_RID,
    BLE_CLASS_SRC_UUID16,
} ble_class_source_t;

typedef struct {
    uint8_t            addr[6];
    ble_addr_subtype_t addr_subtype;
    int8_t             rssi;
    int8_t             tx_power;
    uint8_t            prim_phy;
    uint16_t           distance_dm;
    char               name[33];
    char               vendor[33];
    uint16_t           mfg_company_id;
    uint8_t            mfg_payload[2];
    uint16_t           uuids16[8];
    uint8_t            num_uuids16;
    uint16_t           uuid16_flags;
    uint8_t            uuid16_class;
    const char        *uuid16_name;
    uint8_t            num_uuids32;
    uint8_t            num_uuids128;
    uint16_t           eui_flags;
    uint8_t            device_class;
    uint8_t            mac_match_len;
    uint16_t           bt_company_flags;
    uint8_t            bt_company_class;
    char               company_name[33];

    const char        *mfg_rule_name;
    uint16_t           mfg_rule_flags;
    uint8_t            mfg_rule_class;
    uint8_t            mfg_rule_subtype;

    const char        *apple_subtype_name;
    uint16_t           apple_subtype_flags;
    uint8_t            apple_subtype_class;
    uint8_t            apple_subtype;

    uint8_t            apple_state;
    uint8_t            apple_devcat;
    char               apple_evidence[24];

    const char        *ms_subtype_name;
    uint16_t           ms_subtype_flags;
    uint8_t            ms_subtype_class;

    const char        *fastpair_name;
    uint16_t           fastpair_flags;
    uint8_t            fastpair_class;
    uint32_t           fastpair_model_id;

    const char        *uuid32_name;
    uint16_t           uuid32_flags;
    uint8_t            uuid32_class;

    const char        *uuid128_name;
    uint16_t           uuid128_flags;
    uint8_t            uuid128_class;

    const char        *name_rule_name;
    uint16_t           name_rule_flags;
    uint8_t            name_rule_class;
    uint8_t            name_rule_kind;

    bool               is_airtag;
    bool               scannable;
    bool               suppressed;

    uint8_t            base_quality;
    uint16_t           trust_q88;

    uint8_t            vendor_conf;
    uint8_t            class_conf;
    uint8_t            class_source;
    uint8_t            identity_score;
    uint8_t            identity_conf;
    uint8_t            threat_level;
    int16_t            wifi_match;

    bool               has_rid;
    drone_rid_t        drone;

    int32_t            _rssi_sum;
    uint16_t           _rssi_count;
} ble_device_t;

typedef struct {
    ble_device_t devices[BLE_MAX_DEVICES];
    uint16_t     count;
} ble_results_t;

esp_err_t ble_scanner_init(void);

const char *ble_proximity_label(uint16_t distance_dm);

esp_err_t ble_scan_run(ble_results_t *out, uint32_t duration_ms);

esp_err_t ble_scan_run_ex(ble_results_t *out, uint32_t duration_ms, bool continuous,
                          bool coded_phy);

typedef enum {
    BLE_EV_PENALTY = 0,
    BLE_EV_BASE    = 1,
    BLE_EV_TRUST   = 2,
} ble_evidence_kind_t;

typedef struct {
    char    label[22];
    int16_t delta;
    uint8_t kind;
} ble_evidence_t;

uint8_t ble_score_trail(const ble_device_t *d, ble_evidence_t *out, uint8_t max);
