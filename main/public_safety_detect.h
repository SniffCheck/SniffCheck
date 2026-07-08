#pragma once

#include "analyzer.h"
#include "ble_scanner.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    PS_DEV_UNKNOWN = 0,
    PS_DEV_BODY_CAMERA,
    PS_DEV_TASER,
    PS_DEV_IN_CAR_CAMERA,
    PS_DEV_RADIO,
    PS_DEV_VEHICLE_GATEWAY,
    PS_DEV_RUGGED_DEVICE,
    PS_DEV_OTHER,
    PS_DEV_TYPE_COUNT,
} ps_device_type_t;

typedef enum {
    PS_PRESENCE_NONE = 0,
    PS_PRESENCE_POSSIBLE,
    PS_PRESENCE_LIKELY,
    PS_PRESENCE_CONFIRMED,
} ps_presence_t;

#define PS_MAX_EVIDENCE 12

typedef struct {
    uint8_t  layer;
    uint8_t  device_type;
    uint8_t  confidence;
    char     source[14];
    char     label[24];
    char     target[18];
} ps_evidence_t;

typedef struct {
    ps_presence_t presence;
    uint8_t  confidence;
    uint16_t matches;
    uint16_t strong_matches;
    uint16_t device_counts[PS_DEV_TYPE_COUNT];
    uint16_t estimated_officers_low;
    uint16_t estimated_officers_high;
    uint16_t evidence_count;
    ps_evidence_t evidence[PS_MAX_EVIDENCE];
} ps_result_t;

void public_safety_begin(ps_result_t *r);
void public_safety_eval_wifi(const ap_score_t *ap, ps_result_t *r);
void public_safety_eval_ble(const ble_device_t *d, ps_result_t *r);

void public_safety_finalize(ps_result_t *r);

const ps_result_t *public_safety_last(void);

const char *public_safety_presence_label(ps_presence_t p);
const char *public_safety_device_type_label(ps_device_type_t t);

#define PS_PAIRING_MODEL "body_camera_taser_max_plus_outliers_v1"
