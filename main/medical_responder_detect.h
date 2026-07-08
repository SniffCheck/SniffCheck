#pragma once

#include "analyzer.h"
#include "ble_scanner.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    MR_DEV_UNKNOWN = 0,
    MR_DEV_AMBULANCE_GATEWAY,
    MR_DEV_EMS_TABLET,
    MR_DEV_MEDICAL_MONITOR,
    MR_DEV_RADIO_ACCESSORY,
    MR_DEV_EMS_CAMERA,
    MR_DEV_AIR_AMBULANCE,
    MR_DEV_HOSPITAL_EMS,
    MR_DEV_OTHER,
    MR_DEV_TYPE_COUNT,
} mr_device_type_t;

typedef enum {
    MR_PRESENCE_NONE = 0,
    MR_PRESENCE_POSSIBLE,
    MR_PRESENCE_LIKELY,
    MR_PRESENCE_CONFIRMED,
} mr_presence_t;

#define MR_MAX_EVIDENCE 12

typedef struct {
    uint8_t  layer;
    uint8_t  device_type;
    uint8_t  confidence;
    char     source[14];
    char     label[28];
    char     target[18];
} mr_evidence_t;

typedef struct {
    mr_presence_t presence;
    uint8_t  confidence;
    bool     could_be_first_responder;
    uint16_t matches;
    uint16_t strong_matches;
    uint16_t device_counts[MR_DEV_TYPE_COUNT];
    uint16_t evidence_count;
    mr_evidence_t evidence[MR_MAX_EVIDENCE];
} mr_result_t;

void medical_responder_begin(mr_result_t *r);
void medical_responder_eval_wifi(const ap_score_t *ap, mr_result_t *r);
void medical_responder_eval_ble(const ble_device_t *d, mr_result_t *r);
void medical_responder_finalize(mr_result_t *r);

const mr_result_t *medical_responder_last(void);

const char *medical_responder_presence_label(mr_presence_t p);
const char *medical_responder_device_type_label(mr_device_type_t t);
