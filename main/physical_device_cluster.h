#pragma once

#include "analyzer.h"
#include "ble_scanner.h"
#include <stdbool.h>
#include <stdint.h>

#define PDC_NODE_WIFI  0
#define PDC_NODE_BLE   1

typedef enum {
    PDC_EV_MAC_ADJACENT = 0,
    PDC_EV_SAME_PHYSICAL_ROUTER,
    PDC_EV_WPS_VENDOR_MODEL,
    PDC_EV_L2L3_ID,
    PDC_EV_NAME_MATCH,

    PDC_EV_BLE_FASTPAIR_MODEL,
    PDC_EV_BLE_SERVICE_UUID,
    PDC_EV_BLE_LOCAL_NAME,

    PDC_EV_BLE_RID_ID,

    PDC_EV_VEHICLE_NAME,

    PDC_EV_ECOSYSTEM_COPRESENCE,
    PDC_EV_COUNT

} pdc_evidence_type_t;

typedef enum {
    PDC_CLASS_PHYSICAL_STRONG = 0,
    PDC_CLASS_PHYSICAL_CANDIDATE,
    PDC_CLASS_RELATIONSHIP,
    PDC_CLASS_PRODUCT_FAMILY,
    PDC_CLASS_CONTEXT,
    PDC_CLASS_COUNT
} pdc_evidence_class_t;

typedef struct {
    uint8_t kind_a;
    uint8_t idx_a;
    uint8_t kind_b;
    uint8_t idx_b;
    uint8_t evidence;
    uint8_t evclass;
    uint8_t confidence;
    uint8_t can_union;

    uint16_t cand_mask;
    uint16_t conflict_mask;
    uint8_t corroborated;
} pdc_edge_t;

typedef struct {
    uint8_t kind;
    uint8_t idx;
} pdc_member_t;

#define PDC_MAX_EDGES     96
#define PDC_MAX_CLUSTERS  24
#define PDC_MAX_MEMBERS    8

#define PDC_CLUSTER_PHYSICAL  0
#define PDC_CLUSTER_VEHICLE   1

typedef struct {
    pdc_member_t members[PDC_MAX_MEMBERS];
    uint8_t      member_count;
    uint8_t      total_members;
    uint8_t      confidence;
    uint8_t      kind;
} pdc_cluster_t;

typedef struct {
    uint8_t kind;
    uint8_t idx;
    uint8_t mac[6];
    uint8_t evidence;
    uint8_t evclass;
    uint8_t confidence;
} pdc_peer_t;

void pdc_build(const ap_score_t *scores, uint16_t ap_count,
               const ble_results_t *ble);

uint8_t             pdc_cluster_count(void);
const pdc_cluster_t *pdc_cluster_get(uint8_t i);

uint8_t             pdc_vehicle_cluster_count(void);
const pdc_cluster_t *pdc_vehicle_cluster_get(uint8_t i);
int8_t              pdc_vehicle_cluster_of(uint8_t kind, uint8_t idx);

uint8_t             pdc_edge_count(void);
const pdc_edge_t    *pdc_edge_get(uint8_t i);

int8_t pdc_cluster_of(uint8_t kind, uint8_t idx);

const uint8_t *pdc_node_mac(uint8_t kind, uint8_t idx);

uint8_t pdc_peers_of_mac(uint8_t kind, const uint8_t mac[6],
                         pdc_peer_t *out, uint8_t max, uint8_t *total_out);

const char *pdc_evidence_label(uint8_t ev);
const char *pdc_evidence_short(uint8_t ev);

pdc_evidence_class_t pdc_evidence_class(uint8_t ev);
bool        pdc_class_can_union_alone(uint8_t evclass);
const char *pdc_class_label(uint8_t evclass);
const char *pdc_class_short(uint8_t evclass);

const char *pdc_conflict_label(uint16_t bit);

const char *pdc_cand_label(uint16_t bit);
