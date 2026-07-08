#pragma once

#include "analyzer.h"
#include "ble_scanner.h"
#include "public_safety_detect.h"
#include "medical_responder_detect.h"
#include "probe_req_log.h"
#include "seq_analyzer.h"
#include "ie_signature.h"
#include "anqp_analyzer.h"
#include "wifi_sniffer.h"
#include "sta_tracker.h"
#include "pcap_capture.h"
#include "wifi_csi_probe.h"
#include "virtual_pup_walk.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    CAP_END_USER_DISABLE = 0,
    CAP_END_TIMEOUT,
    CAP_END_ROTATION,
    CAP_END_SHUTDOWN,
    CAP_END_SCAN_START,
    CAP_END_IMPORT,
} capture_end_reason_t;

const char *capture_writer_session_id(void);
const char *capture_writer_fw_version(void);
const char *capture_writer_schema_version(void);
uint16_t    capture_writer_last_scan(void);

void capture_writer_init(uint32_t boot_count);

void capture_emit_header(void);

void capture_emit_codebook(void);

void capture_emit_wifi_ap(const ap_score_t *ap, uint16_t scan_index);
void capture_emit_ble_device(const ble_device_t *d, uint16_t scan_index);

void capture_emit_wifi_ap_walk(const ap_score_t *ap, uint16_t scan_index, uint32_t walk_id);
void capture_emit_ble_device_walk(const ble_device_t *d, uint16_t scan_index, uint32_t walk_id);

#define CAPTURE_BYOS_MAX_SIGHT 8
typedef struct {
    char     source_id[16 + 1];
    int8_t   rssi;
    int32_t  lat_e7, lon_e7;
    uint32_t ts_s;
    bool     has_pos;
    bool     has_ts;
} capture_byos_sight_t;

void capture_emit_byos_mac(const uint8_t mac[6], uint16_t scan_index,
                           uint32_t import_id, uint16_t import_index,
                           const capture_byos_sight_t *sights, uint8_t n_sight);
void capture_emit_byos_wifi(const uint8_t bssid[6], uint16_t scan_index,
                            uint32_t import_id, uint16_t import_index,
                            const char *ssid, uint8_t channel,
                            const char *auth_raw,
                            const capture_byos_sight_t *sights, uint8_t n_sight);
void capture_emit_byos_ble(const uint8_t addr[6], uint16_t scan_index,
                           uint32_t import_id, uint16_t import_index,
                           const char *name,
                           const capture_byos_sight_t *sights, uint8_t n_sight);

void capture_emit_tracker_if_applicable(const ble_device_t *d, uint16_t scan_index);

void capture_emit_drone_rid_if_applicable(const ble_device_t *d, uint16_t scan_index);
void capture_emit_drone_rid_wifi(const sniffer_rec_t *sr, uint16_t scan_index);

void capture_emit_device_clusters(uint16_t scan_index);

void capture_emit_ble_addr_stats(const ble_results_t *ble, uint16_t scan_index);

void capture_emit_crowd_density(const crowd_estimate_t *cd, uint16_t scan_index);

void capture_emit_law_enforcement_presence(const ps_result_t *ps, uint16_t scan_index);

void capture_emit_medical_responder_presence(const mr_result_t *mr, uint16_t scan_index);

typedef struct {
    uint16_t camera_count;
    uint8_t  camera_conf;
    uint16_t public_safety_low;
    uint16_t public_safety_high;
    uint8_t  public_safety_conf;
    uint16_t phone_like_count;
    uint8_t  phone_like_conf;
    uint16_t medical_count;
    uint8_t  medical_conf;
} environment_indicators_t;

void capture_emit_environment_indicators(const environment_indicators_t *ei,
                                         uint16_t scan_index);

void capture_emit_channel_activity(const ap_score_t *scores, uint16_t count,
                                   uint16_t scan_index);

void capture_emit_pcap_capture(const pcap_meta_t *m, uint16_t scan_index);

void capture_emit_alerts_for_ap(const ap_score_t *ap, uint16_t scan_index);

void capture_emit_alerts_for_ble(const ble_device_t *d, uint16_t scan_index);

void capture_emit_probe_req_log(const probe_req_log_aggregate_t *agg,
                                 uint16_t scan_index, bool include_detail);

void capture_emit_seq_fingerprint_log(const seq_analyzer_aggregate_t *agg,
                                       uint16_t scan_index, bool include_detail);
void capture_emit_ie_signature_log(const ie_signature_aggregate_t *agg,
                                    uint16_t scan_index, bool include_detail);
void capture_emit_anqp_log(const anqp_analyzer_aggregate_t *agg,
                           uint16_t scan_index, bool include_detail);

void capture_emit_station_log(uint16_t scan_index);
void capture_emit_csi(uint16_t scan_index);

void capture_emit_pup_walk(const pup_walk_summary_t *w);

void capture_emit_footer(capture_end_reason_t reason,
                         uint32_t wifi_aps_seen, uint32_t ble_devices_seen,
                         uint32_t trackers_seen, uint32_t probe_reqs_seen,
                         uint32_t alerts_fired, uint32_t scans_completed);
