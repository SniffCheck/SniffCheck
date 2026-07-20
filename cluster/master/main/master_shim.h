#pragma once
#include <stdint.h>

void master_shim_set_session(const char *id, const char *fw);
void master_shim_set_last_scan(uint16_t s);

void master_on_rescan_request(void);
void master_on_walk_request(bool start);

void master_on_epup_label(const char *label);

void master_cluster_status_json(char *buf, size_t buflen);

void master_cluster_log_json(char *buf, size_t buflen);

void master_cluster_sentinel_json(char *buf, size_t buflen);
void master_on_sentinel_cfg(const char *body, int len);

void master_cluster_places_json(char *buf, size_t buflen);
void master_on_place_label(const char *body, int len);
void master_cluster_hits_json(char *buf, size_t buflen);
void master_on_settime(uint32_t epoch);

void master_on_brain_reset(void);
