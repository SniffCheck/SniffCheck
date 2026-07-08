#pragma once

#include <stdint.h>
#include <stdbool.h>

void flock_detect_begin_scan(void);

void flock_detect_observe_probe(const uint8_t src_mac[6], const char *ssid);

bool flock_oui_match(const uint8_t mac[6]);

uint16_t flock_detect_hits(void);

uint16_t flock_detect_distinct(void);
