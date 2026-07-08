#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PUP_TROPHY_COUNT     200
#define PUP_TROPHY_MAX_NEW   16

typedef struct {
    uint16_t wifi_n;
    uint16_t ble_n;
    uint16_t hidden;
    uint16_t band5g;
    uint16_t open_nets;
    uint16_t wpa3;
    uint16_t enterprise;
    uint16_t consumer;
    uint16_t iot;
    uint16_t surveil;
    uint16_t axon;
    uint16_t flock;
    uint16_t investigation;
    uint16_t tracker;
    uint16_t airtag;
    uint16_t drone;
    uint16_t pwnagotchi;
    uint16_t deauth;
    uint16_t twin;
    uint16_t pmkid;
    uint16_t malicious;
    uint16_t phone;
    uint16_t laptop;
    uint16_t wearable;
    uint16_t audio;
    uint16_t medical;
    uint16_t vehicle;
    uint16_t maker;
    uint16_t devmod;
    uint16_t beacon;
    uint16_t pos;
    uint16_t access;
    uint16_t infra;
    uint16_t close_ble;
    uint16_t strong_wifi;
    uint8_t  env_threat;
} pup_scan_stats_t;

typedef struct {
    uint8_t  new_count;
    uint16_t new_ids[PUP_TROPHY_MAX_NEW];
    uint16_t new_scents;
    uint32_t bonus_xp;
} pup_trophy_feed_result_t;

void pup_trophy_init(void);

bool pup_trophy_smell(const char *vendor);

pup_trophy_feed_result_t pup_trophy_feed(const pup_scan_stats_t *st,
                                         uint32_t boot_count,
                                         uint16_t level,
                                         uint32_t age_boots);

uint16_t    pup_trophy_earned_count(void);

uint16_t    pup_trophy_earned_at(uint16_t n);
const char *pup_trophy_name(uint16_t id);
uint8_t     pup_trophy_weight(uint16_t id);
uint32_t    pup_trophy_xp(uint16_t id);
uint8_t     pup_trophy_icon(uint16_t id);
uint32_t    pup_trophy_boot_earned(uint16_t id);
uint32_t    pup_trophy_scent_count(void);

void pup_trophy_dump(void);

#ifdef __cplusplus
}
#endif
