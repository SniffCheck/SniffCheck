#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EPUP_TITLE_PUPPY = 0,
    EPUP_TITLE_YOUNG,
    EPUP_TITLE_ADULT,
    EPUP_TITLE_VETERAN,
    EPUP_TITLE_LEGEND,
} epup_title_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  schema_ver;
    uint8_t  title;
    uint8_t  confidence;
    uint32_t level;
    uint32_t total_scans;
    uint32_t born_boot;
    uint64_t total_obs;
    uint32_t unique_est;
    uint16_t last_wifi;
    uint16_t last_ble;
    uint16_t last_new;
    uint16_t ema_total;

    int8_t   place_cur;
    uint8_t  place_count;
    uint8_t  place_sim;
    uint8_t  place_flags;
    uint32_t place_scans;
    char     place_label[16];

    uint32_t boot_now;
    uint16_t crc;
} epup_summary_t;

#define EPUP_SUMMARY_MAGIC   0x8E
#define EPUP_SCHEMA_VER      1
#define EPUP_PLACE_KNOWN     0x01u
#define EPUP_PLACE_NEW       0x02u
#define EPUP_MATURE_SCANS    40000u

static inline const char *epup_title_label(epup_title_t t)
{
    switch (t) {
        case EPUP_TITLE_PUPPY:   return "Puppy";
        case EPUP_TITLE_YOUNG:   return "Young";
        case EPUP_TITLE_ADULT:   return "Adult";
        case EPUP_TITLE_VETERAN: return "Veteran";
        case EPUP_TITLE_LEGEND:  return "Legend";
    }
    return "Puppy";
}

#ifdef __cplusplus
}
#endif
