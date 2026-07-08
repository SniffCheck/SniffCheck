#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VP_TITLE_PUPPY = 0,
    VP_TITLE_YOUNG,
    VP_TITLE_ADULT,
    VP_TITLE_VETERAN,
    VP_TITLE_LEGEND,
} vp_title_t;

typedef enum {
    VP_MOOD_CURIOUS = 0,
    VP_MOOD_HAPPY,
    VP_MOOD_EXCITED,
    VP_MOOD_CONTENT,
} vp_mood_t;

#define VP_NAME_MAX 24

typedef struct {
    uint32_t   lifetime_wifi;
    uint32_t   lifetime_ble;
    uint64_t   total_xp;
    uint16_t   level;
    uint64_t   xp_into_level;
    uint64_t   xp_for_level;
    vp_title_t title;
    uint8_t    avatar;
    uint32_t   birth_boot;
    uint32_t   lifetime_scans;
    uint32_t   pets;
    uint32_t   treats;
    uint32_t   last_scan_xp;
    vp_mood_t  mood;
} vp_status_t;

typedef struct {
    uint32_t xp_gained;
    bool     leveled_up;
    uint16_t new_level;
} vp_feed_result_t;

void virtual_pup_init(uint32_t boot_count);

vp_feed_result_t virtual_pup_feed(uint16_t wifi_n, uint16_t ble_n);

vp_feed_result_t virtual_pup_grant_xp(uint32_t xp);

void virtual_pup_get(vp_status_t *out);

uint16_t virtual_pup_level_for_xp(uint64_t xp);

vp_title_t  virtual_pup_title_for_level(uint16_t level);
const char *virtual_pup_title_label(vp_title_t title);

const char *virtual_pup_name(void);

void virtual_pup_set_name(const char *name);

void virtual_pup_pet(void);
void virtual_pup_treat(void);

const char *virtual_pup_mood_label(void);

void virtual_pup_reset(void);

#ifdef __cplusplus
}
#endif
