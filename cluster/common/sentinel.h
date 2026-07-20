#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SENTINEL_CAT_PWNAGOTCHI = 0,
    SENTINEL_CAT_MINIGOTCHI,
    SENTINEL_CAT_MARAUDER,
    SENTINEL_CAT_HAK5,
    SENTINEL_CAT_FLIPPER,
    SENTINEL_CAT_FLOCK,
    SENTINEL_CAT_LAW_ENFORCEMENT,
    SENTINEL_CAT_DEAUTHER,
    SENTINEL_CAT_OMG,
    SENTINEL_CAT_UBERTOOTH,
    SENTINEL_CAT_WARDRIVER,
    SENTINEL_CAT_BETTERCAP,
    SENTINEL_CAT_SNIFFCHECK,
    SENTINEL_CAT_RAGNAR,
    SENTINEL_CAT_COUNT
} sentinel_cat_t;

#define SENTINEL_MASK_ALL  ((uint16_t)((1u << SENTINEL_CAT_COUNT) - 1))

typedef enum {
    SENTINEL_CONF_NONE = 0,
    SENTINEL_CONF_LOW  = 1,
    SENTINEL_CONF_HIGH = 2,
} sentinel_conf_t;

typedef struct {
    const char *key;
    const char *label;
    const char *icon;
} sentinel_cat_meta_t;

const sentinel_cat_meta_t *sentinel_cat_meta(int i);

uint32_t sentinel_match_categories(const char *line, int n);

uint32_t sentinel_match_categories_conf(const char *line, int n, uint8_t *conf);

uint32_t sentinel_match_fields(const char *name, const char *vendor,
                               const char *name_rule, bool is_le);

uint32_t sentinel_match_fields_conf(const char *name, const char *vendor,
                                    const char *name_rule, bool is_le, uint8_t *conf);

bool sentinel_line_identifier(const char *line, int n, uint8_t mac[6]);

int sentinel_line_type(const char *line, int n, char *out, int outsz);

bool sentinel_mac_prefix(const uint8_t mac[6], const uint8_t *pref, int pref_len);

#ifdef __cplusplus
}
#endif
