#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t lifetime_detections;
    uint32_t lifetime_unique;
    uint32_t session_detections;
    uint32_t session_unique;
    uint32_t returning;
} sentinel_reg_stats_t;

void sentinel_registry_init(void);

int  sentinel_registry_key(uint8_t cat, const uint8_t mac[6], const char *name,
                           uint8_t *out, int outcap);

bool sentinel_registry_note(const uint8_t *key, int keylen,
                            const char *rec_json, int rec_len);

void sentinel_registry_note_untracked(void);

void sentinel_registry_stats(sentinel_reg_stats_t *out);

void sentinel_registry_sync(void);
