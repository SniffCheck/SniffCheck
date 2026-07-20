#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "epup_summary.h"

#ifdef __cplusplus
extern "C" {
#endif

bool epup_brain_init(uint32_t boot_count);

void epup_brain_observe(const char *jsonl, size_t len);

void epup_brain_get(epup_summary_t *out);

typedef struct {
    int8_t   cur;
    uint8_t  count;
    uint8_t  similarity;
    bool     known;
    bool     is_new;
    uint32_t scans;
    char     label[16];
} epup_place_t;

void epup_brain_place(epup_place_t *out);

#include "cluster_proto.h"
void epup_brain_places(cl_places_t *out);

void epup_brain_place_label(int i, const char *label);

void epup_brain_reset(void);

size_t epup_brain_ckpt_size(void);

size_t epup_brain_ckpt_save(uint8_t *out, size_t cap);

bool epup_brain_ckpt_load(const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif
