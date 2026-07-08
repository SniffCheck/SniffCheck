#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    size_t   capacity;
    size_t   bytes_used;
    uint32_t records_total;
    uint32_t records_current;
    uint32_t records_dropped;
    uint64_t bytes_total;
} capture_ring_stats_t;

typedef struct {
    size_t   pos;
    size_t   end;
    bool     wrapped;
    bool     valid;
} capture_ring_reader_t;

esp_err_t capture_ring_init(size_t preferred_bytes, size_t fallback_bytes);

size_t capture_ring_write(const char *line, size_t len);

void capture_ring_reader_open(capture_ring_reader_t *r);

size_t capture_ring_reader_next(capture_ring_reader_t *r, char *out, size_t out_sz);

void capture_ring_get_stats(capture_ring_stats_t *out);

void capture_ring_clear_volatile(void);
