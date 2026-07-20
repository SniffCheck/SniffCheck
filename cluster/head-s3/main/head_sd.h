#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
    bool     mounted;
    bool     full;
    uint64_t card_bytes;
    uint64_t free_bytes;
    uint64_t written_bytes;
    uint32_t records;
    uint32_t write_errors;
    char     path[64];
} head_sd_stats_t;

esp_err_t head_sd_mount(void);

bool head_sd_ok(void);

void head_sd_append(const char *line, size_t len);

void head_sd_flush(void);

void head_sd_get_stats(head_sd_stats_t *out);

FILE *head_sd_ckpt_open(bool write);
bool  head_sd_ckpt_commit(void);

#define HEAD_SD_REPORT_WINDOW  (768u * 1024u)
typedef struct head_sd_reader head_sd_reader_t;
head_sd_reader_t *head_sd_report_open(size_t window_bytes);
size_t            head_sd_report_next(head_sd_reader_t *r, char *buf, size_t bufsz);
void              head_sd_report_close(head_sd_reader_t *r);
