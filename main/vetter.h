#pragma once

#include "analyzer.h"
#include "ble_scanner.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    VETTER_PASS  = 0,
    VETTER_INFO  = 1,
    VETTER_WARN  = 2,
    VETTER_ALERT = 3,
    VETTER_SKIP  = 4,
} vetter_check_t;

typedef struct {
    vetter_check_t check[10];
    bool           blocked;
    char           summary[400];
} vetter_result_t;

esp_err_t vetter_run(const ap_score_t *ap,
                     const ble_results_t *ble,
                     vetter_result_t *out);

void vetter_log(const ap_score_t *ap, const vetter_result_t *result);

uint8_t vetter_lite_reasons(const ap_score_t *ap, char lines[2][64]);

const char *vetter_check_reason(const ap_score_t *ap,
                                const vetter_result_t *result,
                                uint8_t check_idx);
