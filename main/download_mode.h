#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "capture_writer.h"

typedef enum {
    DL_PASSIVE_SCAN = 0,
    DL_AP_STARTING,
    DL_AP_ACTIVE,
    DL_AP_STOPPING,
} download_state_t;

void download_mode_init(void);

void download_mode_request_enable(void);
void download_mode_request_disable(capture_end_reason_t reason);

bool             download_mode_is_active(void);
download_state_t download_mode_get_state(void);

const char *download_mode_get_ssid(void);
const char *download_mode_get_passphrase(void);
uint32_t    download_mode_get_seconds_remaining(void);
uint8_t     download_mode_get_client_count(void);

uint32_t download_mode_extend_seconds(uint32_t seconds);

void    download_mode_set_timeout_minutes(uint8_t m);
uint8_t download_mode_get_timeout_minutes(void);

void download_mode_set_channel(uint8_t ch);
