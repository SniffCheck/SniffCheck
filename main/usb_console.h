#pragma once

#include "esp_err.h"
#include <stddef.h>

typedef void (*usb_cmd_cb_t)(const char *cmd, const char *args);

esp_err_t usb_console_init(void);

void usb_console_set_cmd_cb(usb_cmd_cb_t cb);

void usb_console_task(void *arg);
