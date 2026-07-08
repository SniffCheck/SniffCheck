#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"
#include <stdint.h>

esp_err_t led_init(spi_host_device_t host);
void      led_set(uint8_t r, uint8_t g, uint8_t b, uint8_t brightness);
void      led_off(void);
