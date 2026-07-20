#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#define DISPLAY_W 160
#define DISPLAY_H  80

static inline uint16_t rgb565be(uint8_t r, uint8_t g, uint8_t b)
{
    uint16_t c = ((uint16_t)(r & 0xF8) << 8)
               | ((uint16_t)(g & 0xFC) << 3)
               | (b >> 3);
    return (uint16_t)((c >> 8) | (c << 8));
}

#define COLOR_BLACK      0x0000u
#define COLOR_NEARBLACK  rgb565be(8, 8, 8)
#define COLOR_WHITE      0xFFFFu
#define COLOR_RED        0x00F8u
#define COLOR_GREEN      0xE007u
#define COLOR_BLUE       0x1F00u
#define COLOR_AMBER      0x00FDu
#define COLOR_HEADER     rgb565be(0x40, 0xC4, 0xF6)

esp_err_t display_init(spi_host_device_t host);
void      display_set_brightness_percent(uint8_t percent);
void      display_set_post_blit_cb(void (*cb)(void));
void      display_clear(uint16_t color_be);
void      display_fill_rect(int x, int y, int w, int h, uint16_t color_be);
void      display_draw_image(int x, int y, int w, int h, const uint16_t *pixels);
void      display_draw_image_masked(int x, int y, int w, int h,
                                    const uint16_t *pixels, const uint8_t *mask);
void      display_draw_image_masked_scaled(int x, int y, int w, int h,
                                           const uint16_t *pixels,
                                           const uint8_t *mask, int scale);

void display_blit_brand(int y);
void display_blit_sitting(int y);
void display_blit_sitting_scaled(int y, int scale);

void display_draw_string(int x, int y, const char *str,
                         uint16_t fg, uint16_t bg, uint8_t scale);

void display_logo_frame(int frame);
void display_splash(void);
void display_splash_credit(void);
void display_splash_credit2(void);

void display_scan_stage_static(const char *subject);
void display_scan_walk_frame(int x, bool facing_left, int frame);
int  display_scan_walk_x_min(void);
int  display_scan_walk_x_max(void);
void display_score_dig_frame(int frame);

void display_advisor_scanning(void);
void display_advisor_scanning_wifi(void);
void display_advisor_scanning_ble(void);

void display_walk_screen(const char *pup_name, uint32_t duration_sec,
                         uint16_t wifi, uint16_t ble, bool ending);
void display_advisor_scoring_results(uint16_t n_nets, uint16_t n_ble);
