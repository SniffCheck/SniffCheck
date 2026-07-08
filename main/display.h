#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"
#include "analyzer.h"
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

#define COLOR_BLACK  0x0000u

#define COLOR_NEARBLACK  rgb565be(8, 8, 8)
#define COLOR_WHITE  0xFFFFu
#define COLOR_RED    0x00F8u
#define COLOR_GREEN  0xE007u
#define COLOR_BLUE   0x1F00u
#define COLOR_NAVY   0x1000u
#define COLOR_AMBER  0x00FDu
#define COLOR_ORANGE 0x60FBu
#define COLOR_YELLOW 0xA0FEu

#define COLOR_SAFE    rgb565be(0x00, 0xC8, 0x53)
#define COLOR_OK      rgb565be(0xFF, 0xD6, 0x00)
#define COLOR_CAUTION rgb565be(0xFF, 0x6D, 0x00)
#define COLOR_DANGER  rgb565be(0xD5, 0x00, 0x00)
#define COLOR_PURPLE  rgb565be(0x8B, 0x00, 0x8B)
#define COLOR_HEADER  rgb565be(0x40, 0xC4, 0xF6)

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

void      display_blit_brand(int y);
void      display_blit_sitting(int y);
void      display_blit_verdict(int y, uint8_t verdict);

void      display_blit_verdict_scaled(int y, uint8_t verdict, int scale);

void      display_blit_verdict_lg(int y, uint8_t verdict);

void display_draw_string(int x, int y, const char *str,
                         uint16_t fg, uint16_t bg, uint8_t scale);

void display_logo_frame(int frame);
void display_splash(void);

void display_splash_credit(void);

void display_splash_credit2(void);

void display_advisor_scanning(void);
void display_advisor_scanning_wifi(void);
void display_advisor_scanning_ble(void);
void display_advisor_scoring_results(uint16_t n_nets, uint16_t n_ble);

void display_walk_screen(const char *pup_name, uint32_t duration_sec,
                         uint16_t wifi, uint16_t ble, bool ending);

void display_scan_stage_static(const char *subject);
void display_scan_walk_frame(int x, bool facing_left, int frame);
int  display_scan_walk_x_min(void);
int  display_scan_walk_x_max(void);

void display_score_dig_frame(int frame);
void display_advisor_summary(uint16_t n_nets, uint16_t n_ble,
                             uint8_t n_2g, uint8_t n_5g,
                             const ap_score_t *best);
void display_advisor_recommend(const ap_score_t *ap, uint8_t rank,
                               uint16_t n_nets, uint8_t n_2g,
                               uint8_t n_5g, uint16_t n_ble);
void display_advisor_no_safe(uint16_t n_nets, uint8_t n_2g,
                             uint8_t n_5g, uint16_t n_ble);

#include "vetter.h"
#include "ble_scanner.h"

uint8_t display_details_wifi_lite(const ap_score_t *ap,
                                  const vetter_result_t *v,
                                  uint8_t page_idx);

uint8_t display_details_wifi_adv (const ap_score_t *ap,
                                  const vetter_result_t *v,
                                  const ble_results_t *ble,
                                  uint8_t page_idx);
uint8_t display_details_ble_lite (const ble_device_t *d, uint8_t page_idx);

uint8_t display_details_ble_adv  (const ble_device_t *d,
                                  const ap_score_t *scores, uint16_t count,
                                  uint8_t page_idx);

void display_details_chrome(const char *title, uint8_t page_idx, uint8_t page_total);

void display_details_chrome_footer(const char *title, uint8_t page_idx,
                                   uint8_t page_total, const char *footer);
