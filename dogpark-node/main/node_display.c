#include "node_display.h"
#include "sniffcheck_logo_1.h"
#include "sniffcheck_logo_2.h"
#include "sniffcheck_logo_3.h"
#include "sniffcheck_logo_4.h"
#include "sniffcheck_logo_5.h"
#include "sniffcheck_logo_6.h"
#include "sniffcheck_logo_7.h"
#include "sniffcheck_logo_8.h"
#include "sniffcheck_logo_9.h"
#include "sniffcheck_logo_10.h"
#include "sniffcheck_standing.h"
#include "sniffcheck_sniff_r1.h"
#include "sniffcheck_sniff_r2.h"
#include "sniffcheck_sniff_l1.h"
#include "sniffcheck_sniff_l2.h"
#include "sniffcheck_dig_1.h"
#include "sniffcheck_dig_2.h"
#include "sniffcheck_dig_3.h"
#include "sniffcheck_sitting.h"
#include <stdarg.h>
#include "st7735.h"
#include "esp_check.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "driver/ledc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <string.h>

#define LCD_CLK_HZ    (20 * 1000 * 1000)
#define LCD_CMD_BITS  8
#define LCD_PARAM_BITS 8

#ifndef PIN_CS
#define PIN_CS   10
#endif
#ifndef PIN_DC
#define PIN_DC    3
#endif
#ifndef PIN_RST
#define PIN_RST   1
#endif
#ifndef PIN_BL
#define PIN_BL    0
#endif
#ifndef SC_LCD_MIRROR_X
#define SC_LCD_MIRROR_X true
#endif
#ifndef SC_LCD_MIRROR_Y
#define SC_LCD_MIRROR_Y false
#endif

#define PWM_TIMER   LEDC_TIMER_0
#define PWM_MODE    LEDC_LOW_SPEED_MODE
#define PWM_CH      LEDC_CHANNEL_0
#define PWM_BITS    LEDC_TIMER_10_BIT
#define PWM_FREQ_HZ 5000
#define PWM_DUTY_MAX ((1U << 10) - 1U)

#define BL_ACTIVE_LOW 1

static const char *TAG = "sc_display";
static esp_lcd_panel_handle_t s_panel;

static void backlight_set_percent(uint8_t percent)
{
    if (percent > 100) percent = 100;

    uint32_t duty = (PWM_DUTY_MAX * percent) / 100;
    if (BL_ACTIVE_LOW) {
        duty = PWM_DUTY_MAX - duty;
    }

    ESP_ERROR_CHECK(ledc_set_duty(PWM_MODE, PWM_CH, duty));
    ESP_ERROR_CHECK(ledc_update_duty(PWM_MODE, PWM_CH));
}

void display_set_brightness_percent(uint8_t percent)
{
    backlight_set_percent(percent);
}

static void backlight_init(void)
{
    ledc_timer_config_t timer = {
        .duty_resolution = PWM_BITS,
        .freq_hz         = PWM_FREQ_HZ,
        .speed_mode      = PWM_MODE,
        .timer_num       = PWM_TIMER,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    ESP_ERROR_CHECK(ledc_timer_config(&timer));

    ledc_channel_config_t ch = {
        .gpio_num   = PIN_BL,
        .speed_mode = PWM_MODE,
        .channel    = PWM_CH,
        .timer_sel  = PWM_TIMER,
        .duty       = 0,
        .intr_type  = LEDC_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(ledc_channel_config(&ch));

    backlight_set_percent(100);
}

esp_err_t display_init(spi_host_device_t host)
{
    backlight_init();

    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .dc_gpio_num       = PIN_DC,
        .cs_gpio_num       = PIN_CS,
        .pclk_hz           = LCD_CLK_HZ,
        .lcd_cmd_bits      = LCD_CMD_BITS,
        .lcd_param_bits    = LCD_PARAM_BITS,
        .spi_mode          = 0,
        .trans_queue_depth = 10,
    };
    ESP_RETURN_ON_ERROR(
        esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)host, &io_cfg, &io),
        TAG, "panel io init failed"
    );

    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = PIN_RST,
        .rgb_ele_order  = LCD_RGB_ELEMENT_ORDER_BGR,
        .bits_per_pixel = 16,
    };
    ESP_RETURN_ON_ERROR(
        esp_lcd_new_panel_st7735(io, &panel_cfg, &s_panel),
        TAG, "panel create failed"
    );

    ESP_ERROR_CHECK(esp_lcd_panel_reset(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(s_panel, true));
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(s_panel, true));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(s_panel, SC_LCD_MIRROR_X, SC_LCD_MIRROR_Y));
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(s_panel, 1, 26));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(s_panel, true));

    ESP_LOGI(TAG, "ST7735 ready");
    return ESP_OK;
}

static void (*s_post_blit_cb)(void);

void display_set_post_blit_cb(void (*cb)(void))
{
    s_post_blit_cb = cb;
}

static inline void sc_blit(int x0, int y0, int x1, int y1, const uint16_t *buf)
{
    esp_lcd_panel_draw_bitmap(s_panel, x0, y0, x1, y1, buf);
    if (s_post_blit_cb) s_post_blit_cb();
}

void display_fill_rect(int x, int y, int w, int h, uint16_t color_be)
{
    static uint16_t row[DISPLAY_W];
    int cols = w < DISPLAY_W ? w : DISPLAY_W;
    for (int i = 0; i < cols; i++) row[i] = color_be;
    for (int r = 0; r < h; r++)
        sc_blit(x, y + r, x + cols, y + r + 1, row);
}

void display_clear(uint16_t color_be)
{
    display_fill_rect(0, 0, DISPLAY_W, DISPLAY_H, color_be);
}

void display_draw_image(int x, int y, int w, int h, const uint16_t *pixels)
{

    sc_blit(x, y, x + w, y + h, pixels);
}

void display_draw_image_masked(int x, int y, int w, int h,
                               const uint16_t *pixels, const uint8_t *mask)
{

    for (int r = 0; r < h; r++) {
        const uint16_t *row = pixels + (size_t)r * w;
        int c = 0;
        while (c < w) {
            int i = r * w + c;
            if (!((mask[i >> 3] >> (7 - (i & 7))) & 1)) { c++; continue; }
            int start = c;
            while (c < w) {
                int j = r * w + c;
                if (!((mask[j >> 3] >> (7 - (j & 7))) & 1)) break;
                c++;
            }
            sc_blit(x + start, y + r, x + c, y + r + 1, row + start);
        }
    }
}

void display_draw_image_masked_scaled(int x, int y, int w, int h,
                                      const uint16_t *pixels, const uint8_t *mask,
                                      int scale)
{
    if (scale <= 1 || (w * scale) > DISPLAY_W) {
        display_draw_image_masked(x, y, w, h, pixels, mask);
        return;
    }
    uint16_t rowbuf[DISPLAY_W];
    for (int r = 0; r < h; r++) {
        const uint16_t *src = pixels + (size_t)r * w;
        int c = 0;
        while (c < w) {
            int i = r * w + c;
            if (!((mask[i >> 3] >> (7 - (i & 7))) & 1)) { c++; continue; }
            int start = c;
            while (c < w) {
                int j = r * w + c;
                if (!((mask[j >> 3] >> (7 - (j & 7))) & 1)) break;
                c++;
            }
            int span = c - start;
            for (int k = 0; k < span; k++) {
                uint16_t v = src[start + k];
                for (int s = 0; s < scale; s++) rowbuf[k * scale + s] = v;
            }
            int ox = x + start * scale;
            int ow = span * scale;
            for (int s = 0; s < scale; s++)
                sc_blit(ox, y + r * scale + s, ox + ow, y + r * scale + s + 1, rowbuf);
        }
    }
}

#define BADGE_X ((DISPLAY_W - SNIFFCHECK_STANDING_W) / 2)

void display_blit_brand(int y)
{
    display_draw_image_masked(BADGE_X, y, SNIFFCHECK_STANDING_W,
                              SNIFFCHECK_STANDING_H,
                              sniffcheck_standing, sniffcheck_standing_mask);
}

#define SITTING_X ((DISPLAY_W - SNIFFCHECK_SITTING_W) / 2)

void display_blit_sitting(int y)
{
    display_draw_image_masked(SITTING_X, y, SNIFFCHECK_SITTING_W,
                              SNIFFCHECK_SITTING_H,
                              sniffcheck_sitting, sniffcheck_sitting_mask);
}

void display_blit_sitting_scaled(int y, int scale)
{
    if (scale < 1) scale = 1;
    int w = SNIFFCHECK_SITTING_W * scale;
    int x = (DISPLAY_W - w) / 2;
    if (x < 0) x = 0;
    display_draw_image_masked_scaled(x, y, SNIFFCHECK_SITTING_W, SNIFFCHECK_SITTING_H,
                                     sniffcheck_sitting, sniffcheck_sitting_mask, scale);
}

static const uint8_t s_font5x7[95][5] = {
    {0x00,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x5F,0x00,0x00},
    {0x00,0x07,0x00,0x07,0x00},
    {0x14,0x7F,0x14,0x7F,0x14},
    {0x24,0x2A,0x7F,0x2A,0x12},
    {0x23,0x13,0x08,0x64,0x62},
    {0x36,0x49,0x55,0x22,0x50},
    {0x00,0x05,0x03,0x00,0x00},
    {0x00,0x1C,0x22,0x41,0x00},
    {0x00,0x41,0x22,0x1C,0x00},
    {0x08,0x2A,0x1C,0x2A,0x08},
    {0x08,0x08,0x3E,0x08,0x08},
    {0x00,0x50,0x30,0x00,0x00},
    {0x08,0x08,0x08,0x08,0x08},
    {0x00,0x60,0x60,0x00,0x00},
    {0x20,0x10,0x08,0x04,0x02},
    {0x3E,0x51,0x49,0x45,0x3E},
    {0x00,0x42,0x7F,0x40,0x00},
    {0x42,0x61,0x51,0x49,0x46},
    {0x21,0x41,0x45,0x4B,0x31},
    {0x18,0x14,0x12,0x7F,0x10},
    {0x27,0x45,0x45,0x45,0x39},
    {0x3C,0x4A,0x49,0x49,0x30},
    {0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36},
    {0x06,0x49,0x49,0x29,0x1E},
    {0x00,0x36,0x36,0x00,0x00},
    {0x00,0x56,0x36,0x00,0x00},
    {0x00,0x08,0x14,0x22,0x41},
    {0x14,0x14,0x14,0x14,0x14},
    {0x41,0x22,0x14,0x08,0x00},
    {0x02,0x01,0x51,0x09,0x06},
    {0x32,0x49,0x79,0x41,0x3E},
    {0x7E,0x11,0x11,0x11,0x7E},
    {0x7F,0x49,0x49,0x49,0x36},
    {0x3E,0x41,0x41,0x41,0x22},
    {0x7F,0x41,0x41,0x22,0x1C},
    {0x7F,0x49,0x49,0x49,0x41},
    {0x7F,0x09,0x09,0x01,0x01},
    {0x3E,0x41,0x41,0x51,0x32},
    {0x7F,0x08,0x08,0x08,0x7F},
    {0x00,0x41,0x7F,0x41,0x00},
    {0x20,0x40,0x41,0x3F,0x01},
    {0x7F,0x08,0x14,0x22,0x41},
    {0x7F,0x40,0x40,0x40,0x40},
    {0x7F,0x02,0x04,0x02,0x7F},
    {0x7F,0x04,0x08,0x10,0x7F},
    {0x3E,0x41,0x41,0x41,0x3E},
    {0x7F,0x09,0x09,0x09,0x06},
    {0x3E,0x41,0x51,0x21,0x5E},
    {0x7F,0x09,0x19,0x29,0x46},
    {0x46,0x49,0x49,0x49,0x31},
    {0x01,0x01,0x7F,0x01,0x01},
    {0x3F,0x40,0x40,0x40,0x3F},
    {0x1F,0x20,0x40,0x20,0x1F},
    {0x7F,0x20,0x18,0x20,0x7F},
    {0x63,0x14,0x08,0x14,0x63},
    {0x03,0x04,0x78,0x04,0x03},
    {0x61,0x51,0x49,0x45,0x43},
    {0x00,0x00,0x7F,0x41,0x41},
    {0x02,0x04,0x08,0x10,0x20},
    {0x41,0x41,0x7F,0x00,0x00},
    {0x04,0x02,0x01,0x02,0x04},
    {0x40,0x40,0x40,0x40,0x40},
    {0x00,0x01,0x02,0x04,0x00},
    {0x20,0x54,0x54,0x54,0x78},
    {0x7F,0x48,0x44,0x44,0x38},
    {0x38,0x44,0x44,0x44,0x20},
    {0x38,0x44,0x44,0x48,0x7F},
    {0x38,0x54,0x54,0x54,0x18},
    {0x08,0x7E,0x09,0x01,0x02},
    {0x08,0x54,0x54,0x54,0x3C},
    {0x7F,0x08,0x04,0x04,0x78},
    {0x00,0x44,0x7D,0x40,0x00},
    {0x20,0x40,0x44,0x3D,0x00},
    {0x00,0x7F,0x10,0x28,0x44},
    {0x00,0x41,0x7F,0x40,0x00},
    {0x7C,0x04,0x18,0x04,0x78},
    {0x7C,0x08,0x04,0x04,0x78},
    {0x38,0x44,0x44,0x44,0x38},
    {0x7C,0x14,0x14,0x14,0x08},
    {0x08,0x14,0x14,0x18,0x7C},
    {0x7C,0x08,0x04,0x04,0x08},
    {0x48,0x54,0x54,0x54,0x20},
    {0x04,0x3F,0x44,0x40,0x20},
    {0x3C,0x40,0x40,0x20,0x7C},
    {0x1C,0x20,0x40,0x20,0x1C},
    {0x3C,0x40,0x30,0x40,0x3C},
    {0x44,0x28,0x10,0x28,0x44},
    {0x0C,0x50,0x50,0x50,0x3C},
    {0x44,0x64,0x54,0x4C,0x44},
    {0x00,0x08,0x36,0x41,0x00},
    {0x00,0x00,0x7F,0x00,0x00},
    {0x00,0x41,0x36,0x08,0x00},
    {0x08,0x08,0x2A,0x1C,0x08},
};

void display_draw_string(int x, int y, const char *str,
                         uint16_t fg, uint16_t bg, uint8_t scale)
{
    if (!str || scale < 1) return;
    const int char_w = 5 * scale;
    const int char_h = 7 * scale;
    const int gap    = scale;

    for (; *str; str++) {

        if (x + char_w > DISPLAY_W) break;

        unsigned char c = (unsigned char)*str;
        if (c < 0x20 || c > 0x7E) c = '?';
        const uint8_t *glyph = s_font5x7[c - 0x20];

        for (int col = 0; col < 5; col++) {
            uint8_t column = glyph[col];
            for (int row = 0; row < 7; row++) {
                uint16_t color = (column & (1 << row)) ? fg : bg;
                if (color != bg || fg != bg) {
                    display_fill_rect(x + col * scale,
                                      y + row * scale,
                                      scale, scale, color);
                }
            }
        }

        if (fg != bg && x + char_w + gap <= DISPLAY_W)
            display_fill_rect(x + char_w, y, gap, char_h, bg);

        x += char_w + gap;
    }
}

#define ADV_FG   COLOR_WHITE
#define ADV_BG   COLOR_NEARBLACK

#define LILY_BOOT_BG   COLOR_NEARBLACK
#define LILY_BOOT_TEXT rgb565be(0x00, 0xFF, 0x00)

static void draw_centered(int x, int w, int y, const char *str,
                          uint16_t fg, uint16_t bg)
{
    int len    = (int)strlen(str);
    int str_px = len * 6;
    int cx     = x + (w - str_px) / 2;
    if (cx < x) cx = x;
    display_draw_string(cx, y, str, fg, bg, 1);
}

static void draw_centered2(int x, int w, int y, const char *str,
                           uint16_t fg, uint16_t bg)
{
    int len    = (int)strlen(str);
    int str_px = len * 12;
    int cx     = x + (w - str_px) / 2;
    if (cx < x) cx = x;
    display_draw_string(cx, y, str, fg, bg, 2);
}

void display_logo_frame(int frame)
{
    static const uint16_t *const logo_px[10] = {
        sniffcheck_logo_1, sniffcheck_logo_2, sniffcheck_logo_3,
        sniffcheck_logo_4, sniffcheck_logo_5, sniffcheck_logo_6,
        sniffcheck_logo_7, sniffcheck_logo_8, sniffcheck_logo_9,
        sniffcheck_logo_10,
    };
    static const uint8_t *const logo_mask[10] = {
        sniffcheck_logo_1_mask, sniffcheck_logo_2_mask, sniffcheck_logo_3_mask,
        sniffcheck_logo_4_mask, sniffcheck_logo_5_mask, sniffcheck_logo_6_mask,
        sniffcheck_logo_7_mask, sniffcheck_logo_8_mask, sniffcheck_logo_9_mask,
        sniffcheck_logo_10_mask,
    };
    int i = ((frame % 10) + 10) % 10;
    int x = (DISPLAY_W - SNIFFCHECK_LOGO_1_W) / 2;
    int y = (DISPLAY_H - SNIFFCHECK_LOGO_1_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    display_clear(COLOR_NEARBLACK);
    display_draw_image_masked(x, y, SNIFFCHECK_LOGO_1_W, SNIFFCHECK_LOGO_1_H,
                              logo_px[i], logo_mask[i]);
}

void display_splash(void)
{
    display_logo_frame(0);
}

static void draw_heart(int x, int y, uint8_t scale, uint16_t color)
{
    static const uint8_t HEART[4] = {
        0x0A,
        0x1F,
        0x0E,
        0x04,
    };
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 5; col++) {
            if (HEART[row] & (1 << (4 - col))) {
                display_fill_rect(x + col * scale, y + row * scale,
                                  scale, scale, color);
            }
        }
    }
}

void display_splash_credit(void)
{
    const uint16_t card_bg     = COLOR_WHITE;
    const uint16_t card_border = COLOR_BLACK;
    const uint16_t suit_red    = rgb565be(0xD5, 0x00, 0x00);

    display_clear(COLOR_NEARBLACK);

    const int card_x = 6, card_y = 8, card_w = 44, card_h = 64;
    display_fill_rect(card_x, card_y, card_w, card_h, card_border);
    display_fill_rect(card_x + 1, card_y + 1, card_w - 2, card_h - 2, card_bg);

    display_draw_string(card_x + 3, card_y + 3, "J", suit_red, card_bg, 1);
    draw_heart(card_x + 3, card_y + 12, 1, suit_red);

    display_draw_string(card_x + card_w - 8, card_y + card_h - 10,
                        "J", suit_red, card_bg, 1);
    draw_heart(card_x + card_w - 8, card_y + card_h - 18, 1, suit_red);

    int big_x = card_x + (card_w - 5 * 4) / 2;
    int big_y = card_y + (card_h - 4 * 4) / 2;
    draw_heart(big_x, big_y, 4, suit_red);

    const uint16_t label = rgb565be(160, 160, 160);
    const int name_x = card_x + card_w + 8;
    const int avail  = DISPLAY_W - name_x;
    int name_w = 7 * 12;
    int name_y = (DISPLAY_H - 16) / 2;
    int name_lx = name_x + (avail - name_w) / 2;
    draw_centered(name_x, avail, name_y - 11, "AUTHOR", label, COLOR_BLACK);
    display_draw_string(name_lx, name_y, "jLaHire",
                        COLOR_HEADER, COLOR_BLACK, 2);
}

void display_splash_credit2(void)
{
    const uint16_t fg   = COLOR_WHITE;
    const uint16_t bits = rgb565be(70, 70, 70);

    display_clear(COLOR_NEARBLACK);

    const int card_x = 6, card_y = 8, card_w = 44, card_h = 64;

    display_draw_string(card_x + 4,  card_y + 4,  "1011", bits, COLOR_BLACK, 1);
    display_draw_string(card_x + 14, card_y + 13, "0101", bits, COLOR_BLACK, 1);
    display_draw_string(card_x + 6,  card_y + 22, "1100", bits, COLOR_BLACK, 1);
    display_draw_string(card_x + 18, card_y + 31, "0110", bits, COLOR_BLACK, 1);
    display_draw_string(card_x + 8,  card_y + 40, "1001", bits, COLOR_BLACK, 1);

    const int pole_x   = card_x + 55;
    const int pole_top = card_y + 4;
    const int pole_h   = card_h - 8;
    display_fill_rect(pole_x, pole_top, 2, pole_h, fg);

    const int flag_right = pole_x;
    const int flag_w     = 30;
    const int flag_maxh  = 14;
    const int flag_cy    = pole_top + 2 + flag_maxh / 2;
    for (int c = 0; c < flag_w; c++) {
        int h = flag_maxh - (flag_maxh * c) / flag_w;
        if (h < 1) h = 1;
        display_fill_rect(flag_right - 1 - c, flag_cy - h / 2, 1, h, fg);
    }

    const uint16_t label = rgb565be(160, 160, 160);
    const int name_x = card_x + card_w + 8;
    const int avail  = DISPLAY_W - name_x;
    int name_w = 4 * 12;
    int name_y = (DISPLAY_H - 16) / 2;
    int name_lx = name_x + (avail - name_w) / 2;
    draw_centered(name_x, avail, name_y - 11, "CONTRIBUTOR", label, COLOR_BLACK);
    display_draw_string(name_lx, name_y, "Arty",
                        COLOR_HEADER, COLOR_BLACK, 2);
}

static void display_advisor_scan_stage(const char *subject);

void display_advisor_scanning(void)
{

    display_advisor_scan_stage("WiFi");
}

static void display_advisor_scan_stage(const char *subject)
{
    const uint16_t wait_color = rgb565be(160, 160, 160);
    display_clear(LILY_BOOT_BG);
    display_blit_brand(2);
    draw_centered2(0, DISPLAY_W, 24, "SNIFFING",      ADV_FG,         LILY_BOOT_BG);
    draw_centered2(0, DISPLAY_W, 44, subject,         LILY_BOOT_TEXT, LILY_BOOT_BG);
    draw_centered (0, DISPLAY_W, 64, "please wait...", wait_color,     LILY_BOOT_BG);
}

void display_advisor_scanning_wifi(void)
{
    display_advisor_scan_stage("WiFi");
}

void display_advisor_scanning_ble(void)
{
    const uint16_t wait_color = rgb565be(160, 160, 160);
    display_clear(LILY_BOOT_BG);
    display_blit_brand(2);
    draw_centered2(0, DISPLAY_W, 24, "SNIFFING",      ADV_FG,         LILY_BOOT_BG);
    draw_centered2(0, DISPLAY_W, 44, "BLUETOOTH",      LILY_BOOT_TEXT, LILY_BOOT_BG);
    draw_centered (0, DISPLAY_W, 64, "please wait...", wait_color,     LILY_BOOT_BG);
}

#define SCAN_WALK_H 36
#define SCAN_WALK_Y 2
#define SCAN_WALK_X_MIN 0
#define SCAN_WALK_X_MAX (DISPLAY_W - SNIFFCHECK_SNIFF_R1_W)

void display_scan_stage_static(const char *subject)
{
    const uint16_t wait_color = rgb565be(160, 160, 160);
    display_clear(LILY_BOOT_BG);
    display_fill_rect(0, SCAN_WALK_Y, DISPLAY_W, SCAN_WALK_H, LILY_BOOT_BG);
    draw_centered(0, DISPLAY_W, 42, "SNIFFING",      ADV_FG,         LILY_BOOT_BG);
    draw_centered(0, DISPLAY_W, 54, subject,         LILY_BOOT_TEXT, LILY_BOOT_BG);
    draw_centered(0, DISPLAY_W, 66, "please wait...", wait_color,    LILY_BOOT_BG);
}

#define WALK_TEXT_Y (SCAN_WALK_Y + SCAN_WALK_H + 2)
void display_walk_screen(const char *pup_name, uint32_t duration_sec,
                         uint16_t wifi, uint16_t ble, bool ending)
{
    (void)pup_name;
    const uint16_t dim   = rgb565be(160, 160, 160);
    const uint16_t wific = rgb565be(0x40, 0xC4, 0xF6);
    char timer[16], counts[28];

    if (duration_sec == 0 && wifi == 0 && ble == 0 && !ending) {
        display_clear(LILY_BOOT_BG);
        display_fill_rect(0, SCAN_WALK_Y, DISPLAY_W, SCAN_WALK_H, LILY_BOOT_BG);
    }

    unsigned mm = (unsigned)(duration_sec / 60), ss = (unsigned)(duration_sec % 60);
    snprintf(timer, sizeof(timer), "%u:%02u", mm, ss);
    snprintf(counts, sizeof(counts), "WiFi %u   BLE %u", (unsigned)wifi, (unsigned)ble);

    display_fill_rect(0, WALK_TEXT_Y, DISPLAY_W, DISPLAY_H - WALK_TEXT_Y, LILY_BOOT_BG);
    draw_centered2(0, DISPLAY_W, WALK_TEXT_Y,      timer,  ADV_FG, LILY_BOOT_BG);
    draw_centered (0, DISPLAY_W, WALK_TEXT_Y + 18, counts, wific,  LILY_BOOT_BG);
    draw_centered (0, DISPLAY_W, WALK_TEXT_Y + 28,
                   ending ? "join AP for report" : "[hold] end walk",
                   ending ? LILY_BOOT_TEXT : dim, LILY_BOOT_BG);
}

void display_scan_walk_frame(int x, bool facing_left, int frame)
{
    int i = frame & 1;
    display_fill_rect(0, SCAN_WALK_Y, DISPLAY_W, SCAN_WALK_H, LILY_BOOT_BG);
    if (facing_left) {
        const uint16_t *px = i ? sniffcheck_sniff_l2 : sniffcheck_sniff_l1;
        const uint8_t *mask = i ? sniffcheck_sniff_l2_mask : sniffcheck_sniff_l1_mask;
        display_draw_image_masked(x, SCAN_WALK_Y,
                                  SNIFFCHECK_SNIFF_L1_W, SNIFFCHECK_SNIFF_L1_H,
                                  px, mask);
    } else {
        const uint16_t *px = i ? sniffcheck_sniff_r2 : sniffcheck_sniff_r1;
        const uint8_t *mask = i ? sniffcheck_sniff_r2_mask : sniffcheck_sniff_r1_mask;
        display_draw_image_masked(x, SCAN_WALK_Y,
                                  SNIFFCHECK_SNIFF_R1_W, SNIFFCHECK_SNIFF_R1_H,
                                  px, mask);
    }
}

int display_scan_walk_x_min(void) { return SCAN_WALK_X_MIN; }
int display_scan_walk_x_max(void) { return SCAN_WALK_X_MAX; }

void display_score_dig_frame(int frame)
{
    static const uint16_t *const dig_px[3] = {
        SNIFFCHECK_DIG_1, SNIFFCHECK_DIG_2, SNIFFCHECK_DIG_3,
    };
    static const uint8_t *const dig_mask[3] = {
        SNIFFCHECK_DIG_1_mask, SNIFFCHECK_DIG_2_mask, SNIFFCHECK_DIG_3_mask,
    };
    int i = ((frame % 3) + 3) % 3;
    int x = (DISPLAY_W - SNIFFCHECK_DIG_1_W) / 2;
    if (x < 0) x = 0;
    display_fill_rect(0, SCAN_WALK_Y, DISPLAY_W, SCAN_WALK_H, LILY_BOOT_BG);
    display_draw_image_masked(x, SCAN_WALK_Y,
                              SNIFFCHECK_DIG_1_W, SNIFFCHECK_DIG_1_H,
                              dig_px[i], dig_mask[i]);
}

void display_advisor_scoring_results(uint16_t n_nets, uint16_t n_ble)
{
    char wifi_lbl[] = "WiFi:";
    char ble_lbl[] = "BLE:";
    char wifi_n[8];
    char ble_n[8];
    const int seg_gap = 8;

    display_clear(LILY_BOOT_BG);
    display_fill_rect(0, SCAN_WALK_Y, DISPLAY_W, SCAN_WALK_H, LILY_BOOT_BG);
    draw_centered(0, DISPLAY_W, 42, "DIGGING INTO",  ADV_FG,         LILY_BOOT_BG);
    draw_centered(0, DISPLAY_W, 54, "RESULTS",       LILY_BOOT_TEXT, LILY_BOOT_BG);

    snprintf(wifi_n, sizeof(wifi_n), "%u", (unsigned)n_nets);
    snprintf(ble_n, sizeof(ble_n), "%u", (unsigned)n_ble);

    int wifi_lbl_w = (int)strlen(wifi_lbl) * 6;
    int wifi_n_w   = (int)strlen(wifi_n) * 6;
    int ble_lbl_w  = (int)strlen(ble_lbl) * 6;
    int ble_n_w    = (int)strlen(ble_n) * 6;
    int total_w = wifi_lbl_w + wifi_n_w + seg_gap + ble_lbl_w + ble_n_w;
    int x = (DISPLAY_W - total_w) / 2;
    if (x < 0) x = 0;

    display_draw_string(x, 66, wifi_lbl, COLOR_HEADER, LILY_BOOT_BG, 1);
    display_draw_string(x + wifi_lbl_w, 66, wifi_n, COLOR_WHITE, LILY_BOOT_BG, 1);
    x += wifi_lbl_w + wifi_n_w + seg_gap;
    display_draw_string(x, 66, ble_lbl, COLOR_HEADER, LILY_BOOT_BG, 1);
    display_draw_string(x + ble_lbl_w, 66, ble_n, COLOR_WHITE, LILY_BOOT_BG, 1);
}

