#include "display.h"
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
#include "sniffcheck_safe.h"
#include "sniffcheck_ok.h"
#include "sniffcheck_caution.h"
#include "sniffcheck_avoid.h"
#include "sniffcheck_safe_lg.h"
#include "sniffcheck_ok_lg.h"
#include "sniffcheck_caution_lg.h"
#include "sniffcheck_avoid_lg.h"
#include "analyzer.h"
#include "physical_device_cluster.h"
#include "ble_scanner.h"
#include "ble_advise.h"
#include "apple_continuity.h"
#include "eui_db.h"
#include "vetter.h"
#include "wifi_scanner.h"
#include <stdarg.h>
#include "st7735.h"
#include "esp_attr.h"
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

#define PIN_CS   10
#define PIN_DC    3
#define PIN_RST   1
#define PIN_BL    0

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
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(s_panel, true, false));
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

#define FILL_CHUNK_ROWS 4
void display_fill_rect(int x, int y, int w, int h, uint16_t color_be)
{
    static EXT_RAM_BSS_ATTR __attribute__((aligned(64)))
        uint16_t buf[DISPLAY_W * FILL_CHUNK_ROWS];
    int cols = w < DISPLAY_W ? w : DISPLAY_W;
    if (cols <= 0 || h <= 0) return;
    int chunk_px = cols * FILL_CHUNK_ROWS;
    for (int i = 0; i < chunk_px; i++) buf[i] = color_be;
    for (int r = 0; r < h; r += FILL_CHUNK_ROWS) {
        int rows = (h - r) < FILL_CHUNK_ROWS ? (h - r) : FILL_CHUNK_ROWS;
        sc_blit(x, y + r, x + cols, y + r + rows, buf);
    }
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

void display_blit_verdict_scaled(int y, uint8_t verdict, int scale)
{

    const uint16_t *px;  const uint8_t *mask;
    switch (verdict) {
        case VERDICT_YELLOW: px = sniffcheck_ok;      mask = sniffcheck_ok_mask;      break;
        case VERDICT_ORANGE: px = sniffcheck_caution; mask = sniffcheck_caution_mask; break;
        case VERDICT_RED:    px = sniffcheck_avoid;   mask = sniffcheck_avoid_mask;   break;
        default:             px = sniffcheck_safe;    mask = sniffcheck_safe_mask;    break;
    }
    if (scale < 1) scale = 1;
    int x = (DISPLAY_W - SNIFFCHECK_SAFE_W * scale) / 2;
    if (x < 0) x = 0;
    display_draw_image_masked_scaled(x, y, SNIFFCHECK_SAFE_W, SNIFFCHECK_SAFE_H,
                                     px, mask, scale);
}

void display_blit_verdict(int y, uint8_t verdict)
{
    display_blit_verdict_scaled(y, verdict, 1);
}

void display_blit_verdict_lg(int y, uint8_t verdict)
{
    const uint16_t *px;  const uint8_t *mask;
    switch (verdict) {
        case VERDICT_YELLOW: px = sniffcheck_ok_lg;      mask = sniffcheck_ok_lg_mask;      break;
        case VERDICT_ORANGE: px = sniffcheck_caution_lg; mask = sniffcheck_caution_lg_mask; break;
        case VERDICT_RED:    px = sniffcheck_avoid_lg;   mask = sniffcheck_avoid_lg_mask;   break;
        default:             px = sniffcheck_safe_lg;    mask = sniffcheck_safe_lg_mask;    break;
    }
    int x = (DISPLAY_W - SNIFFCHECK_SAFE_LG_W) / 2;
    if (x < 0) x = 0;
    display_draw_image_masked(x, y, SNIFFCHECK_SAFE_LG_W, SNIFFCHECK_SAFE_LG_H,
                              px, mask);
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

static uint16_t verdict_band_color(uint8_t verdict)
{
    switch (verdict) {
    case 0:  return COLOR_SAFE;
    case 1:  return COLOR_OK;
    case 2:  return COLOR_CAUTION;
    default: return COLOR_DANGER;
    }
}

static uint16_t threat_band_color(uint8_t threat_level)
{
    return verdict_band_color(analyzer_threat_to_verdict(threat_level));
}
static const char *threat_word(uint8_t threat_level)
{
    return analyzer_verdict_label(analyzer_threat_to_verdict(threat_level));
}

static char conf_mark(uint8_t count)
{
    if (count >= 4) return 'H';
    if (count >= 2) return 'M';
    return 0;
}

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

void display_advisor_summary(uint16_t n_nets, uint16_t n_ble,
                             uint8_t n_2g, uint8_t n_5g,
                             const ap_score_t *best)
{
    char buf[32];

    display_fill_rect(0, 0, DISPLAY_W, 18, LILY_BOOT_BG);
    display_blit_brand(0);

    display_fill_rect(0, 18, DISPLAY_W, DISPLAY_H - 18, ADV_BG);

    snprintf(buf, sizeof(buf), "%u networks  %u BLE",
             (uint8_t)n_nets, (uint8_t)n_ble);
    draw_centered(0, DISPLAY_W, 20, buf, ADV_FG, ADV_BG);

    snprintf(buf, sizeof(buf), "2.4GHz:%u   5GHz:%u", n_2g, n_5g);
    draw_centered(0, DISPLAY_W, 29, buf, ADV_FG, ADV_BG);

    if (best) {
        char ssid[22];
        strlcpy(ssid, best->ssid, sizeof(ssid));
        draw_centered(0, DISPLAY_W, 38, ssid, threat_band_color(best->threat_level), ADV_BG);
    } else {
        draw_centered(0, DISPLAY_W, 38, "No safe network", COLOR_DANGER, ADV_BG);
    }

    if (best) {
        snprintf(buf, sizeof(buf), "ID:%u/100  %s",
                 best->identity_score, threat_word(best->threat_level));
        draw_centered(0, DISPLAY_W, 47, buf, ADV_FG, ADV_BG);
    }

    draw_centered(0, DISPLAY_W, 56, "Showing best pick...",
                  rgb565be(160, 160, 160), ADV_BG);

    draw_centered(0, DISPLAY_W, 65, "[BOOT]cycle [HOLD]rescan", ADV_FG, ADV_BG);
}

void display_advisor_recommend(const ap_score_t *ap, uint8_t rank,
                               uint16_t n_nets, uint8_t n_2g,
                               uint8_t n_5g, uint16_t n_ble)
{
    if (!ap) { display_advisor_no_safe(n_nets, n_2g, n_5g, n_ble); return; }

    uint16_t band_col = threat_band_color(ap->threat_level);
    char buf[32];
    char idx[16];
    int idx_px, idx_x;
    int ssid_area_w;

    display_fill_rect(0, 0, DISPLAY_W, 18, ADV_BG);
    uint16_t hdr_fg = COLOR_HEADER;

    snprintf(idx, sizeof(idx), "%u/%u", (unsigned)rank, (unsigned)n_nets);
    idx_px = (int)strlen(idx) * 6;
    idx_x = DISPLAY_W - idx_px - 2;
    if (idx_x < 0) idx_x = 0;
    ssid_area_w = idx_x - 4;
    if (ssid_area_w < 24) ssid_area_w = 24;

    int max_scale1 = ssid_area_w / 6;
    if (max_scale1 < 1) max_scale1 = 1;
    if (max_scale1 > 26) max_scale1 = 26;
    char ssid[27];
    snprintf(ssid, sizeof(ssid), "%.*s", max_scale1, ap->ssid);
    display_draw_string(2, 4, ssid, hdr_fg, ADV_BG, 1);

    display_draw_string(idx_x, 4, idx, rgb565be(160, 160, 160), ADV_BG, 1);
    display_fill_rect(0, 18, DISPLAY_W, DISPLAY_H - 18, ADV_BG);

    display_draw_string(2, 20, threat_word(ap->threat_level), band_col, ADV_BG, 1);
    snprintf(buf, sizeof(buf), "ID:%u/100", ap->identity_score);
    display_draw_string(DISPLAY_W - (int)strlen(buf) * 6 - 2, 20,
                        buf, ADV_FG, ADV_BG, 1);

    const char *auth_str = "OPEN";
    if      (ap->auth >= WIFI_AUTH_WPA3_PSK) auth_str = "WPA3";
    else if (ap->auth >= WIFI_AUTH_WPA2_PSK) auth_str = "WPA2";
    else if (ap->auth >= WIFI_AUTH_WPA_PSK)  auth_str = "WPA";

    char reason[22];
    bool warn_color = false;
    if (ap->pwnagotchi)             { strlcpy(reason, "WARN: pwnagotchi",      sizeof(reason)); warn_color = true; }
    else if (ap->auto_fail)         { strlcpy(reason, "WARN: auto-blocked",    sizeof(reason)); warn_color = true; }
    else if (ap->twin_detected)     { strlcpy(reason, "WARN: poss evil-twin",  sizeof(reason)); warn_color = true; }
    else if (ap->karma_suspect)     { strlcpy(reason, "WARN: karma probe",     sizeof(reason)); warn_color = true; }
    else if (ap->eui_flags & EUI_FLAG_INVESTIGATION) { strlcpy(reason, "FLAG: pen-test tool",  sizeof(reason)); warn_color = true; }
    else if (ap->eui_flags & EUI_FLAG_FCC_COVERED)   { strlcpy(reason, "FLAG: FCC covered",    sizeof(reason)); warn_color = true; }
    else if (ap->eui_flags & EUI_FLAG_DEV_MODULE)    { strlcpy(reason, "FLAG: dev module",     sizeof(reason)); warn_color = true; }
    else if (ap->eui_flags & EUI_FLAG_SURVEILLANCE)  { strlcpy(reason, "FLAG: surveillance",   sizeof(reason)); warn_color = true; }
    else if (ap->eui_flags & EUI_FLAG_MAKER)         { strlcpy(reason, "FLAG: maker board",    sizeof(reason)); warn_color = true; }

    else if (ap->vendor_mismatch)   { strlcpy(reason, "CAUTION: 2nd vendor",   sizeof(reason)); warn_color = true; }
    else {

        char l = conf_mark(ap->lldp_count);
        char c = conf_mark(ap->cdp_count);
        char d = conf_mark(ap->dhcp_count);
        if (l || c || d) {
            if (l && c && d)      snprintf(reason, sizeof(reason), "L2L3 L%c C%c D%c", l, c, d);
            else if (l && c)      snprintf(reason, sizeof(reason), "L2 LLDP:%c CDP:%c", l, c);
            else if (l && d)      snprintf(reason, sizeof(reason), "L2L3 LLDP:%c DHCP:%c", l, d);
            else if (c && d)      snprintf(reason, sizeof(reason), "L2L3 CDP:%c DHCP:%c", c, d);
            else if (l)           snprintf(reason, sizeof(reason), "L2 LLDP:%c", l);
            else if (c)           snprintf(reason, sizeof(reason), "L2 CDP:%c", c);
            else                  snprintf(reason, sizeof(reason), "L3 DHCP:%c", d);
        } else if (ap->vendor[0]) {
            strlcpy(reason, ap->vendor, sizeof(reason));
        } else {
            strlcpy(reason, "Vendor unknown", sizeof(reason));
        }
    }
    uint16_t reason_col = warn_color ? COLOR_CAUTION : ADV_FG;
    draw_centered(0, DISPLAY_W, 29, reason, reason_col, ADV_BG);

    snprintf(buf, sizeof(buf), "B:%s RSSI:%ddBm",
             ap->band_5g ? "5G" : "2G", (int)ap->rssi);
    draw_centered(0, DISPLAY_W, 38, buf, COLOR_HEADER, ADV_BG);

    snprintf(buf, sizeof(buf), "ENC:%s PMF:%c WPS:%c",
             auth_str,
             ap->rsn_pmf_required ? 'r' : 'n',
             ap->has_wps ? 'y' : 'n');
    draw_centered(0, DISPLAY_W, 47, buf, COLOR_OK, ADV_BG);

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    draw_centered(0, DISPLAY_W, 56, buf, rgb565be(160, 160, 160), ADV_BG);
}

void display_advisor_no_safe(uint16_t n_nets, uint8_t n_2g,
                             uint8_t n_5g, uint16_t n_ble)
{
    char buf[32];

    display_fill_rect(0, 0, DISPLAY_W, 18, COLOR_DANGER);
    draw_centered2(0, DISPLAY_W, 2, "NO SAFE WiFi", ADV_FG, COLOR_DANGER);

    display_fill_rect(0, 18, DISPLAY_W, DISPLAY_H - 18, ADV_BG);

    draw_centered(0, DISPLAY_W, 20, "USE CELLULAR DATA",      COLOR_DANGER,  ADV_BG);
    draw_centered(0, DISPLAY_W, 29, "All networks are risky", COLOR_CAUTION, ADV_BG);

    snprintf(buf, sizeof(buf), "%u networks scanned", (uint8_t)n_nets);
    draw_centered(0, DISPLAY_W, 38, buf, ADV_FG, ADV_BG);

    snprintf(buf, sizeof(buf), "2.4GHz:%u  5GHz:%u  BLE:%u", n_2g, n_5g, (uint8_t)n_ble);
    draw_centered(0, DISPLAY_W, 47, buf, ADV_FG, ADV_BG);

    draw_centered(0, DISPLAY_W, 56, "Stay off public WiFi", COLOR_CAUTION, ADV_BG);
    draw_centered(0, DISPLAY_W, 65, "[HOLD] rescan",        ADV_FG,        ADV_BG);
}

#define DETAILS_TITLE_FG   rgb565be(0x00, 0xFF, 0x00)
#define DETAILS_DIVIDER    rgb565be(0x00, 0x7A, 0x00)
#define DETAILS_PAGE_FG    rgb565be(160, 160, 160)
#define DETAILS_FOOTER_FG  rgb565be(120, 120, 120)
#define DETAILS_BG         COLOR_BLACK

static uint16_t pdc_class_row_color(uint8_t evclass)
{
    switch (evclass) {
    case PDC_CLASS_PHYSICAL_STRONG:    return COLOR_SAFE;
    case PDC_CLASS_PHYSICAL_CANDIDATE: return COLOR_OK;
    default:                           return DETAILS_PAGE_FG;
    }
}

void display_details_chrome_footer(const char *title, uint8_t page_idx,
                                   uint8_t page_total, const char *footer)
{
    display_clear(DETAILS_BG);

    display_fill_rect(0, 0, DISPLAY_W, 18, DETAILS_BG);
    if (title && title[0]) {
        display_draw_string(4, 5, title, DETAILS_TITLE_FG, DETAILS_BG, 1);
    }

    char ind[8];
    snprintf(ind, sizeof(ind), "%u/%u",
             (unsigned)(page_idx + 1), (unsigned)page_total);
    int ind_px = (int)strlen(ind) * 6;
    int ind_x  = DISPLAY_W - ind_px - 3;
    if (ind_x < 0) ind_x = 0;
    display_draw_string(ind_x, 5, ind, DETAILS_PAGE_FG, DETAILS_BG, 1);

    display_fill_rect(0, 18, DISPLAY_W, 1, DETAILS_DIVIDER);

    int foot_px = (int)strlen(footer) * 6;
    int foot_x  = (DISPLAY_W - foot_px) / 2;
    if (foot_x < 0) foot_x = 0;
    display_draw_string(foot_x, 70, footer, DETAILS_FOOTER_FG, DETAILS_BG, 1);
}

void display_details_chrome(const char *title, uint8_t page_idx, uint8_t page_total)
{

    display_details_chrome_footer(title, page_idx, page_total, "[1] more  [2] back");
}

#define DETAILS_COLS_PER_ROW 26
static const int DETAILS_ROW_Y[5] = { 20, 29, 38, 47, 56 };

static void det_row(uint8_t row, uint16_t fg, const char *text)
{
    if (row >= 5) return;
    display_draw_string(2, DETAILS_ROW_Y[row], text, fg, DETAILS_BG, 1);
}

static void det_rowf(uint8_t row, uint16_t fg, const char *fmt, ...)
{
    char buf[40];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    det_row(row, fg, buf);
}

static uint8_t det_row_wrap(uint8_t start_row, uint8_t max_rows,
                             uint16_t fg, const char *text)
{
    if (!text || !*text || !max_rows || start_row >= 5) return 0;
    if (start_row + max_rows > 5) max_rows = 5 - start_row;

    char buf[DETAILS_COLS_PER_ROW + 4];
    uint8_t rows = 0;
    const char *p = text;

    while (*p && rows < max_rows) {

        while (*p == ' ' || *p == '\n') p++;
        if (!*p) break;

        size_t remaining = strlen(p);
        bool last_row = (rows + 1 == max_rows);
        size_t cap = DETAILS_COLS_PER_ROW;
        bool will_overflow = last_row && remaining > cap;
        if (will_overflow) cap -= 3;

        size_t n = remaining < cap ? remaining : cap;
        if (n < remaining) {

            size_t bp = n;
            while (bp > 0 && p[bp] != ' ') bp--;
            if (bp > 8) n = bp;
        }

        memcpy(buf, p, n);
        buf[n] = '\0';

        while (n > 0 && buf[n-1] == ' ') buf[--n] = '\0';

        if (will_overflow) strlcat(buf, "...", sizeof(buf));

        det_row(start_row + rows, fg, buf);
        rows++;
        p += n;
    }
    return rows;
}

static uint16_t verdict_color(uint8_t v)
{
    switch (v) {
    case VERDICT_GREEN:  return COLOR_SAFE;
    case VERDICT_YELLOW: return COLOR_OK;
    case VERDICT_ORANGE: return COLOR_CAUTION;
    case VERDICT_RED:    return COLOR_DANGER;
    default:             return COLOR_WHITE;
    }
}

static uint16_t threat_color(uint8_t threat_level)
{
    return verdict_color(analyzer_threat_to_verdict(threat_level));
}

static uint16_t score_color(uint8_t score)
{
    if (score >= 90) return COLOR_SAFE;
    if (score >= 70) return COLOR_OK;
    if (score >= 50) return COLOR_CAUTION;
    return COLOR_DANGER;
}

static uint16_t rssi_color(int8_t rssi)
{
    if (rssi >= -75) return COLOR_SAFE;
    if (rssi >= -88) return COLOR_OK;
    return COLOR_OK;
}

static uint16_t auth_color(wifi_auth_mode_t a)
{
    switch (a) {
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA2_WPA3_PSK:   return COLOR_SAFE;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_ENTERPRISE:      return COLOR_SAFE;
    case WIFI_AUTH_WPA_WPA2_PSK:    return COLOR_OK;
    case WIFI_AUTH_WPA_PSK:         return COLOR_CAUTION;
    case WIFI_AUTH_WEP:             return COLOR_DANGER;
    case WIFI_AUTH_OPEN:            return COLOR_CAUTION;
    default:                         return COLOR_WHITE;
    }
}

static uint16_t class_color(uint8_t cls)
{
    switch (cls) {
    case EUI_CLASS_INVESTIGATION:
    case EUI_CLASS_ATTACK_SIGNAL:     return COLOR_DANGER;
    case EUI_CLASS_SURVEILLANCE_CAM:
    case EUI_CLASS_DEV_MODULE:        return COLOR_CAUTION;

    case EUI_CLASS_TRACKER:
    case EUI_CLASS_DRONE:
    case EUI_CLASS_SURVEILLANCE_OUI:
    case EUI_CLASS_MAKER_BOARD:       return COLOR_OK;
    case EUI_CLASS_ENTERPRISE_AP:
    case EUI_CLASS_STANDARDS:         return COLOR_SAFE;
    case EUI_CLASS_PHONE:
    case EUI_CLASS_MOBILE:
    case EUI_CLASS_TABLET:
    case EUI_CLASS_LAPTOP:
    case EUI_CLASS_AUDIO:
    case EUI_CLASS_WEARABLE:
    case EUI_CLASS_IOT_HUB:
    case EUI_CLASS_IOT_LEAF:
    case EUI_CLASS_BEACON:            return rgb565be(0x40, 0xC4, 0xF6);
    case EUI_CLASS_MEDICAL:
    case EUI_CLASS_VEHICLE:
    case EUI_CLASS_ACCESS_CONTROL:    return COLOR_OK;
    default:                          return DETAILS_PAGE_FG;
    }
}

static const char *auth_short(wifi_auth_mode_t a)
{
    switch (a) {
    case WIFI_AUTH_OPEN:            return "Open";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA+2";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2+3";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    case WIFI_AUTH_ENTERPRISE:      return "ENT";
    case WIFI_AUTH_WPA3_ENTERPRISE: return "WPA3-E";
    default:                         return "?";
    }
}

static void todo_append(char *buf, size_t sz, const char *s)
{
    if (buf[0]) strlcat(buf, " ", sz);
    strlcat(buf, s, sz);
}

static const char *lite_wifi_lead(uint8_t verdict)
{
    switch (verdict) {
    case VERDICT_GREEN:  return "Safe to connect.";
    case VERDICT_YELLOW: return "OK for light use.";
    case VERDICT_ORANGE: return "Risky network.";
    case VERDICT_RED:    return "Do not connect.";
    default:             return "Be cautious.";
    }
}

static void wifi_likely_kind(const ap_score_t *ap, char *out, size_t sz)
{
    switch (ap->device_class) {
    case EUI_CLASS_ENTERPRISE_AP:    strlcpy(out, "Business Wi-Fi network.", sz); return;
    case EUI_CLASS_CONSUMER_AP:
        if (ap->vendor[0]) snprintf(out, sz, "Home/office router (%.20s).", ap->vendor);
        else               strlcpy(out, "Home or office router.", sz);
        return;
    case EUI_CLASS_MOBILE:
    case EUI_CLASS_PHONE:            strlcpy(out, "Phone hotspot.", sz); return;
    case EUI_CLASS_SURVEILLANCE_CAM: strlcpy(out, "Security camera's Wi-Fi.", sz); return;
    case EUI_CLASS_SURVEILLANCE_OUI: strlcpy(out, "Maybe surveillance gear (OUI match).", sz); return;
    case EUI_CLASS_IOT_HUB:
    case EUI_CLASS_IOT_LEAF:         strlcpy(out, "Smart-home device.", sz); return;
    case EUI_CLASS_INVESTIGATION:
    case EUI_CLASS_ATTACK_SIGNAL:    strlcpy(out, "Hacking or test tool.", sz); return;
    case EUI_CLASS_MAKER_BOARD:
    case EUI_CLASS_DEV_MODULE:       strlcpy(out, "Hobby board, not a router.", sz); return;
    default: break;
    }
    if (mac_is_laa(ap->bssid)) {
        strlcpy(out, "Hidden maker ID - often a phone hotspot or travel router.", sz);
        return;
    }
    if (ap->vendor[0])                  snprintf(out, sz, "Wi-Fi router by %.24s.", ap->vendor);
    else if (ap->auth == WIFI_AUTH_OPEN) strlcpy(out, "Open public network.", sz);
    else                                 strlcpy(out, "Unidentified Wi-Fi device.", sz);
}

static bool wifi_todo_findings(const ap_score_t *ap, char *buf, size_t sz,
                               bool first_only)
{
    bool any = false, done = false;
    #define EMITW(cond, txt) do { \
        if (!done && (cond)) { todo_append(buf, sz, txt); any = true; \
                               if (first_only) done = true; } \
    } while (0)
    EMITW(ap->pwnagotchi, "Wi-Fi attack tool (pwnagotchi) capturing handshakes.");
    EMITW(ap->auto_fail || (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS),
          "Flagged as a known malicious network.");
    EMITW(ap->karma_suspect, "Answers to any network name (rogue AP).");
    EMITW(ap->open_clone || ap->twin_detected,
          "Impersonates a nearby network (evil twin).");
    EMITW(ap->vendor_mismatch, "Another maker's hardware shares this network name — verify ownership.");
    EMITW(ap->deauth_flood, "Nearby devices are being kicked off Wi-Fi.");
    EMITW((ap->eui_flags & EUI_FLAG_INVESTIGATION) != 0,
          "Hardware matches a known pen-test tool.");
    EMITW(ap->auth == WIFI_AUTH_OPEN, "Open: traffic is unencrypted and readable.");
    #undef EMITW
    return any;
}

static void wifi_todo_note(const ap_score_t *ap, char *buf, size_t sz, bool adv)
{
    buf[0] = '\0';

    uint8_t v = analyzer_threat_to_verdict(ap->threat_level);
    switch (v) {
    case VERDICT_YELLOW: todo_append(buf, sz, "Fine for browsing, but skip logins and banking."); break;
    case VERDICT_ORANGE: todo_append(buf, sz, "Prefer cellular data."); break;
    case VERDICT_RED:    todo_append(buf, sz, "Use your cellular data instead."); break;
    default:

        if (!adv && ap->auth != WIFI_AUTH_OPEN) {
            if (mac_is_laa(ap->bssid))
                todo_append(buf, sz, "If it is your hotspot, connect. If not, pick a name you recognize.");
            else
                todo_append(buf, sz, "Connect with the password you normally use for it.");
        }
        break;
    }

    bool found = wifi_todo_findings(ap, buf, sz,!adv);

    if (!found && v == VERDICT_GREEN) {
        if (ap->vendor[0]) {
            char m[48];
            snprintf(m, sizeof(m), "Recognized maker: %.20s.", ap->vendor);
            todo_append(buf, sz, m);
            todo_append(buf, sz, "Confirm the exact name with the owner.");
        } else {
            todo_append(buf, sz, "Confirm the exact name with the owner.");
        }
    }

    if (ap->has_wps && (adv || (!found && v != VERDICT_GREEN)))
        todo_append(buf, sz, "WPS on (minor risk).");

    if (adv && ap->pmkid_exposed)
        todo_append(buf, sz, "Password is offline-crackable; WPA3 avoids it.");
}

static bool eui_flags_to_str(uint16_t f, char *buf, size_t sz)
{
    buf[0] = '\0';
    static const struct { uint16_t bit; const char *tok; } MAP[] = {
        { EUI_FLAG_KNOWN_MALICIOUS,  "MALICIOUS" },
        { EUI_FLAG_INVESTIGATION,    "INVEST"    },
        { EUI_FLAG_SURVEILLANCE,     "SURVEIL"   },
        { EUI_FLAG_FCC_COVERED,      "FCC_COV"   },
        { EUI_FLAG_DEV_MODULE,       "DEVMOD"    },
        { EUI_FLAG_MAKER,            "MAKER"     },
        { EUI_FLAG_STANDARDS,        "STD"       },
        { EUI_FLAG_ENTERPRISE_GRADE, "ENT"       },
        { EUI_FLAG_CONSUMER_GRADE,   "CONSUMER"  },
        { EUI_FLAG_IOT_DEVICE,       "IOT"       },
        { EUI_FLAG_MOBILE_DEVICE,    "MOBILE"    },
        { EUI_FLAG_FCC_APPROVED,     "FCC_OK"    },
        { EUI_FLAG_PRIVATE_ASSIGN,   "PRIV"      },
        { EUI_FLAG_REGISTRY_CID,     "CID"       },
        { EUI_FLAG_REGISTRY_OUI28,   "OUI28"     },
        { EUI_FLAG_REGISTRY_OUI36,   "OUI36"     },
    };
    for (size_t i = 0; i < sizeof(MAP) / sizeof(MAP[0]); i++) {
        if (f & MAP[i].bit) {
            if (buf[0]) strlcat(buf, " ", sz);
            strlcat(buf, MAP[i].tok, sz);
        }
    }
    return buf[0] != '\0';
}

uint8_t display_details_wifi_adv(const ap_score_t *ap,
                                  const vetter_result_t *v,
                                  const ble_results_t *ble,
                                  uint8_t page_idx)
{
    const uint8_t TOTAL = 11;
    if (!ap) { display_details_chrome("WIFI", 0, TOTAL); return TOTAL; }
    uint8_t p = page_idx % TOTAL;

    char title[24];
    static const char *page_titles[] = {
        "ID", "SECURITY", "IDENTITY", "THREAT",
        "L2/L3", "META", "VETTER", "VET DETAIL", "SUMMARY", "LINK", "WHAT TO DO",
    };
    snprintf(title, sizeof(title), "WIFI %s", page_titles[p]);
    display_details_chrome_footer(title, p, TOTAL, "[1] more  [2] next");

    switch (p) {
    case 0: {
        uint8_t row = det_row_wrap(0, 2, COLOR_WHITE, ap->ssid);
        if (row < 5) {
            det_rowf(row++, DETAILS_PAGE_FG,
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     ap->bssid[0], ap->bssid[1], ap->bssid[2],
                     ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        }
        if (row < 5) {
            det_rowf(row++, ap->vendor[0] ? COLOR_WHITE : COLOR_CAUTION,
                     "%-15.20s /%u",
                     ap->vendor[0] ? ap->vendor : "Unknown",
                     (unsigned)(ap->mac_match_len ? ap->mac_match_len : 24));
        }

        if (row < 4) {
            det_rowf(row++, class_color(ap->device_class), "%-8s %s",
                     eui_class_label(ap->device_class),
                     ap->band_5g ? "5GHz" : "2.4GHz");
        }
        if (row < 5) {
            det_rowf(row, threat_color(ap->threat_level),
                     "ID:%u thr:%s rssi:%d", ap->identity_score,
                     threat_word(ap->threat_level), (int)ap->rssi);
        }
        break;
    }
    case 1: {
        det_rowf(0, auth_color(ap->auth), "Auth: %s", auth_short(ap->auth));
        det_rowf(1, ap->rsn_pmf_required ? COLOR_SAFE : DETAILS_PAGE_FG,
                 "PMF: req=%s cap=%s",
                 ap->rsn_pmf_required ? "Y" : "N",
                 ap->has_rsn ? "Y" : "?");
        det_rowf(2, (ap->has_wps || ap->pmkid_exposed) ? COLOR_OK : COLOR_SAFE,
                 "WPS:%s crack:%s", ap->has_wps ? "on" : "off",
                 ap->pmkid_exposed ? "yes" : "no");
        if (ap->rsn_group_suite) {
            det_rowf(3, DETAILS_PAGE_FG,
                     "RSN grp: %02X%02X%02X-%02u",
                     ap->rsn_group_oui[0], ap->rsn_group_oui[1],
                     ap->rsn_group_oui[2], ap->rsn_group_suite);
        }
        det_rowf(4, DETAILS_PAGE_FG,
                 "Cntry: %s",
                 ap->country_code[0] ? ap->country_code : "?");
        break;
    }
    case 2: {
        det_rowf(0, score_color(ap->identity_score),
                 "IDENTITY: %u/100", ap->identity_score);
        det_rowf(1, COLOR_WHITE, "conf: %u/100", ap->identity_conf);
        det_rowf(2, COLOR_WHITE, "base:%u  hygiene:-%u",
                 ap->base_quality, ap->hygiene);
        if (ap->mac_match_len)
            det_rowf(3, DETAILS_PAGE_FG, "vendor match: /%u", ap->mac_match_len);
        det_rowf(4, threat_color(ap->threat_level),
                 "threat: %s", threat_word(ap->threat_level));
        break;
    }
    case 3: {
        det_rowf(0, threat_color(ap->threat_level),
                 "THREAT: %s", threat_word(ap->threat_level));

        char sig[96] = "";
        if (ap->pwnagotchi)     strlcat(sig, "PWNAGOTCHI ", sizeof(sig));
        if (ap->open_clone)     strlcat(sig, "CLONE ",  sizeof(sig));
        if (ap->karma_suspect)  strlcat(sig, "KARMA ",  sizeof(sig));
        if (ap->deauth_flood)   strlcat(sig, "DEAUTH ", sizeof(sig));
        if (ap->twin_detected)  strlcat(sig, "TWIN ",   sizeof(sig));
        if (ap->vendor_mismatch)strlcat(sig, "VMISMATCH ", sizeof(sig));
        if (ap->has_wps)        strlcat(sig, "WPS ",    sizeof(sig));
        if (ap->has_rsn && !ap->rsn_pmf_required) strlcat(sig, "NOPMF ", sizeof(sig));
        if (sig[0])
            det_row_wrap(1, 2, threat_color(ap->threat_level), sig);

        char fl[96];
        eui_flags_to_str(ap->eui_flags, fl, sizeof(fl));
        if (fl[0]) {
            char full[112];
            snprintf(full, sizeof(full), "flags: %s", fl);
            det_row_wrap(3, 2, DETAILS_PAGE_FG, full);
        }
        break;
    }
    case 4: {
        det_rowf(0, ap->l2l3_signal_count > 0 ? COLOR_SAFE : DETAILS_PAGE_FG,
                 "CDP:%u  LLDP:%u  DHCP:%u",
                 ap->cdp_count, ap->lldp_count, ap->dhcp_count);
        if (ap->cdp_device_id[0])
            det_rowf(1, COLOR_SAFE, "cdp: %s", ap->cdp_device_id);
        if (ap->lldp_system_name[0])
            det_rowf(2, COLOR_SAFE, "sys: %s", ap->lldp_system_name);
        if (ap->dhcp_vendor_class[0])
            det_rowf(3, COLOR_SAFE, "dhcp: %s", ap->dhcp_vendor_class);
        det_rowf(4, ap->l2l3_signal_count > 0 ? COLOR_SAFE : DETAILS_PAGE_FG,
                 "signals: %u/3", ap->l2l3_signal_count);
        break;
    }
    case 5: {
        uint8_t row = 0;
        for (uint8_t k = 0; k < ap->vendor_ie_count && row < 3; k++) {
            if (ap->vendor_ie_names[k])
                det_rowf(row++, COLOR_SAFE, "IE: %s", ap->vendor_ie_names[k]);
            else
                det_rowf(row++, DETAILS_PAGE_FG,
                         "IE: %02X:%02X:%02X",
                         ap->vendor_ie_ouis[k][0],
                         ap->vendor_ie_ouis[k][1],
                         ap->vendor_ie_ouis[k][2]);
        }
        if (ap->wps_manufacturer[0]) {

            uint16_t wf = 0; uint8_t wc = 0;
            const char *resolved = eui_lookup_wps(ap->wps_manufacturer, &wf, &wc);
            det_rowf(row++, COLOR_WHITE, "WPS: %s",
                     resolved ? resolved : ap->wps_manufacturer);
        }
        det_rowf(4, DETAILS_PAGE_FG, "IE# %08lX",
                 (unsigned long)ap->ie_pattern_hash);
        break;
    }
    case 6: {
        if (v) {
            det_rowf(0, COLOR_WHITE,
                     "ssid:%-3s bloc:%-3s cry:%-3s",
                     v->check[0] == VETTER_PASS  ? "ok"  :
                     v->check[0] == VETTER_WARN  ? "warn" : "AL!",
                     v->check[1] == VETTER_PASS  ? "ok"  : "AL!",
                     v->check[2] == VETTER_PASS  ? "ok"  :
                     v->check[2] == VETTER_WARN  ? "warn" : "AL!");
            det_rowf(1, COLOR_WHITE,
                     "laa:%-3s twn:%-3s cln:%-3s",
                     v->check[3] == VETTER_PASS  ? "ok"  :
                     v->check[3] == VETTER_WARN  ? "warn" : "AL!",
                     v->check[4] == VETTER_PASS  ? "ok"  : "AL!",
                     v->check[5] == VETTER_PASS  ? "ok"  : "AL!");
            det_rowf(2, v->blocked ? COLOR_DANGER : COLOR_SAFE,
                     "blocked: %s", v->blocked ? "YES" : "no");
        } else {
            det_row(0, DETAILS_PAGE_FG, "Vetter not run.");
        }
        if (ap->karma_suspect)  det_row(3, COLOR_DANGER, "KARMA suspect.");
        if (ap->deauth_flood || ap->pwnagotchi)
            det_row(4, COLOR_DANGER, ap->pwnagotchi ? "PWNAGOTCHI tool." : "DEAUTH FLOOD.");
        break;
    }
    case 7: {
        if (!v) {
            det_row(0, DETAILS_PAGE_FG, "Vetter not run.");
            break;
        }
        uint8_t row = 0;
        static const char *check_short[6] = {
            "ssid", "bloc", "cryp", "laa", "twin", "cln",
        };
        for (uint8_t i = 0; i < 6 && row < 5; i++) {
            const char *reason = vetter_check_reason(ap, v, i);
            if (!reason) continue;
            uint16_t color = (v->check[i] == VETTER_ALERT) ? COLOR_DANGER
                                                            : COLOR_OK;
            det_rowf(row++, color, "%s: %s", check_short[i], reason);
        }
        if (row == 0) det_row(0, COLOR_SAFE, "All checks PASS.");
        break;
    }
    case 8: {
        const char *s = v ? v->summary : "(no summary)";
        if (!s || !s[0]) s = "(empty)";
        det_row_wrap(0, 5, COLOR_WHITE, s);
        break;
    }
    case 9: {
        pdc_peer_t peers[4];
        uint8_t total = 0;
        uint8_t np = pdc_peers_of_mac(PDC_NODE_WIFI, ap->bssid,
                                      peers, 4, &total);
        if (np == 0) {
            det_row(0, DETAILS_PAGE_FG, "No cluster peers.");
            det_row_wrap(2, 3, DETAILS_PAGE_FG,
                         "No radio shares hardware evidence with this AP.");
            break;
        }
        det_rowf(0, COLOR_SAFE, "Cluster: %u link%s", (unsigned)total,
                 total == 1 ? "" : "s");
        for (uint8_t i = 0; i < np; i++) {
            const pdc_peer_t *p = &peers[i];
            char id[16];

            if (p->kind == PDC_NODE_BLE && ble && p->idx < ble->count &&
                ble->devices[p->idx].name[0]) {
                snprintf(id, sizeof(id), "%.12s", ble->devices[p->idx].name);
            } else {
                snprintf(id, sizeof(id), "%02X:%02X:%02X",
                         p->mac[3], p->mac[4], p->mac[5]);
            }
            det_rowf(1 + i, pdc_class_row_color(p->evclass), "%c %2u%% %-8s %s",
                     p->kind == PDC_NODE_WIFI ? 'W' : 'B',
                     (unsigned)p->confidence,
                     pdc_evidence_short(p->evidence), id);
        }
        break;
    }
    case 10: {
        char note[256];
        wifi_todo_note(ap, note, sizeof(note),true);
        uint8_t tv = analyzer_threat_to_verdict(ap->threat_level);
        uint8_t row = det_row_wrap(0, 1, verdict_color(tv), lite_wifi_lead(tv));
        if (note[0] && row < 5)
            det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, note);
        break;
    }
    }
    return TOTAL;
}

uint8_t display_details_wifi_lite(const ap_score_t *ap,
                                   const vetter_result_t *v,
                                   uint8_t page_idx)
{
    const uint8_t TOTAL = 3;
    (void)v;
    if (!ap) { display_details_chrome("WIFI", 0, TOTAL); return TOTAL; }
    uint8_t p = page_idx % TOTAL;

    static const char *titles[] = { "ABOUT", "WHY?", "WHAT TO DO" };

    display_details_chrome_footer(titles[p], p, TOTAL, "[1] page  [2] next");

    switch (p) {
    case 0: {
        uint8_t row = det_row_wrap(0, 2, COLOR_WHITE, ap->ssid);

        if (row < 3) {
            char kind[64];
            wifi_likely_kind(ap, kind, sizeof(kind));
            row += det_row_wrap(row, (uint8_t)(3 - row), DETAILS_PAGE_FG, kind);
        }

        display_blit_verdict(47, analyzer_threat_to_verdict(ap->threat_level));
        break;
    }
    case 1: {
        char lines[2][64];
        uint8_t n = vetter_lite_reasons(ap, lines);
        uint8_t row = 0;
        if (n >= 1) {

            uint8_t cap = (n >= 2) ? 2 : 5;
            row += det_row_wrap(row, cap, COLOR_WHITE, lines[0]);
        }
        if (n >= 2 && row < 5) {
            if (row < 4) row++;
            row += det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, lines[1]);
        }
        if (n == 0) det_row(0, DETAILS_PAGE_FG, "No reason data.");
        break;
    }
    case 2: {
        char note[192];
        wifi_todo_note(ap, note, sizeof(note),false);
        uint8_t tv = analyzer_threat_to_verdict(ap->threat_level);
        uint8_t row = det_row_wrap(0, 1, verdict_color(tv), lite_wifi_lead(tv));
        if (note[0] && row < 5)
            det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, note);
        break;
    }
    }
    return TOTAL;
}

static const char *lite_ble_lead(uint8_t cls);
static void ble_todo_note(const ble_device_t *d, uint8_t cls,
                          char *buf, size_t sz, bool adv);

static const char *addr_subtype_str(ble_addr_subtype_t s)
{
    switch (s) {
    case BLE_ADDR_SUB_PUBLIC:        return "Public";
    case BLE_ADDR_SUB_STATIC_RANDOM: return "Static";
    case BLE_ADDR_SUB_RPA:           return "RPA";
    case BLE_ADDR_SUB_NRPA:          return "NRPA";
    default:                          return "?";
    }
}

uint8_t display_details_ble_adv(const ble_device_t *d,
                                const ap_score_t *scores, uint16_t count,
                                uint8_t page_idx)
{

    const uint8_t TOTAL = (d && d->has_rid) ? 11 : 10;
    if (!d) { display_details_chrome("BLE", 0, TOTAL); return TOTAL; }
    uint8_t p = page_idx % TOTAL;

    static const char *titles[] = {
        "BLE ID", "BT IDs", "CATALOG",
        "APPLE/MS/FP", "UUIDS", "SIGNAL", "SCORE", "EVIDENCE", "LINK",
        "WHAT TO DO", "DRONE",
    };
    display_details_chrome_footer(titles[p], p, TOTAL, "[1] more  [2] next");

    switch (p) {
    case 0: {
        uint8_t row = 0;
        if (d->name[0]) {
            char namebuf[64];
            snprintf(namebuf, sizeof(namebuf), "\"%.60s\"", d->name);
            row = det_row_wrap(0, 2, COLOR_WHITE, namebuf);
        }
        if (row < 5) {
            det_rowf(row++, DETAILS_PAGE_FG,
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     d->addr[0],d->addr[1],d->addr[2],
                     d->addr[3],d->addr[4],d->addr[5]);
        }
        if (row < 5) {
            det_rowf(row++, d->vendor[0] ? COLOR_WHITE : COLOR_CAUTION,
                     "%-6.6s %.24s",
                     addr_subtype_str(d->addr_subtype),
                     d->vendor[0] ? d->vendor : "Unknown");
        }

        if (row < 4) {
            uint8_t eff_cls = ble_effective_class(d);
            det_rowf(row++, class_color(eff_cls), "/%u %s [%c]",
                     (unsigned)(d->mac_match_len ? d->mac_match_len : 24),
                     eui_class_label(eff_cls),
                     ble_class_conf_letter(d));
        }
        if (row < 5) {
            det_rowf(row, threat_color(d->threat_level),
                     "rssi:%d dist:%udm",
                     (int)d->rssi,
                     (unsigned)(d->distance_dm == 0xFFFF ? 0 : d->distance_dm));
        }
        break;
    }
    case 1: {
        det_rowf(0, COLOR_WHITE, "cid: 0x%04X",
                 (unsigned)d->mfg_company_id);
        uint8_t row = 1;
        if (d->company_name[0]) {
            row = 1 + det_row_wrap(1, 2, DETAILS_PAGE_FG, d->company_name);
        }
        if (row < 5) {
            det_rowf(row++, DETAILS_PAGE_FG, "pl: %02X %02X",
                     d->mfg_payload[0], d->mfg_payload[1]);
        }
        if (row < 5) {
            det_rowf(row++, DETAILS_PAGE_FG, "u16:%u u32:%u u128:%u",
                     d->num_uuids16, d->num_uuids32, d->num_uuids128);
        }
        if (row < 5) {
            det_rowf(row, DETAILS_PAGE_FG, "scannable: %s",
                     d->scannable ? "Y" : "N");
        }
        break;
    }
    case 2: {
        if (d->mfg_rule_name) {
            det_row(0, COLOR_SAFE, "rule:");
            uint8_t r = det_row_wrap(1, 2, COLOR_WHITE, d->mfg_rule_name);
            uint8_t next = 1 + r;
            if (next < 5) {
                det_rowf(next++, class_color(d->mfg_rule_class), "class: %s",
                         eui_class_label(d->mfg_rule_class));
            }
            if (next < 5) {
                det_rowf(next, DETAILS_PAGE_FG, "subtype: 0x%02X",
                         d->mfg_rule_subtype);
            }
        } else {
            det_row(0, DETAILS_PAGE_FG, "No catalog rule match.");
        }
        break;
    }
    case 3: {
        uint8_t row = 0;
        if (d->apple_subtype_name) {

            const char *label = (d->mfg_rule_name && d->mfg_company_id == 0x004C)
                              ? d->mfg_rule_name : d->apple_subtype_name;
            det_rowf(row++, COLOR_WHITE, "Apple 0x%02X:", d->apple_subtype);
            det_rowf(row++, DETAILS_PAGE_FG, "%.32s", label);

            const char *state_lbl = NULL;
            if (d->apple_subtype == 0x10) {
                state_lbl = apple_nearby_state_label(d->apple_state);
            } else if (d->apple_subtype == 0x12) {
                state_lbl = apple_airtag_state_label(d->apple_state,
                                                     d->mfg_payload[1]);
            }
            if (state_lbl && state_lbl[0] && row < 5) {
                det_rowf(row++, COLOR_OK, "st: %.26s", state_lbl);
            }
            if (d->apple_evidence[0] && row < 5) {
                det_rowf(row++, DETAILS_PAGE_FG, "ev: %.26s", d->apple_evidence);
            }
        }
        if (d->ms_subtype_name && row < 5) {
            det_rowf(row++, COLOR_WHITE, "MS: %.30s", d->ms_subtype_name);
        }
        if (d->fastpair_name && row < 5) {
            det_rowf(row++, COLOR_WHITE, "FP 0x%06lX:",
                     (unsigned long)d->fastpair_model_id);
            if (row < 5)
                det_rowf(row++, DETAILS_PAGE_FG, "%.32s", d->fastpair_name);
        }
        if (!d->apple_subtype_name && !d->ms_subtype_name && !d->fastpair_name)
            det_row(0, DETAILS_PAGE_FG, "No subtype / Fast Pair.");
        break;
    }
    case 4: {
        uint8_t row = 0;
        if (d->uuid32_name && row < 5) {
            det_rowf(row++, COLOR_WHITE, "u32: %.30s", d->uuid32_name);
        }
        if (d->uuid128_name && row < 5) {
            det_row(row++, COLOR_WHITE, "u128:");
            if (row < 5) {
                row += det_row_wrap(row, 2, DETAILS_PAGE_FG, d->uuid128_name);
            }
        }
        if (d->name_rule_name && row < 5) {
            det_row(row++, COLOR_OK, "name rule:");
            if (row < 5) {
                row += det_row_wrap(row, 2, DETAILS_PAGE_FG, d->name_rule_name);
            }
        }
        if (row == 0) det_row(0, DETAILS_PAGE_FG, "No UUID / name match.");
        break;
    }
    case 5: {
        det_rowf(0, rssi_color(d->rssi), "rssi:  %d dBm", (int)d->rssi);
        det_rowf(1, COLOR_WHITE, "txpwr: %d",
                 d->tx_power == 127 ? -59 : (int)d->tx_power);
        det_rowf(2, COLOR_WHITE, "dist:  %u dm (%s)",
                 (unsigned)(d->distance_dm == 0xFFFF ? 0 : d->distance_dm),
                 ble_proximity_label(d->distance_dm));
        const char *phy = (d->prim_phy == 1) ? "1M"
                        : (d->prim_phy == 2) ? "2M"
                        : (d->prim_phy == 3) ? "Coded"
                        : "?";
        uint16_t phy_col = (d->prim_phy == 3) ? COLOR_OK : COLOR_WHITE;
        det_rowf(3, phy_col, "phy:   %s", phy);
        if (d->is_airtag) det_row(4, COLOR_OK, "is_airtag: YES");
        break;
    }
    case 6: {
        uint16_t t = d->trust_q88 ? d->trust_q88 : 256;
        uint16_t t_int  = t >> 8;
        uint16_t t_frac = ((t & 0xFF) * 100) >> 8;
        det_rowf(0, COLOR_WHITE,
                 "base:%u  trust:%u.%02u",
                 d->base_quality, (unsigned)t_int, (unsigned)t_frac);
        det_rowf(1, COLOR_WHITE,
                 "ident:%u  conf:%u",
                 d->identity_score, d->identity_conf);
        det_rowf(2, threat_color(d->threat_level), "threat: %s",
                 threat_word(d->threat_level));
        uint16_t combined = d->eui_flags | d->bt_company_flags |
                            d->mfg_rule_flags | d->uuid128_flags |
                            d->name_rule_flags;
        char fl[64];

        if (eui_flags_to_str(combined, fl, sizeof(fl)))
            det_rowf(3, DETAILS_PAGE_FG, "flags: %s", fl);
        det_rowf(4, DETAILS_PAGE_FG, "cls:%c vnd:%c src:%s",
                 ble_class_conf_letter(d), ble_vendor_conf_letter(d),
                 ble_class_source_label(d->class_source));
        break;
    }
    case 7: {
        ble_evidence_t ev[12];
        uint8_t ne = ble_score_trail(d, ev, 12);
        if (ne == 0) { det_row(0, COLOR_SAFE, "No scored signals."); break; }

        uint8_t shown = ne > 5 ? 4 : ne;
        for (uint8_t i = 0; i < shown; i++) {
            char line[40];
            uint16_t col;
            if (ev[i].kind == BLE_EV_TRUST) {

                unsigned mi = ((unsigned)ev[i].delta >> 8) & 0x0F;
                unsigned mf = (((unsigned)ev[i].delta & 0xFF) * 100) >> 8;
                snprintf(line, sizeof(line), "x%u.%02u %.18s",
                         mi, mf, ev[i].label);
                col = COLOR_OK;
            } else {
                snprintf(line, sizeof(line), "%+d %.18s",
                         (int)ev[i].delta, ev[i].label);
                col = (ev[i].kind == BLE_EV_PENALTY) ? COLOR_DANGER : COLOR_WHITE;
            }
            det_row(i, col, line);
        }
        if (ne > 5)
            det_rowf(4, DETAILS_PAGE_FG, "+%u more", (unsigned)(ne - 4));
        break;
    }
    case 8: {
        pdc_peer_t peers[4];
        uint8_t total = 0;
        uint8_t np = pdc_peers_of_mac(PDC_NODE_BLE, d->addr,
                                      peers, 4, &total);
        if (np == 0) {
            det_row(0, DETAILS_PAGE_FG, "No cluster peers.");
            det_row_wrap(2, 3, DETAILS_PAGE_FG,
                         "No radio shares hardware evidence with this device.");
            break;
        }
        det_rowf(0, COLOR_SAFE, "Cluster: %u link%s", (unsigned)total,
                 total == 1 ? "" : "s");
        for (uint8_t i = 0; i < np; i++) {
            const pdc_peer_t *p = &peers[i];
            char id[16];

            if (p->kind == PDC_NODE_WIFI && scores && p->idx < count &&
                scores[p->idx].ssid[0] &&
                strcmp(scores[p->idx].ssid, "<hidden>") != 0) {
                snprintf(id, sizeof(id), "%.12s", scores[p->idx].ssid);
            } else {
                snprintf(id, sizeof(id), "%02X:%02X:%02X",
                         p->mac[3], p->mac[4], p->mac[5]);
            }
            det_rowf(1 + i, pdc_class_row_color(p->evclass), "%c %2u%% %-8s %s",
                     p->kind == PDC_NODE_WIFI ? 'W' : 'B',
                     (unsigned)p->confidence,
                     pdc_evidence_short(p->evidence), id);
        }
        break;
    }
    case 9: {
        uint8_t cls = ble_effective_class_certain(d);
        char note[256];
        ble_todo_note(d, cls, note, sizeof(note),true);
        uint8_t row = det_row_wrap(0, 1, threat_color(d->threat_level),
                                   lite_ble_lead(cls));
        if (note[0] && row < 5)
            det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, note);
        break;
    }
    case 10: {
        const drone_rid_t *r = &d->drone;
        det_rowf(0, COLOR_OK, "%s [%s]",
                 drone_ua_type_label(r->ua_type), drone_rid_bearer_label(r->bearer));
        const char *make = NULL;
        if (r->mfr_code[0]) {
            uint16_t mf = 0; uint8_t mc = 0;
            make = eui_lookup_drone_mfr(r->mfr_code, &mf, &mc);
        }
        if (make)
            det_rowf(1, COLOR_WHITE, "%.12s ID:%.10s", make, r->id);
        else
            det_rowf(1, COLOR_WHITE, "ID:%.17s", r->id[0] ? r->id : "(none)");
        if (r->msg_mask & DRONE_RID_MSG_LOCATION) {

            long alat = r->lat < 0 ? -(long)r->lat : r->lat;
            long alon = r->lon < 0 ? -(long)r->lon : r->lon;
            det_rowf(2, DETAILS_PAGE_FG, "drn %s%ld.%04ld,%s%ld.%04ld",
                     r->lat < 0 ? "-" : "", alat / 10000000, (alat % 10000000) / 1000,
                     r->lon < 0 ? "-" : "", alon / 10000000, (alon % 10000000) / 1000);
        } else {
            det_row(2, DETAILS_PAGE_FG, "drn pos: not given");
        }
        int sep = drone_op_separation_m(r);
        if (sep >= 0)
            det_rowf(3, COLOR_OK, "pilot ~%dm away", sep);
        else if (r->has_op_loc)
            det_row(3, COLOR_OK, "pilot located");
        else
            det_row(3, COLOR_CAUTION, "pilot: not given");
        det_rowf(4, DETAILS_PAGE_FG, "alt %dm  auth %s",
                 (int)r->alt_m, r->auth_present ? "Y" : "N");
        break;
    }
    }
    return TOTAL;
}

static const char *lite_ble_lead(uint8_t cls)
{
    switch (cls) {
    case EUI_CLASS_TRACKER:          return "Possible location tracker.";
    case EUI_CLASS_INVESTIGATION:
    case EUI_CLASS_ATTACK_SIGNAL:    return "Attack-capable hardware.";
    case EUI_CLASS_SURVEILLANCE_CAM: return "Possible camera.";
    case EUI_CLASS_SURVEILLANCE_OUI: return "Surveillance-OUI (unconfirmed).";
    case EUI_CLASS_ACCESS_CONTROL:   return "Smart lock or reader.";
    case EUI_CLASS_MEDICAL:          return "Medical device.";
    case EUI_CLASS_VEHICLE:          return "Vehicle / scan tool.";
    case EUI_CLASS_DRONE:            return "Drone broadcasting nearby.";
    case EUI_CLASS_PHONE:
    case EUI_CLASS_MOBILE:
    case EUI_CLASS_TABLET:
    case EUI_CLASS_LAPTOP:
    case EUI_CLASS_AUDIO:
    case EUI_CLASS_WEARABLE:
    case EUI_CLASS_IOT_HUB:
    case EUI_CLASS_IOT_LEAF:
    case EUI_CLASS_BEACON:
    case EUI_CLASS_STANDARDS:        return "Normal nearby device.";
    default:                          return "Unknown device.";
    }
}

static void ble_todo_note(const ble_device_t *d, uint8_t cls,
                          char *buf, size_t sz, bool adv)
{
    buf[0] = '\0';
    uint16_t flags = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags |
                     d->uuid128_flags | d->name_rule_flags;
    bool first_only = !adv;
    bool threat = false, done = false;
    #define EMITB(cond, txt) do { \
        if (!done && (cond)) { todo_append(buf, sz, txt); threat = true; \
                               if (first_only) done = true; } \
    } while (0)
    EMITB(d->is_airtag || cls == EUI_CLASS_TRACKER,
          "A common item tracker. Its presence is normal and not a sign of "
          "danger. No action needed.");
    EMITB(cls == EUI_CLASS_INVESTIGATION || cls == EUI_CLASS_ATTACK_SIGNAL ||
          (flags & EUI_FLAG_INVESTIGATION),
          "It can probe or attack nearby devices. Keep your devices locked "
          "and Bluetooth off.");
    EMITB(cls == EUI_CLASS_SURVEILLANCE_CAM || (flags & EUI_FLAG_SURVEILLANCE),
          "It may be recording. Note where it is.");
    EMITB((flags & (EUI_FLAG_MAKER | EUI_FLAG_DEV_MODULE)) != 0,
          "A hobbyist board. Often harmless but unverified.");
    #undef EMITB

    if (!threat) {
        if (cls == EUI_CLASS_DRONE)
            todo_append(buf, sz, "A drone is broadcasting Remote ID (public by "
                                 "law). Receive-only; not a threat to you.");
        else if (cls == EUI_CLASS_ACCESS_CONTROL)
            todo_append(buf, sz, "Normal in most buildings. No action needed.");
        else if (cls == EUI_CLASS_MEDICAL)
            todo_append(buf, sz, "Leave it alone.");
        else if (d->threat_level >= THREAT_MEDIUM)
            todo_append(buf, sz, "Unrecognized and scored risky. Keep your distance.");
        else
            todo_append(buf, sz, "No action needed.");
    }
}

uint8_t display_details_ble_lite(const ble_device_t *d, uint8_t page_idx)
{
    const uint8_t TOTAL = 3;
    if (!d) { display_details_chrome("BLE", 0, TOTAL); return TOTAL; }
    uint8_t p = page_idx % TOTAL;

    static const char *titles[] = { "DEVICE", "CONCERN?", "WHAT TO DO" };

    display_details_chrome_footer(titles[p], p, TOTAL, "[1] page  [2] next");

    uint8_t cls = ble_effective_class_certain(d);

    switch (p) {
    case 0: {
        det_rowf(0, COLOR_WHITE, "%.32s",
                 d->name[0] ? d->name :
                 d->vendor[0] ? d->vendor : "Unknown device");
        det_rowf(1, DETAILS_PAGE_FG, "type: %.28s",
                 eui_class_label(cls));
        if (d->vendor[0] && d->name[0])
            det_rowf(2, DETAILS_PAGE_FG, "from %.30s", d->vendor);

        display_blit_verdict(47, analyzer_threat_to_verdict(d->threat_level));
        break;
    }
    case 1: {
        char lines[2][64];
        uint8_t n = ble_lite_reasons(d, lines);
        uint8_t row = 0;
        if (n >= 1) {
            row += det_row_wrap(row, 2, COLOR_WHITE, lines[0]);
        }
        if (n >= 2 && row < 5) {
            if (row < 4) row++;
            row += det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, lines[1]);
        }
        if (n == 0) det_row(0, DETAILS_PAGE_FG, "No specific concern.");
        break;
    }
    case 2: {
        char note[160];
        ble_todo_note(d, cls, note, sizeof(note),false);
        uint8_t row = det_row_wrap(0, 1, threat_color(d->threat_level),
                                   lite_ble_lead(cls));
        if (note[0] && row < 5)
            det_row_wrap(row, (uint8_t)(5 - row), DETAILS_PAGE_FG, note);
        break;
    }
    }
    return TOTAL;
}

