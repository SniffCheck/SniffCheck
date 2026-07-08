#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "esp_chip_info.h"
#include "esp_attr.h"
#include "sdkconfig.h"
#if CONFIG_SPIRAM
#include "esp_psram.h"
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "led.h"
#include "display.h"
#include "usb_console.h"
#include "wifi_scanner.h"
#include "eui_db.h"
#include "wifi_sniffer.h"
#include "probe_req_log.h"
#include "flock_detect.h"
#include "public_safety_detect.h"
#include "medical_responder_detect.h"
#include "sta_tracker.h"
#include "wifi_csi_probe.h"
#include "seq_analyzer.h"
#include "ie_signature.h"
#include "anqp_analyzer.h"
#include "probe_frame_ring.h"
#include "ble_adv_ring.h"
#include "analyzer.h"
#include "physical_device_cluster.h"
#include "ble_scanner.h"
#include "apple_continuity.h"
#include "ble_advise.h"
#include "vetter.h"
#include "capture_ring.h"
#include "capture_writer.h"
#include "pcap_capture.h"
#include "download_mode.h"
#include "app_settings.h"
#include "self_test.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "ui_activity.h"
#include "pup_trophy.h"
#include "pup_trophy_icons.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "qrcode.h"

#define SPI_HOST       SPI2_HOST
#define PIN_MOSI       2
#define PIN_MISO       7
#define PIN_SCK        6

#define SNIFF_DWELL_MS 600

#define WIFI_STAGE_MS  1500
#define BLE_STAGE_MS   1500
#define SCORE_STAGE_MS 1500

#define WIFI_ADV_MAX_MS   60000

#define WIFI_ADV_ACTIVE_SWEEPS  4
#define BLE_ADV_SCAN_MS   30000

#define WIFI_UI_MAX_APS   32

#define PIN_BOOT            28
#define LONG_HOLD_MS        1500
#define DOUBLE_CLICK_GAP_MS 450

#define SCREENSAVER_MS      45000
#define LOGO_HOLD_FRAME     9

#define CFG_NS "uicfg"

static const char *TAG = "sc_adv";

static SemaphoreHandle_t s_state_mutex;

static EXT_RAM_BSS_ATTR ap_score_t      s_scores[ANALYZER_MAX_APS];
static uint16_t        s_score_count = 0;
static EXT_RAM_BSS_ATTR ble_results_t   s_ble;
static uint8_t         s_n_2g   = 0;
static uint8_t         s_n_5g   = 0;
static bool            s_scan_valid   = false;
static uint16_t        s_capture_scan_idx = 0;

static volatile bool   s_regular_scan_override = false;

typedef enum {
    ADVISOR_MODE_LITE = 0,
    ADVISOR_MODE_ADV  = 1,
} advisor_mode_t;

static const uint8_t s_brightness_steps[] = {25, 50, 75, 100};
#define BRIGHTNESS_STEPS_COUNT (sizeof(s_brightness_steps) / sizeof(s_brightness_steps[0]))

static advisor_mode_t s_advisor_mode = ADVISOR_MODE_ADV;
static uint8_t        s_screen_brightness_idx = BRIGHTNESS_STEPS_COUNT - 1;
static bool           s_led_enabled = true;

static bool           s_auto_ap_enabled = false;

typedef enum {
    UI_MODE_MAIN = 0,
    UI_MODE_SCANNING,
    UI_MODE_ENV_SUMMARY,
    UI_MODE_PUP,

    UI_MODE_PUP_INTERACT,
    UI_MODE_PUP_DIG,
    UI_MODE_PUP_TROPHIES,
    UI_MODE_PUP_TROPHY_DETAIL,
    UI_MODE_OPTIONS,

    UI_MODE_CREDITS,
    UI_MODE_WIFI_LIST,
    UI_MODE_BLE_LIST,
    UI_MODE_DETAILS_WIFI,
    UI_MODE_DETAILS_BLE,
    UI_MODE_BLE_CLASSES,
    UI_MODE_PROBE_LOG,
    UI_MODE_SEQ_LINK,
    UI_MODE_IE_SIG,
    UI_MODE_ANQP_LEAK,

    UI_MODE_PROBE_EXPLORE,
    UI_MODE_PROBE_DIG,

    UI_MODE_BLE_EXPLORE,
    UI_MODE_BLE_DIG,
    UI_MODE_DOWNLOAD_CONFIRM,
    UI_MODE_DOWNLOAD_ACTIVE,
    UI_MODE_WALK,

    UI_MODE_MENU,
} ui_mode_t;

static ui_mode_t s_ui_mode = UI_MODE_MAIN;

static volatile bool s_anim_dig = false;
static uint8_t   s_results_pane = 0;
static uint8_t   s_main_sel = 0;
static uint8_t   s_dl_sel = 0;
static uint32_t  s_boot_count = 0;
static uint8_t   s_credit_index = 0;
static uint16_t  s_wifi_index = 1;
static uint16_t  s_ble_index  = 1;

#define BLE_CLASS_FILTER_NONE     0x00
#define BLE_CLASS_FILTER_UNKNOWN  0xFF
static uint8_t   s_ble_class_filter = BLE_CLASS_FILTER_NONE;

static uint8_t   s_details_page  = 0;
static uint8_t   s_details_total = 1;

typedef enum { EXP_PROBE = 0, EXP_SEQ, EXP_IE, EXP_ANQP } explore_panel_t;
static explore_panel_t s_explore_panel  = EXP_PROBE;
static uint16_t        s_explore_cursor = 0;
static uint16_t        s_dig_frame      = 0;

static uint16_t        s_ble_explore_cursor = 0;
static uint16_t        s_ble_dig_frame      = 0;

static uint16_t        s_trophy_cursor      = 0;

static uint8_t   s_dl_last_drawn_state = 0xFF;

static uint8_t   s_dl_last_drawn_joined = 0xFF;

static volatile bool s_rescan_after_dl = false;

static volatile bool s_force_rescan = false;

static volatile bool     s_capture_after_dl = false;
static volatile uint8_t  s_capture_kind = 0;
static volatile uint8_t  s_capture_channel = 6;
static volatile uint16_t s_capture_secs = 5;
static TaskHandle_t      s_capture_task_handle = NULL;

static uint8_t           s_pcap_channels[PCAP_MAX_CHANNELS];
static uint8_t           s_pcap_channel_count = 0;

static volatile bool s_walk_requested = false;
static volatile bool s_walk_after_dl = false;
static volatile bool s_walk_end_requested = false;
#define WALK_MAX_SEC      (30 * 60)

#define WALK_BLE_WINDOW_MS 3000

#define WIFI_WARDRIVE_5G_EVERY 4

static bool icontains(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0]) return false;
    size_t nlen = strlen(needle);
    for (const char *h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] &&
               (char)tolower((unsigned char)h[i]) == (char)tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static uint8_t env_threat_level(void);

static const char *lite_rf_threat_status(void)
{
    bool banned = false;
    bool pwnagotchi = false;
    bool evil_twin = false;
    bool attack_tool = false;
    bool deauth = false;
    bool lost_tracker = false;
    bool surveillance = false;

    for (uint16_t i = 0; i < s_score_count; i++) {
        const ap_score_t *ap = &s_scores[i];
        if (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) banned = true;
        if (ap->pwnagotchi ||
            icontains(ap->ssid, "Pwnagotchi") || icontains(ap->vendor, "Pwnagotchi")) pwnagotchi = true;
        if (ap->deauth_flood) deauth = true;

        if (ap->eui_flags & EUI_FLAG_INVESTIGATION) attack_tool = true;

        if (ap->twin_detected || ap->open_clone || ap->karma_suspect) evil_twin = true;

        if ((ap->eui_flags & EUI_FLAG_SURVEILLANCE) ||
            ap->device_class == EUI_CLASS_SURVEILLANCE_CAM ||
            icontains(ap->ssid, "hikvision") || icontains(ap->ssid, "dahua") ||
            icontains(ap->ssid, "reolink")   || icontains(ap->ssid, "wyzecam") ||
            icontains(ap->ssid, "eufycam")   || icontains(ap->ssid, "amcrest") ||
            icontains(ap->ssid, "lorex")     || icontains(ap->ssid, "arlo")) {
            surveillance = true;
        }
    }

    for (uint16_t i = 0; i < s_ble.count; i++) {
        const ble_device_t *d = &s_ble.devices[i];
        uint16_t flags = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags
                       | d->uuid128_flags | d->name_rule_flags;
        const char *vendor = d->vendor[0] ? d->vendor : d->company_name;
        const char *name = d->name;

        if (flags & EUI_FLAG_KNOWN_MALICIOUS) banned = true;
        if (icontains(vendor, "Pwnagotchi") || icontains(name, "Pwnagotchi")) pwnagotchi = true;

        if ((flags & EUI_FLAG_INVESTIGATION) ||
            d->uuid128_class == EUI_CLASS_INVESTIGATION ||
            d->name_rule_class == EUI_CLASS_INVESTIGATION ||
            icontains(vendor, "Hak5") || icontains(name, "Pineapple") ||
            icontains(name, "Flipper") || icontains(name, "Marauder") ||
            icontains(name, "Bjorn") || icontains(name, "Biscuit")) {
            attack_tool = true;
        }

        if (d->is_airtag || d->apple_subtype == APPLE_SUB_FIND_MY_SEP) lost_tracker = true;
        if (flags & EUI_FLAG_SURVEILLANCE) surveillance = true;
    }

    if (sta_tracker_camera_count() > 0) surveillance = true;

    if (banned) return "RF Threat: Banned Device";
    if (pwnagotchi) return "RF Threat: Pwnagotchi";
    if (deauth) return "RF Threat: Deauth Flood";
    if (evil_twin) return "RF Threat: Evil Twin";
    if (attack_tool) return "RF Threat: Attack Tool";

    if (lost_tracker) return "Watch: Lost Tracker";

    if (surveillance) return "Watch: Camera Device";
    if (flock_detect_distinct() > 0) return "Watch: Possible Flock";

    switch (env_threat_level()) {
    case THREAT_HIGH:   return "RF Threat: See Results";
    case THREAT_MEDIUM: return "Caution: See Results";
    default:            return "No RF Threats Detected";
    }
}

static uint16_t lite_best_index(void)
{
    if (s_score_count == 0) return 1;
    for (uint16_t i = 0; i < s_score_count; i++) {
        const ap_score_t *ap = &s_scores[i];
        if (ap->suppressed) continue;
        if (ap->threat_level < THREAT_MEDIUM) return (uint16_t)(i + 1);
    }
    return 1;
}

static uint16_t wifi_disp_count(void)
{
    return (s_score_count < WIFI_UI_MAX_APS) ? s_score_count : WIFI_UI_MAX_APS;
}

static uint16_t lite_next_index(uint16_t current_1based)
{
    uint16_t n = wifi_disp_count();
    if (n == 0) return 1;

    if (current_1based == 0 || current_1based > n) {
        return lite_best_index();
    }

    return (uint16_t)(current_1based % n) + 1;
}

static uint8_t s_led_r, s_led_g, s_led_b, s_led_bri;

static void led_apply(uint8_t r, uint8_t g, uint8_t b, uint8_t brightness)
{
    s_led_r = r; s_led_g = g; s_led_b = b; s_led_bri = brightness;
    if (!s_led_enabled) {
        led_off();
        return;
    }
    led_set(r, g, b, brightness);
}

static void led_reassert(void)
{
    led_apply(s_led_r, s_led_g, s_led_b, s_led_bri);
}

static void led_post_blit_guard(void)
{
    if (!s_led_enabled) {
        led_off();
    }
}

static void led_for_verdict(uint8_t verdict)
{
    switch (verdict) {
    case VERDICT_GREEN:  led_apply(  0, 200,  83, 8); break;
    case VERDICT_YELLOW: led_apply(255, 214,   0, 8); break;
    case VERDICT_ORANGE: led_apply(255, 109,   0, 8); break;
    default:             led_apply(213,   0,   0, 4); break;
    }
}

static void dl_assert_led_locked(void)
{
    led_apply(0, 0, 255, 8);
}

static void boot_assert_led(void)
{
    led_apply(128, 0, 128, 8);
}

static void settings_apply(void)
{
    if (s_screen_brightness_idx >= BRIGHTNESS_STEPS_COUNT) {
        s_screen_brightness_idx = BRIGHTNESS_STEPS_COUNT - 1;
    }
    display_set_brightness_percent(s_brightness_steps[s_screen_brightness_idx]);
    if (!s_led_enabled) {
        led_off();
    }
}

static void led_state_preload(void)
{
    nvs_handle_t h;
    if (nvs_open(CFG_NS, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    uint8_t led = s_led_enabled ? 1 : 0;
    if (nvs_get_u8(h, "led_en", &led) == ESP_OK) {
        s_led_enabled = (led != 0);
    }
    nvs_close(h);
}

static void settings_load(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(CFG_NS, NVS_READONLY, &h);
    if (err != ESP_OK) {
        settings_apply();
        return;
    }

    uint8_t mode = (uint8_t)s_advisor_mode;
    uint8_t bri  = s_screen_brightness_idx;
    uint8_t led  = s_led_enabled ? 1 : 0;

    if (nvs_get_u8(h, "advisor_mode", &mode) == ESP_OK) {
        s_advisor_mode = (mode == 0) ? ADVISOR_MODE_LITE : ADVISOR_MODE_ADV;
    }
    if (nvs_get_u8(h, "screen_bri", &bri) == ESP_OK && bri < BRIGHTNESS_STEPS_COUNT) {
        s_screen_brightness_idx = bri;
    }
    if (nvs_get_u8(h, "led_en", &led) == ESP_OK) {
        s_led_enabled = (led != 0);
    }
    uint8_t auto_ap = s_auto_ap_enabled ? 1 : 0;
    if (nvs_get_u8(h, "auto_ap", &auto_ap) == ESP_OK) {
        s_auto_ap_enabled = (auto_ap != 0);
    }

    nvs_close(h);
    settings_apply();
}

static void settings_save(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(CFG_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "settings save open failed: %s", esp_err_to_name(err));
        return;
    }

    nvs_set_u8(h, "advisor_mode", (uint8_t)s_advisor_mode);
    nvs_set_u8(h, "screen_bri", s_screen_brightness_idx);
    nvs_set_u8(h, "led_en", s_led_enabled ? 1 : 0);
    nvs_set_u8(h, "auto_ap", s_auto_ap_enabled ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
}

void app_settings_get_json(char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    const char *mode = (s_advisor_mode == ADVISOR_MODE_LITE) ? "lite" : "adv";
    uint8_t idx = (s_screen_brightness_idx < BRIGHTNESS_STEPS_COUNT)
                      ? s_screen_brightness_idx : (BRIGHTNESS_STEPS_COUNT - 1);
    unsigned pct = s_brightness_steps[idx];
    bool led = s_led_enabled;
    xSemaphoreGive(s_state_mutex);

    snprintf(buf, buflen,
        "{\"advisor_mode\":\"%s\",\"brightness_pct\":%u,\"led_enabled\":%s,"
        "\"download_timeout_min\":%u,\"pup_name\":\"%s\"}",
        mode, pct, led ? "true" : "false",
        (unsigned)download_mode_get_timeout_minutes(),
        virtual_pup_name());
}

bool app_settings_set_mode(bool adv)
{
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_advisor_mode = adv ? ADVISOR_MODE_ADV : ADVISOR_MODE_LITE;
    settings_save();
    xSemaphoreGive(s_state_mutex);

    ESP_LOGI(TAG, "WebAP: mode -> %s (applies next scan)", adv ? "Adv" : "Lite");
    return true;
}

bool app_settings_set_brightness_pct(int pct)
{
    int idx = -1;
    for (int i = 0; i < (int)BRIGHTNESS_STEPS_COUNT; i++) {
        if (s_brightness_steps[i] == pct) { idx = i; break; }
    }
    if (idx < 0) return false;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_screen_brightness_idx = (uint8_t)idx;
    settings_apply();
    settings_save();
    xSemaphoreGive(s_state_mutex);
    ESP_LOGI(TAG, "WebAP: brightness -> %d%%", pct);
    return true;
}

bool app_settings_set_led(bool enabled)
{
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_led_enabled = enabled;
    settings_save();
    if (!s_led_enabled) led_off();
    xSemaphoreGive(s_state_mutex);
    ESP_LOGI(TAG, "WebAP: LED -> %s", enabled ? "on" : "off");
    return true;
}

static uint16_t verdict_band_color(uint8_t verdict)
{
    switch (verdict) {
    case VERDICT_GREEN:  return COLOR_SAFE;
    case VERDICT_YELLOW: return COLOR_OK;
    case VERDICT_ORANGE: return COLOR_CAUTION;
    default:             return COLOR_DANGER;
    }
}

#define UI_THEME_BG          COLOR_NEARBLACK
#define UI_THEME_TITLE       rgb565be(0x00, 0xFF, 0x00)
#define UI_THEME_DIVIDER     rgb565be(0x00, 0x7A, 0x00)
#define UI_THEME_MUTED       rgb565be(120, 120, 120)

static const char *verdict_label(uint8_t verdict)
{
    switch (verdict) {
    case VERDICT_GREEN:  return "SAFE";
    case VERDICT_YELLOW: return "OK";
    case VERDICT_ORANGE: return "CAUTION";
    default:             return "AVOID";
    }
}

static void draw_line_clip(int y, const char *text, uint16_t fg, uint16_t bg)
{
    char line[27];
    strlcpy(line, text ? text : "", sizeof(line));
    display_draw_string(2, y, line, fg, bg, 1);
}

static void draw_center_clip(int y, const char *text, uint16_t fg, uint16_t bg, uint8_t scale)
{
    if (scale < 1) scale = 1;
    if (scale > 2) scale = 2;

    int max_chars = (scale == 2) ? 13 : 26;
    char line[27];
    strlcpy(line, text ? text : "", (size_t)max_chars + 1);

    int px_per_char = (scale == 2) ? 12 : 6;
    int width = (int)strlen(line) * px_per_char;
    int x = (DISPLAY_W - width) / 2;
    if (x < 0) x = 0;

    display_draw_string(x, y, line, fg, bg, scale);
}

static void draw_center_sc_title(int y, const char *title, uint16_t bg)
{
    char line[17];
    strlcpy(line, title ? title : "", sizeof(line));

    size_t n = strlen(line);
    if (n == 0) return;

    int total_w = (int)n * 12;
    int x = (DISPLAY_W - total_w) / 2;
    if (x < 0) x = 0;

    for (size_t i = 0; i < n; i++) {
        char one[2] = { line[i], 0 };
        display_draw_string(x + (int)i * 12, y, one, UI_THEME_TITLE, bg, 2);
    }
}

static void draw_menu_header(const char *title)
{
    display_fill_rect(0, 0, DISPLAY_W, 18, UI_THEME_BG);
    draw_center_sc_title(2, title, UI_THEME_BG);
    display_fill_rect(0, 18, DISPLAY_W, 1, UI_THEME_DIVIDER);
}

static void draw_menu_header_plain(const char *title)
{
    display_fill_rect(0, 0, DISPLAY_W, 18, UI_THEME_BG);
    draw_center_clip(2, title, UI_THEME_TITLE, UI_THEME_BG, 2);
    display_fill_rect(0, 18, DISPLAY_W, 1, UI_THEME_DIVIDER);
}

static uint16_t action_btn_color(const char *btn)
{
    if (!btn) return COLOR_WHITE;
    if (icontains(btn, "1"))    return COLOR_SAFE;
    if (icontains(btn, "2"))    return COLOR_OK;
    if (icontains(btn, "hold")) return COLOR_CAUTION;
    return UI_THEME_TITLE;
}

static void draw_action_pair_region(int x, int w, int y, const char *btn, const char *action)
{
    if (!btn || !action) return;
    int btn_px = (int)strlen(btn) * 6;
    int act_px = (int)strlen(action) * 6;
    int total_px = btn_px + 6 + act_px;
    int sx = x + (w - total_px) / 2;
    if (sx < x) sx = x;

    display_draw_string(sx, y, btn, action_btn_color(btn), UI_THEME_BG, 1);
    display_draw_string(sx + btn_px + 6, y, action, COLOR_WHITE, UI_THEME_BG, 1);
}

static void draw_action_footer_two(int y, const char *btn1, const char *action1,
                                   const char *btn2, const char *action2)
{
    draw_action_pair_region(0, DISPLAY_W / 2, y, btn1, action1);
    draw_action_pair_region(DISPLAY_W / 2, DISPLAY_W / 2, y, btn2, action2);
}

static void draw_action_footer_one(int y, const char *btn, const char *action)
{
    draw_action_pair_region(0, DISPLAY_W, y, btn, action);
}

#define ACTION_BTN_X      8
#define ACTION_ARROW_X   52
#define ACTION_TEXT_X    64
#define ACTION_ROW1_Y    44
#define ACTION_ROW2_Y    56
#define ACTION_ROW3_Y    68

static void draw_action_row(int y, const char *btn, const char *action)
{
    display_draw_string(ACTION_BTN_X,  y, btn,    action_btn_color(btn), UI_THEME_BG, 1);
    display_draw_string(ACTION_ARROW_X, y, ">",   UI_THEME_MUTED, UI_THEME_BG, 1);
    display_draw_string(ACTION_TEXT_X, y, action, COLOR_WHITE, UI_THEME_BG, 1);
}

static const char *wifi_signal_word(int8_t rssi)
{
    if (rssi >= -55) return "Strong";
    if (rssi >= -70) return "Good";
    if (rssi >= -80) return "Fair";
    return "Weak";
}

static void format_distance_line(char *out, size_t out_sz, int8_t rssi, uint16_t distance_dm)
{

    snprintf(out, out_sz, "RSSI:%ddBm  %s",
             (int)rssi, ble_proximity_label(distance_dm));
}

static uint8_t env_threat_level(void)
{
    uint8_t t = THREAT_NONE;
    for (uint16_t i = 0; i < s_score_count; i++) {
        if (s_scores[i].suppressed) continue;
        if (s_scores[i].threat_level > t) t = s_scores[i].threat_level;
    }
    for (uint16_t i = 0; i < s_ble.count; i++) {
        if (s_ble.devices[i].suppressed) continue;
        if (s_ble.devices[i].threat_level > t) t = s_ble.devices[i].threat_level;
    }
    return t;
}

static const char *env_verdict_label(void)
{
    if (!s_scan_valid) return "PENDING";
    if (s_score_count == 0 && s_ble.count == 0) return "PENDING";
    return verdict_label(analyzer_threat_to_verdict(env_threat_level()));
}

static void draw_env_mode_row(int y)
{
    const char *verdict = env_verdict_label();
    const char *mode_val = (s_advisor_mode == ADVISOR_MODE_LITE) ? "LITE" : "ADV";
    const uint16_t verdict_col =
        (strcmp(verdict, "SAFE") == 0)    ? COLOR_SAFE :
        (strcmp(verdict, "OK") == 0)      ? COLOR_OK :
        (strcmp(verdict, "CAUTION") == 0) ? COLOR_CAUTION :
        (strcmp(verdict, "AVOID") == 0)   ? COLOR_DANGER :
                                            COLOR_WHITE;

    const char *mode_lbl = "MODE:";
    int mode_lbl_px = (int)strlen(mode_lbl) * 6;
    int mode_val_px = (int)strlen(mode_val) * 6;
    int mode_total_px = mode_lbl_px + mode_val_px;
    int mode_x = DISPLAY_W - mode_total_px - 2;
    if (mode_x < 2) mode_x = 2;

    const char *audit_lbl = "RF Audit:";
    int audit_lbl_px = (int)strlen(audit_lbl) * 6;
    int verdict_max_px = mode_x - 2 - 6 - (2 + audit_lbl_px + 6);
    int verdict_max_chars = verdict_max_px / 6;
    if (verdict_max_chars < 1) verdict_max_chars = 1;
    if (verdict_max_chars > 12) verdict_max_chars = 12;

    char verdict_clip[13];
    strlcpy(verdict_clip, verdict, sizeof(verdict_clip));
    verdict_clip[verdict_max_chars] = '\0';

    display_draw_string(2, y, audit_lbl, COLOR_HEADER, UI_THEME_BG, 1);
    display_draw_string(2 + audit_lbl_px + 6, y, verdict_clip, verdict_col, UI_THEME_BG, 1);
    display_draw_string(mode_x, y, mode_lbl, COLOR_HEADER, UI_THEME_BG, 1);
    display_draw_string(mode_x + mode_lbl_px, y, mode_val, COLOR_OK, UI_THEME_BG, 1);
}

static void draw_menu_footer(void);

static const char *const s_main_rows[] = { "Results", "Settings", "Rescan" };
#define MAIN_ROW_COUNT (sizeof(s_main_rows) / sizeof(s_main_rows[0]))

static void render_main_locked(void)
{
    ESP_LOGI(TAG, "SPLASH: MAIN mode=%s scan_valid=%d nets=%u ble=%u",
             s_advisor_mode == ADVISOR_MODE_LITE ? "Lite" : "Adv",
             s_scan_valid ? 1 : 0, (unsigned)s_score_count, (unsigned)s_ble.count);

    display_clear(UI_THEME_BG);
    display_blit_brand(1);
    draw_env_mode_row(22);

    if (s_main_sel >= MAIN_ROW_COUNT) s_main_sel = 0;

    int y = 36;
    for (uint8_t i = 0; i < MAIN_ROW_COUNT; i++) {
        bool focus = (i == s_main_sel);
        char line[24];
        snprintf(line, sizeof(line), "%c %s", focus ? '>' : ' ', s_main_rows[i]);
        display_draw_string(10, y, line,
                            focus ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);
        y += 9;
    }

    draw_menu_footer();
}

static environment_indicators_t s_env_ind;

static void draw_env_badges_locked(void)
{
    char strip[24];
    int p = 0;
    if (s_env_ind.camera_count)
        p += snprintf(strip + p, sizeof(strip) - p, "%sC%u",
                      p ? " " : "", (unsigned)s_env_ind.camera_count);
    if (s_env_ind.public_safety_high)
        p += snprintf(strip + p, sizeof(strip) - p, "%sL~%u",
                      p ? " " : "", (unsigned)s_env_ind.public_safety_high);
    if (s_env_ind.phone_like_count)
        p += snprintf(strip + p, sizeof(strip) - p, "%sP~%u",
                      p ? " " : "", (unsigned)s_env_ind.phone_like_count);
    if (s_env_ind.medical_count)
        p += snprintf(strip + p, sizeof(strip) - p, "%sM~%u",
                      p ? " " : "", (unsigned)s_env_ind.medical_count);
    if (p <= 0) return;

    int w = p * 6;
    int x = DISPLAY_W - w - 1;
    if (x < 99) x = 99;
    display_draw_string(x, 1, strip, UI_THEME_MUTED, UI_THEME_BG, 1);
}

static void render_env_summary_locked(void)
{
    char line[32];
    const char *verdict   = env_verdict_label();
    const char *rf_threat = lite_rf_threat_status();

    ESP_LOGI(TAG, "SPLASH: ENV_SUMMARY verdict=%s threat=\"%s\" nets=%u ble=%u",
             verdict, rf_threat, (unsigned)s_score_count, (unsigned)s_ble.count);

    display_clear(UI_THEME_BG);

    uint8_t env_verdict = (strcmp(verdict, "OK") == 0)      ? VERDICT_YELLOW
                        : (strcmp(verdict, "CAUTION") == 0) ? VERDICT_ORANGE
                        : (strcmp(verdict, "AVOID") == 0)   ? VERDICT_RED
                                                            : VERDICT_GREEN;
    display_blit_verdict_lg(0, env_verdict);

    draw_env_badges_locked();

    draw_center_clip(42, rf_threat,
                     (rf_threat[0] == 'R') ? COLOR_CAUTION : COLOR_WHITE,
                     UI_THEME_BG, 1);

    uint16_t radios = 0;
    for (uint16_t i = 0; i < s_score_count; i++)
        radios += s_scores[i].radio_count ? s_scores[i].radio_count : 1;
    char count_line[40];
    if (radios > s_score_count)
        snprintf(count_line, sizeof(count_line), "%u Nets/%u rad  %u BLE",
                 (unsigned)s_score_count, (unsigned)radios, (unsigned)s_ble.count);
    else
        snprintf(count_line, sizeof(count_line), "%u Networks  %u BLE",
                 (unsigned)s_score_count, (unsigned)s_ble.count);
    draw_center_clip(52, count_line, UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_footer_two(62, "[1]", "menu", "[2]", "pup");
    draw_action_footer_one(72, "[hold]", "rescan");
}

static uint16_t pup_title_color(vp_title_t t)
{
    switch (t) {
    case VP_TITLE_PUPPY:   return COLOR_HEADER;
    case VP_TITLE_YOUNG:   return COLOR_SAFE;
    case VP_TITLE_ADULT:   return COLOR_OK;
    case VP_TITLE_VETERAN: return COLOR_CAUTION;
    case VP_TITLE_LEGEND:  return COLOR_PURPLE;
    default:               return COLOR_WHITE;
    }
}

static void render_pup_locked(void)
{
    vp_status_t st;
    virtual_pup_get(&st);

    char line[56];
    uint16_t tcol = pup_title_color(st.title);
    uint32_t age  = (s_boot_count > st.birth_boot)
                        ? (s_boot_count - st.birth_boot) : 0;

    ESP_LOGI(TAG, "SPLASH: PUP L%u xp_into=%llu/%llu wifi=%u ble=%u age=%u",
             (unsigned)st.level,
             (unsigned long long)st.xp_into_level,
             (unsigned long long)st.xp_for_level,
             (unsigned)st.lifetime_wifi, (unsigned)st.lifetime_ble,
             (unsigned)age);

    display_clear(UI_THEME_BG);
    display_blit_sitting(1);

    snprintf(line, sizeof(line), "Lv %u  %s",
             (unsigned)st.level, virtual_pup_title_label(st.title));
    draw_center_clip(24, line, tcol, UI_THEME_BG, 1);

    const int bx = 20, by = 35, bw = 120, bh = 6;
    display_fill_rect(bx, by, bw, bh, UI_THEME_MUTED);
    int fill = 0;
    if (st.xp_for_level > 0) {

        uint64_t num = st.xp_into_level * (uint64_t)(bw - 2);
        fill = (int)(num / st.xp_for_level);
        if (fill > bw - 2) fill = bw - 2;
    }
    if (fill > 0) display_fill_rect(bx + 1, by + 1, fill, bh - 2, tcol);

    if (st.xp_for_level > 0) {
        snprintf(line, sizeof(line), "%llu / %llu to next",
                 (unsigned long long)st.xp_into_level,
                 (unsigned long long)st.xp_for_level);
    } else {
        snprintf(line, sizeof(line), "xp %llu", (unsigned long long)st.total_xp);
    }
    draw_center_clip(43, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    uint8_t env_t = env_threat_level();
    if (env_t > THREAT_NONE) {
        draw_center_clip(53, lite_rf_threat_status(),
                         verdict_band_color(analyzer_threat_to_verdict(env_t)),
                         UI_THEME_BG, 1);
    } else {
        snprintf(line, sizeof(line), "%u WiFi  %u BLE  age %u",
                 (unsigned)st.lifetime_wifi, (unsigned)st.lifetime_ble,
                 (unsigned)age);
        draw_center_clip(53, line, UI_THEME_MUTED, UI_THEME_BG, 1);
    }

    draw_action_footer_two(62, "[1]", "interact", "[2]", "back");
}

static void render_pup_levelup(uint16_t level, vp_title_t title)
{
    char line[32];
    display_clear(UI_THEME_BG);
    display_blit_sitting(2);
    draw_center_clip(26, "LEVEL UP!", COLOR_OK, UI_THEME_BG, 2);
    snprintf(line, sizeof(line), "Suz reached Lv %u", (unsigned)level);
    draw_center_clip(50, line, COLOR_WHITE, UI_THEME_BG, 1);
    draw_center_clip(60, virtual_pup_title_label(title),
                     pup_title_color(title), UI_THEME_BG, 1);
}

static uint16_t pup_weight_color(uint8_t w)
{
    switch (w) {
    case 2:  return COLOR_HEADER;
    case 3:  return COLOR_SAFE;
    case 4:  return COLOR_CAUTION;
    case 5:  return COLOR_PURPLE;
    default: return COLOR_WHITE;
    }
}

static void render_pup_interact_locked(void)
{
    char line[36];
    ESP_LOGI(TAG, "SPLASH: PUP_INTERACT trophies=%u scents=%u",
             (unsigned)pup_trophy_earned_count(),
             (unsigned)pup_trophy_scent_count());

    display_clear(UI_THEME_BG);
    draw_menu_header("SUZ");

    snprintf(line, sizeof(line), "Trophies %u/%u  Scents %u",
             (unsigned)pup_trophy_earned_count(), PUP_TROPHY_COUNT,
             (unsigned)pup_trophy_scent_count());
    draw_center_clip(26, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_row(ACTION_ROW1_Y, "[1]",    "dig");
    draw_action_row(ACTION_ROW2_Y, "[2]",    "trophies");
    draw_action_row(ACTION_ROW3_Y, "[hold]", "back");
}

typedef struct {
    const char *label;
    char        value[28];
} pup_dig_find_t;

static bool pup_dig_pick(pup_dig_find_t *out)
{
    enum { K_STRONG, K_HIDDEN, K_5G, K_CLOSE, K_NAMED, K_VENDOR, K_MAX };
    uint8_t kinds[K_MAX];
    uint8_t nk = 0;

    uint16_t n_hidden = 0, n_5g = 0, n_close = 0, n_named = 0, n_vendor = 0;
    for (uint16_t i = 0; i < s_score_count; i++) {
        if (!s_scores[i].ssid[0]) n_hidden++;
        if (s_scores[i].band_5g)  n_5g++;
        if (s_scores[i].vendor[0]) n_vendor++;
    }
    for (uint16_t i = 0; i < s_ble.count; i++) {
        const ble_device_t *d = &s_ble.devices[i];
        if (d->suppressed) continue;
        if (d->distance_dm != 0xFFFF && d->distance_dm <= 20) n_close++;
        if (d->name[0])   n_named++;
        if (d->vendor[0]) n_vendor++;
    }

    if (s_score_count) kinds[nk++] = K_STRONG;
    if (n_hidden)      kinds[nk++] = K_HIDDEN;
    if (n_5g)          kinds[nk++] = K_5G;
    if (n_close)       kinds[nk++] = K_CLOSE;
    if (n_named)       kinds[nk++] = K_NAMED;
    if (n_vendor)      kinds[nk++] = K_VENDOR;
    if (!nk) return false;

    switch (kinds[esp_random() % nk]) {
    case K_STRONG: {
        const ap_score_t *best = &s_scores[0];
        for (uint16_t i = 1; i < s_score_count; i++) {
            if (s_scores[i].rssi > best->rssi) best = &s_scores[i];
        }
        out->label = "Strongest scent:";
        snprintf(out->value, sizeof(out->value), "%.20s %d",
                 best->ssid[0] ? best->ssid : "<hidden>", (int)best->rssi);
        return true;
    }
    case K_HIDDEN: {
        uint16_t pick = esp_random() % n_hidden;
        for (uint16_t i = 0; i < s_score_count; i++) {
            if (s_scores[i].ssid[0]) continue;
            if (pick--) continue;
            out->label = "Buried bone:";
            snprintf(out->value, sizeof(out->value), "<hidden> ch%u %d",
                     (unsigned)s_scores[i].channel, (int)s_scores[i].rssi);
            return true;
        }
        break;
    }
    case K_5G: {
        uint16_t pick = esp_random() % n_5g;
        for (uint16_t i = 0; i < s_score_count; i++) {
            if (!s_scores[i].band_5g) continue;
            if (pick--) continue;
            out->label = "High band find:";
            snprintf(out->value, sizeof(out->value), "%.20s 5GHz",
                     s_scores[i].ssid[0] ? s_scores[i].ssid : "<hidden>");
            return true;
        }
        break;
    }
    case K_CLOSE: {
        uint16_t pick = esp_random() % n_close;
        for (uint16_t i = 0; i < s_ble.count; i++) {
            const ble_device_t *d = &s_ble.devices[i];
            if (d->suppressed) continue;
            if (d->distance_dm == 0xFFFF || d->distance_dm > 20) continue;
            if (pick--) continue;
            out->label = "Right under my nose:";
            snprintf(out->value, sizeof(out->value), "%.26s",
                     d->name[0] ? d->name
                                : (d->vendor[0] ? d->vendor : "BLE device"));
            return true;
        }
        break;
    }
    case K_NAMED: {
        uint16_t pick = esp_random() % n_named;
        for (uint16_t i = 0; i < s_ble.count; i++) {
            const ble_device_t *d = &s_ble.devices[i];
            if (d->suppressed || !d->name[0]) continue;
            if (pick--) continue;
            out->label = "Dug this up:";
            snprintf(out->value, sizeof(out->value), "%.26s", d->name);
            return true;
        }
        break;
    }
    case K_VENDOR: {
        uint16_t pick = esp_random() % n_vendor;
        for (uint16_t i = 0; i < s_score_count; i++) {
            if (!s_scores[i].vendor[0]) continue;
            if (pick--) continue;
            out->label = "Fresh trail:";
            snprintf(out->value, sizeof(out->value), "%.26s", s_scores[i].vendor);
            return true;
        }
        for (uint16_t i = 0; i < s_ble.count; i++) {
            const ble_device_t *d = &s_ble.devices[i];
            if (d->suppressed || !d->vendor[0]) continue;
            if (pick--) continue;
            out->label = "Fresh trail:";
            snprintf(out->value, sizeof(out->value), "%.26s", d->vendor);
            return true;
        }
        break;
    }
    }
    return false;
}

static void render_pup_dig_locked(void)
{
    pup_dig_find_t find;
    bool got = pup_dig_pick(&find);

    ESP_LOGI(TAG, "SPLASH: PUP_DIG %s%s", got ? find.label : "(nothing)",
             got ? find.value : "");

    display_clear(UI_THEME_BG);

    display_score_dig_frame(0);

    if (got) {
        draw_center_clip(44, find.label, UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_center_clip(54, find.value, COLOR_WHITE, UI_THEME_BG, 1);
    } else {
        draw_center_clip(44, "Nothing buried here", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_center_clip(54, "scan to bury more", UI_THEME_MUTED, UI_THEME_BG, 1);
    }
    draw_action_footer_two(68, "[1]", "dig more", "[2]", "back");
}

#define TROPHY_VISIBLE_ROWS 5

static void render_pup_trophies_locked(void)
{
    uint16_t total = pup_trophy_earned_count();
    char line[36];

    ESP_LOGI(TAG, "SPLASH: PUP_TROPHIES cursor=%u/%u",
             (unsigned)s_trophy_cursor, (unsigned)total);

    snprintf(line, sizeof(line), "TROPHIES %u/%u",
             (unsigned)total, PUP_TROPHY_COUNT);
    display_clear(UI_THEME_BG);
    draw_menu_header_plain(line);

    if (total == 0) {
        draw_center_clip(34, "No trophies yet", COLOR_WHITE, UI_THEME_BG, 1);
        draw_center_clip(46, "every scan counts", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[hold]", "back");
        return;
    }
    if (s_trophy_cursor >= total) s_trophy_cursor = 0;

    uint16_t page  = s_trophy_cursor / TROPHY_VISIBLE_ROWS;
    uint16_t start = page * TROPHY_VISIBLE_ROWS;
    const int row_h  = 9;
    const int body_y = 22;

    for (uint16_t r = 0; r < TROPHY_VISIBLE_ROWS; r++) {
        uint16_t n = start + r;
        if (n >= total) break;
        uint16_t id = pup_trophy_earned_at(n);
        if (id == 0xFFFF) break;

        uint8_t  wgt = pup_trophy_weight(id);
        uint16_t col = pup_weight_color(wgt);
        int y = body_y + r * row_h;

        char stars[6];
        memset(stars, '*', wgt);
        stars[wgt] = '\0';
        int spx = (int)wgt * 6;

        snprintf(line, sizeof(line), "%.20s", pup_trophy_name(id));
        if (n == s_trophy_cursor) {
            display_fill_rect(2, y - 1, DISPLAY_W - 4, row_h, col);
            display_draw_string(4, y, line, UI_THEME_BG, col, 1);
            display_draw_string(DISPLAY_W - 4 - spx, y, stars, UI_THEME_BG, col, 1);
        } else {
            display_draw_string(4, y, line, col, UI_THEME_BG, 1);
            display_draw_string(DISPLAY_W - 4 - spx, y, stars, UI_THEME_MUTED,
                                UI_THEME_BG, 1);
        }
    }

    draw_action_footer_two(72, "[1]", "next", "[2]", "view");
}

static void render_pup_trophy_detail_locked(void)
{
    uint16_t total = pup_trophy_earned_count();
    if (total == 0) {
        s_ui_mode = UI_MODE_PUP_TROPHIES;
        render_pup_trophies_locked();
        return;
    }
    if (s_trophy_cursor >= total) s_trophy_cursor = 0;
    uint16_t id = pup_trophy_earned_at(s_trophy_cursor);
    if (id == 0xFFFF) {
        s_ui_mode = UI_MODE_PUP_TROPHIES;
        render_pup_trophies_locked();
        return;
    }

    ESP_LOGI(TAG, "SPLASH: PUP_TROPHY_DETAIL id=%u \"%s\"",
             (unsigned)id, pup_trophy_name(id));

    char line[36];
    uint8_t icon = pup_trophy_icon(id);

    display_clear(UI_THEME_BG);
    display_draw_image_masked_scaled((DISPLAY_W - PUP_ICON_W * 2) / 2, 4,
                                     PUP_ICON_W, PUP_ICON_H,
                                     PUP_ICON_PX[icon], PUP_ICON_MASK[icon], 2);

    draw_center_clip(42, pup_trophy_name(id),
                     pup_weight_color(pup_trophy_weight(id)), UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "earned @ boot %u",
             (unsigned)pup_trophy_boot_earned(id));
    draw_center_clip(54, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_footer_two(68, "[1]", "next", "[2]", "back");
}

static void render_pup_trophy_award(uint16_t id)
{
    char line[36];
    uint8_t icon = pup_trophy_icon(id);

    display_clear(UI_THEME_BG);
    draw_center_clip(4, "TROPHY!", COLOR_AMBER, UI_THEME_BG, 2);
    display_draw_image_masked_scaled((DISPLAY_W - PUP_ICON_W * 2) / 2, 24,
                                     PUP_ICON_W, PUP_ICON_H,
                                     PUP_ICON_PX[icon], PUP_ICON_MASK[icon], 2);
    draw_center_clip(58, pup_trophy_name(id),
                     pup_weight_color(pup_trophy_weight(id)), UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "+%u xp", (unsigned)pup_trophy_xp(id));
    draw_center_clip(70, line, UI_THEME_MUTED, UI_THEME_BG, 1);
}

static void draw_menu_footer(void);
typedef enum { RPANE_WIFI, RPANE_BLE, RPANE_PROBES, RPANE_PUP, RPANE_MAIN } results_pane_t;

static uint8_t results_panes(results_pane_t *panes)
{
    uint8_t n = 0;
    panes[n++] = RPANE_WIFI;
    if (s_advisor_mode == ADVISOR_MODE_ADV) {
        panes[n++] = RPANE_BLE;
        panes[n++] = RPANE_PROBES;
    }
    panes[n++] = RPANE_PUP;
    panes[n++] = RPANE_MAIN;
    return n;
}

static void render_options_locked(void)
{
    char line[32];

    ESP_LOGI(TAG, "SPLASH: RESULTS_MENU mode=%s nets=%u ble=%u",
             s_advisor_mode == ADVISOR_MODE_LITE ? "Lite" : "Adv",
             (unsigned)s_score_count, (unsigned)s_ble.count);

    display_clear(UI_THEME_BG);
    draw_menu_header("RESULTS");

    results_pane_t panes[5];
    uint8_t n = results_panes(panes);
    if (s_results_pane >= n) s_results_pane = 0;

    vp_status_t vpst;
    virtual_pup_get(&vpst);

    int y = 24;
    for (uint8_t i = 0; i < n; i++) {
        bool focus = (i == s_results_pane);
        const char *name; int count = -1;
        switch (panes[i]) {
        case RPANE_WIFI:   name = "WiFi";   count = s_score_count;             break;
        case RPANE_BLE:    name = "BLE";    count = s_ble.count;               break;
        case RPANE_PROBES: name = "Probes"; count = probe_req_log_entry_count(); break;
        case RPANE_PUP:    name = "Pup";    count = vpst.level;                break;
        default:           name = "Main Menu";                                break;
        }
        if (panes[i] == RPANE_PUP)
            snprintf(line, sizeof(line), "%c %-10s Lv%u", focus ? '>' : ' ', name,
                     (unsigned)count);
        else if (count >= 0)
            snprintf(line, sizeof(line), "%c %-10s %u", focus ? '>' : ' ', name,
                     (unsigned)count);
        else
            snprintf(line, sizeof(line), "%c %s", focus ? '>' : ' ', name);
        display_draw_string(10, y, line,
                            focus ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);
        y += 9;
    }
    draw_menu_footer();
}

static void render_wifi_locked(void)
{
    char line[32];

    const char *two_label = "results";

    if (!s_scan_valid) {
        ESP_LOGI(TAG, "SPLASH: WIFI_RESULTS no_scan");
        display_clear(UI_THEME_BG);
        draw_menu_header_plain("WIFI RESULTS");
        draw_center_clip(30, "No scan yet", COLOR_WHITE, UI_THEME_BG, 1);
        draw_action_footer_one(68, "[hold]", two_label);
        return;
    }

    if (s_score_count == 0) {
        ESP_LOGI(TAG, "SPLASH: WIFI_RESULTS no_safe");
        display_advisor_no_safe(s_score_count, s_n_2g, s_n_5g, s_ble.count);
        display_fill_rect(0, 64, DISPLAY_W, 16, UI_THEME_BG);
        draw_action_footer_one(68, "[hold]", two_label);
        return;
    }

    uint16_t disp_count = wifi_disp_count();
    if (s_wifi_index == 0 || s_wifi_index > disp_count) s_wifi_index = 1;

    const ap_score_t *ap = &s_scores[s_wifi_index - 1];

    ESP_LOGI(TAG, "SPLASH: WIFI_RESULTS mode=%s idx=%u/%u ssid=%s",
             s_advisor_mode == ADVISOR_MODE_LITE ? "Lite" : "Adv",
             (unsigned)s_wifi_index, (unsigned)disp_count, ap->ssid);

    if (s_advisor_mode == ADVISOR_MODE_LITE) {
        uint16_t verdict_col = verdict_band_color(analyzer_threat_to_verdict(ap->threat_level));
        const uint16_t lite_accent = UI_THEME_TITLE;
        bool short_ssid = (strlen(ap->ssid) <= 13);

        display_clear(UI_THEME_BG);
        draw_center_clip(6, "WIFI RESULTS", lite_accent, UI_THEME_BG, 1);

        snprintf(line, sizeof(line), "%u/%u",
                 (unsigned)s_wifi_index, (unsigned)disp_count);
        display_draw_string(2, 4, line, lite_accent, UI_THEME_BG, 1);

        const char *sig = wifi_signal_word(ap->rssi);
        display_draw_string(DISPLAY_W - ((int)strlen(sig) * 6) - 2, 4, sig,
                            lite_accent, UI_THEME_BG, 1);

        if (short_ssid) {
            snprintf(line, sizeof(line), "%.13s", ap->ssid);
            draw_center_clip(20, line, COLOR_WHITE, UI_THEME_BG, 2);
        } else {
            snprintf(line, sizeof(line), "%.26s", ap->ssid);
            draw_center_clip(24, line, COLOR_WHITE, UI_THEME_BG, 1);
        }

        display_blit_verdict(40, analyzer_threat_to_verdict(ap->threat_level));

        snprintf(line, sizeof(line), "%.26s",
                 ap->vendor[0] ? ap->vendor : "Vendor unknown");
        draw_center_clip(62, line, verdict_col, UI_THEME_BG, 1);
        draw_action_footer_two(72, "[1]", "next", "[2]", "details");
    } else {

        display_advisor_recommend(ap, (uint8_t)s_wifi_index,
                                  disp_count, s_n_2g, s_n_5g, s_ble.count);
        display_fill_rect(0, 70, DISPLAY_W, 10, UI_THEME_BG);
        draw_action_footer_two(72, "[1]", "next", "[2]", "details");
    }
}

typedef struct {
    uint8_t     class_id;
    const char *label;
} ble_class_row_t;

static const ble_class_row_t s_ble_class_rows[] = {
    { EUI_CLASS_PHONE,            "Phones"    },
    { EUI_CLASS_TABLET,           "Tablets"   },
    { EUI_CLASS_LAPTOP,           "Laptops"   },
    { EUI_CLASS_WEARABLE,         "Wearables" },
    { EUI_CLASS_AUDIO,            "Audio"     },
    { EUI_CLASS_TRACKER,          "Trackers"  },
    { EUI_CLASS_DRONE,            "Drones"    },
    { EUI_CLASS_IOT_LEAF,         "IoT sens"  },
    { EUI_CLASS_IOT_HUB,          "IoT app"   },
    { EUI_CLASS_ACCESS_CONTROL,   "Access"    },
    { EUI_CLASS_INFRASTRUCTURE,   "Infra"     },
    { EUI_CLASS_SURVEILLANCE_CAM, "Surveil"   },
    { EUI_CLASS_VEHICLE,          "Vehicle"   },
    { EUI_CLASS_MEDICAL,          "Medical"   },
    { EUI_CLASS_POS_PAYMENT,      "POS"       },
    { EUI_CLASS_MAKER_BOARD,      "Devboards" },
    { EUI_CLASS_ATTACK_SIGNAL,    "Pentest"   },
};
#define BLE_CLASS_ROW_COUNT  ((uint8_t)(sizeof(s_ble_class_rows) / sizeof(s_ble_class_rows[0])))

static uint8_t s_ble_class_focus = 0;

static uint16_t ble_class_row_color(uint8_t class_id)
{
    switch (class_id) {
        case EUI_CLASS_ATTACK_SIGNAL:    return COLOR_DANGER;
        case EUI_CLASS_SURVEILLANCE_CAM: return COLOR_DANGER;
        case EUI_CLASS_TRACKER:          return COLOR_CAUTION;
        case EUI_CLASS_DRONE:            return COLOR_CAUTION;
        case EUI_CLASS_MAKER_BOARD:      return COLOR_CAUTION;
        case EUI_CLASS_ACCESS_CONTROL:   return COLOR_OK;
        default:                         return COLOR_WHITE;
    }
}

static bool ble_passes_filter(uint16_t i)
{

    if (s_ble.devices[i].suppressed && s_advisor_mode != ADVISOR_MODE_ADV)
        return false;
    if (s_ble_class_filter == BLE_CLASS_FILTER_NONE) return true;
    uint8_t c = ble_effective_class(&s_ble.devices[i]);
    if (s_ble_class_filter == BLE_CLASS_FILTER_UNKNOWN) {
        for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
            if (s_ble_class_rows[b].class_id == c) return false;
        }
        return true;
    }
    return c == s_ble_class_filter;
}

static uint16_t ble_filter_count(void)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_ble.count; i++) {
        if (ble_passes_filter(i)) n++;
    }
    return n;
}

static uint16_t ble_filter_at(uint16_t filtered_idx)
{
    if (filtered_idx == 0) return 0xFFFF;
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_ble.count; i++) {
        if (ble_passes_filter(i)) {
            n++;
            if (n == filtered_idx) return i;
        }
    }
    return 0xFFFF;
}

static const char *ble_filter_label(void)
{
    if (s_ble_class_filter == BLE_CLASS_FILTER_NONE) return NULL;
    if (s_ble_class_filter == BLE_CLASS_FILTER_UNKNOWN) return "Unknown";
    for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
        if (s_ble_class_rows[b].class_id == s_ble_class_filter) {
            return s_ble_class_rows[b].label;
        }
    }
    return NULL;
}

static void render_ble_locked(void)
{

    const char *two_label = (s_advisor_mode == ADVISOR_MODE_ADV) ? "classes" : "results";

    if (!s_scan_valid) {
        ESP_LOGI(TAG, "SPLASH: BLE_RESULTS no_scan");
        display_clear(UI_THEME_BG);
        draw_menu_header("BLE RESULTS");
        draw_center_clip(30, "No scan yet", COLOR_WHITE, UI_THEME_BG, 1);
        draw_action_footer_one(68, "[hold]", two_label);
        return;
    }

    uint16_t filtered_total = ble_filter_count();
    const char *filter_label = ble_filter_label();

    if (s_ble.count == 0 || filtered_total == 0) {
        ESP_LOGI(TAG, "SPLASH: BLE_RESULTS none filter=%s",
                 filter_label ? filter_label : "(none)");
        display_clear(UI_THEME_BG);
        draw_menu_header("BLE RESULTS");
        if (filter_label) {
            char msg[40];
            snprintf(msg, sizeof(msg), "No %s devices", filter_label);
            draw_center_clip(30, msg, COLOR_CAUTION, UI_THEME_BG, 1);
        } else {
            draw_center_clip(30, "No devices", COLOR_DANGER, UI_THEME_BG, 1);
        }
        draw_action_footer_one(68, "[hold]", two_label);
        return;
    }

    if (s_ble_index == 0 || s_ble_index > filtered_total) s_ble_index = 1;

    uint16_t raw_idx = ble_filter_at(s_ble_index);
    if (raw_idx == 0xFFFF) {

        s_ble_index = 1;
        raw_idx = ble_filter_at(1);
        if (raw_idx == 0xFFFF) return;
    }
    const ble_device_t *d = &s_ble.devices[raw_idx];
    uint16_t band = verdict_band_color(analyzer_threat_to_verdict(d->threat_level));
    char line[40];

    ESP_LOGI(TAG, "SPLASH: BLE_RESULTS mode=%s filter=%s idx=%u/%u name=%s",
             s_advisor_mode == ADVISOR_MODE_LITE ? "Lite" : "Adv",
             filter_label ? filter_label : "(none)",
             (unsigned)s_ble_index, (unsigned)filtered_total,
             d->name[0] ? d->name : "(no local name)");

    display_clear(UI_THEME_BG);

    if (s_advisor_mode == ADVISOR_MODE_LITE) {
        const uint16_t lite_accent = UI_THEME_TITLE;

        display_clear(UI_THEME_BG);

        display_blit_verdict(2, analyzer_threat_to_verdict(d->threat_level));
        draw_center_clip(24, "BLE RESULTS", lite_accent, UI_THEME_BG, 2);

        snprintf(line, sizeof(line), "%u/%u",
                 (unsigned)s_ble_index, (unsigned)filtered_total);
        display_draw_string(DISPLAY_W - ((int)strlen(line) * 6) - 2, 4, line,
                            lite_accent, UI_THEME_BG, 1);

        uint16_t hidden = 0;
        for (uint16_t k = 0; k < s_ble.count; k++)
            if (s_ble.devices[k].suppressed) hidden++;
        if (hidden > 0) {
            snprintf(line, sizeof(line), "+%u anon", (unsigned)hidden);
            display_draw_string(DISPLAY_W - ((int)strlen(line) * 6) - 2, 13, line,
                                UI_THEME_MUTED, UI_THEME_BG, 1);
        }

        snprintf(line, sizeof(line), "%.26s", d->name[0] ? d->name : "(no local name)");
        draw_center_clip(42, line, COLOR_WHITE, UI_THEME_BG, 1);

        snprintf(line, sizeof(line), "%.26s",
                 d->vendor[0] ? d->vendor : "Vendor unknown");
        draw_center_clip(50, line, band, UI_THEME_BG, 1);

        format_distance_line(line, sizeof(line), d->rssi, d->distance_dm);

        draw_center_clip(58, line, COLOR_HEADER, UI_THEME_BG, 1);
        draw_action_footer_two(72, "[1]", "next", "[2]", "details");
        return;
    }

    draw_line_clip(4, d->name[0] ? d->name : "(no local name)",
                   COLOR_HEADER, UI_THEME_BG);

    if (filter_label) {
        snprintf(line, sizeof(line), "%s %u/%u",
                 filter_label, (unsigned)s_ble_index, (unsigned)filtered_total);
    } else {
        snprintf(line, sizeof(line), "%u/%u",
                 (unsigned)s_ble_index, (unsigned)filtered_total);
    }
    display_draw_string(DISPLAY_W - (int)strlen(line) * 6 - 2, 4, line,
                        filter_label ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_line_clip(22, verdict_label(analyzer_threat_to_verdict(d->threat_level)), band, UI_THEME_BG);
    snprintf(line, sizeof(line), "Ident:%u/100", (unsigned)d->identity_score);
    display_draw_string(DISPLAY_W - (int)strlen(line) * 6 - 2, 22, line,
                        band, UI_THEME_BG, 1);
    draw_line_clip(31, d->company_name[0] ? d->company_name : "company unknown",
                   COLOR_WHITE, UI_THEME_BG);

    {
        uint8_t eff_cls = ble_effective_class_certain(d);
        const char *cls_label = eui_class_label(eff_cls);
        if (cls_label && cls_label[0]) {
            if (d->vendor[0]) {
                snprintf(line, sizeof(line), "%s [%c] - %.20s",
                         cls_label, ble_class_conf_letter(d), d->vendor);
            } else {
                snprintf(line, sizeof(line), "%s [%c]",
                         cls_label, ble_class_conf_letter(d));
            }
            draw_line_clip(40, line, ble_class_row_color(eff_cls), UI_THEME_BG);
        } else {
            draw_line_clip(40, d->vendor[0] ? d->vendor : "vendor unknown",
                           UI_THEME_MUTED, UI_THEME_BG);
        }
    }

    format_distance_line(line, sizeof(line), d->rssi, d->distance_dm);

    draw_center_clip(49, line, COLOR_HEADER, UI_THEME_BG, 1);

    snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X",
             d->addr[0], d->addr[1], d->addr[2], d->addr[3], d->addr[4], d->addr[5]);
    draw_line_clip(58, line, rgb565be(160, 160, 160), UI_THEME_BG);

    draw_action_footer_two(72, "[1]", "next", "[2]", "details");
}

static void render_details_wifi_locked(void)
{
    if (wifi_disp_count() == 0 || s_wifi_index == 0 ||
        s_wifi_index > wifi_disp_count()) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }
    const ap_score_t *ap = &s_scores[s_wifi_index - 1];

    vetter_result_t vr;
    vetter_run(ap, &s_ble, &vr);

    uint8_t total;
    if (s_advisor_mode == ADVISOR_MODE_LITE)
        total = display_details_wifi_lite(ap, &vr, s_details_page);
    else
        total = display_details_wifi_adv (ap, &vr, &s_ble, s_details_page);
    if (total == 0) total = 1;
    s_details_total = total;
    if (s_details_page >= total) {
        s_details_page = 0;
        if (s_advisor_mode == ADVISOR_MODE_LITE)
            display_details_wifi_lite(ap, &vr, 0);
        else
            display_details_wifi_adv (ap, &vr, &s_ble, 0);
    }
}

static void render_details_ble_locked(void)
{
    uint16_t total_filtered = ble_filter_count();
    if (total_filtered == 0 || s_ble_index == 0 || s_ble_index > total_filtered) {
        s_ui_mode = UI_MODE_MAIN;
        s_ble_class_filter = BLE_CLASS_FILTER_NONE;
        render_main_locked();
        return;
    }
    uint16_t raw_idx = ble_filter_at(s_ble_index);
    if (raw_idx == 0xFFFF) {
        s_ui_mode = UI_MODE_MAIN;
        s_ble_class_filter = BLE_CLASS_FILTER_NONE;
        render_main_locked();
        return;
    }
    const ble_device_t *d = &s_ble.devices[raw_idx];

    uint8_t total;
    if (s_advisor_mode == ADVISOR_MODE_LITE)
        total = display_details_ble_lite(d, s_details_page);
    else
        total = display_details_ble_adv (d, s_scores, s_score_count, s_details_page);
    if (total == 0) total = 1;
    s_details_total = total;
    if (s_details_page >= total) {
        s_details_page = 0;
        if (s_advisor_mode == ADVISOR_MODE_LITE)
            display_details_ble_lite(d, 0);
        else
            display_details_ble_adv (d, s_scores, s_score_count, 0);
    }
}

static void render_ble_classes_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    uint16_t counts[BLE_CLASS_ROW_COUNT];
    memset(counts, 0, sizeof(counts));
    uint16_t unknown_count = 0;

    for (uint16_t i = 0; i < s_ble.count; i++) {
        if (s_ble.devices[i].suppressed) continue;
        uint8_t c = ble_effective_class(&s_ble.devices[i]);
        bool bucketed = false;
        for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
            if (s_ble_class_rows[b].class_id == c) {
                counts[b]++;
                bucketed = true;
                break;
            }
        }
        if (!bucketed) unknown_count++;
    }

    struct { const char *label; uint16_t count; uint8_t cls; } visible[BLE_CLASS_ROW_COUNT + 1];
    uint8_t n_visible = 0;
    for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
        if (counts[b] > 0) {
            visible[n_visible].label = s_ble_class_rows[b].label;
            visible[n_visible].count = counts[b];
            visible[n_visible].cls   = s_ble_class_rows[b].class_id;
            n_visible++;
        }
    }
    if (unknown_count > 0) {
        visible[n_visible].label = "Unknown";
        visible[n_visible].count = unknown_count;
        visible[n_visible].cls   = EUI_CLASS_UNKNOWN;
        n_visible++;
    }

    if (s_ble_class_focus >= n_visible) s_ble_class_focus = 0;

    ESP_LOGI(TAG, "SPLASH: BLE_CLASSES rows=%u total=%u focus=%u",
             (unsigned)n_visible, (unsigned)s_ble.count, (unsigned)s_ble_class_focus);

    display_clear(UI_THEME_BG);
    draw_menu_header("CLASSES");

    if (n_visible == 0) {
        draw_center_clip(30, "No devices", COLOR_DANGER, UI_THEME_BG, 1);
        draw_action_footer_one(68, "[hold]", "results");
        return;
    }

    char line[24];
    const int col0_x = 4;
    const int col1_x = DISPLAY_W / 2 + 2;
    const int row_h  = 8;
    const int body_y = 20;
    const uint8_t per_col = 4;
    const uint8_t max_visible = per_col * 2;
    uint8_t shown = n_visible > max_visible ? max_visible : n_visible;

    for (uint8_t r = 0; r < shown; r++) {
        int x = (r < per_col) ? col0_x : col1_x;
        int y = body_y + ((r % per_col) * row_h);
        bool focused = (r == s_ble_class_focus);
        uint16_t class_col = ble_class_row_color(visible[r].cls);
        uint16_t fg = focused ? UI_THEME_BG : class_col;
        uint16_t bg = focused ? class_col   : UI_THEME_BG;
        if (focused) {
            display_fill_rect(x - 2, y - 1, DISPLAY_W / 2 - 2, row_h, bg);
        }
        snprintf(line, sizeof(line), "%-9s %u", visible[r].label, (unsigned)visible[r].count);
        display_draw_string(x, y, line, fg, bg, 1);
    }

    draw_action_footer_two(72, "[1]", "next", "[2]", "explore");
}

static uint16_t ssid_category_color(ssid_category_t cat)
{
    switch (cat) {
        case SSID_CAT_PII:       return COLOR_DANGER;
        case SSID_CAT_CORPORATE: return COLOR_CAUTION;
        case SSID_CAT_HOTEL:
        case SSID_CAT_AIRPORT:   return COLOR_OK;
        case SSID_CAT_ISP:
        case SSID_CAT_GENERIC:   return COLOR_HEADER;
        case SSID_CAT_HIDDEN:
        case SSID_CAT_OTHER:     return UI_THEME_MUTED;
        default:                 return UI_THEME_MUTED;
    }
}

static void render_probe_log_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    const probe_req_log_aggregate_t *sl = probe_req_log_get();

    ESP_LOGI(TAG, "SPLASH: PROBE_LOG total=%u directed=%u",
             (unsigned)sl->total_probe_reqs,
             (unsigned)sl->directed_probe_reqs);

    display_clear(UI_THEME_BG);
    draw_menu_header("PROBE LOG");

    uint16_t entries = probe_req_log_entry_count();

    if (sl->total_probe_reqs == 0) {
        draw_center_clip(30, "No probes seen", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(68, "[2]", "seq");
        return;
    }

    char line[24];
    const int col0_x = 4;
    const int col1_x = DISPLAY_W / 2 + 2;
    const int row_h  = 8;
    const int body_y = 22;
    const uint8_t per_col = 4;

    for (uint8_t i = 0; i < SSID_CAT_COUNT; i++) {
        int x = (i < per_col) ? col0_x : col1_x;
        int y = body_y + ((i % per_col) * row_h);
        uint16_t col = ssid_category_color((ssid_category_t)i);

        if (sl->counts[i] == 0) col = UI_THEME_MUTED;
        snprintf(line, sizeof(line), "%-9s %u",
                 ssid_category_label((ssid_category_t)i),
                 (unsigned)sl->counts[i]);
        display_draw_string(x, y, line, col, UI_THEME_BG, 1);
    }

    if (entries > 0) {
        draw_action_footer_two(72, "[1]", "explore", "[2]", "seq");
    } else {
        draw_action_footer_one(72, "[2]", "seq");
    }
}

static void render_seq_link_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    const seq_analyzer_aggregate_t *sa = seq_analyzer_get();
    uint16_t entries = seq_analyzer_entry_count();

    ESP_LOGI(TAG, "SPLASH: SEQ_LINK total=%u distinct=%u linked=%u apparent=%u entries=%u",
             (unsigned)sa->total_probe_reqs, (unsigned)sa->distinct_macs,
             (unsigned)sa->linked_pairs, (unsigned)sa->apparent_devices,
             (unsigned)entries);

    display_clear(UI_THEME_BG);
    draw_menu_header("SEQ");

    if (sa->total_probe_reqs == 0) {
        draw_center_clip(30, "No probes seen", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[2]", "ie");
        return;
    }

    char line[24];
    const int col0_x = 4;
    const int col1_x = DISPLAY_W / 2 + 2;
    const int row_h  = 8;
    const int body_y = 22;

    snprintf(line, sizeof(line), "Total:    %u", (unsigned)sa->total_probe_reqs);
    display_draw_string(col0_x, body_y + 0 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Distinct: %u", (unsigned)sa->distinct_macs);
    display_draw_string(col0_x, body_y + 1 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Linked:   %u", (unsigned)sa->linked_pairs);
    uint16_t linked_col = sa->linked_pairs > 0 ? COLOR_CAUTION : UI_THEME_MUTED;
    display_draw_string(col0_x, body_y + 2 * row_h, line, linked_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Apparent: %u", (unsigned)sa->apparent_devices);
    display_draw_string(col0_x, body_y + 3 * row_h, line, COLOR_OK, UI_THEME_BG, 1);

    snprintf(line, sizeof(line), "Seq11: %u", (unsigned)sa->chipset_seq11);
    display_draw_string(col1_x, body_y + 0 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Seq12: %u", (unsigned)sa->chipset_seq12);
    display_draw_string(col1_x, body_y + 1 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Drop:  %u", (unsigned)sa->entries_dropped);
    uint16_t drop_col = sa->entries_dropped > 0 ? COLOR_CAUTION : UI_THEME_MUTED;
    display_draw_string(col1_x, body_y + 2 * row_h, line, drop_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "MACs:  %u", (unsigned)entries);
    display_draw_string(col1_x, body_y + 3 * row_h, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    if (entries > 0) {
        draw_action_footer_two(72, "[1]", "explore", "[2]", "ie");
    } else {
        draw_action_footer_one(72, "[2]", "ie");
    }
}

static void render_ie_sig_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    const ie_signature_aggregate_t *ia = ie_signature_get();
    uint16_t entries = ie_signature_entry_count();

    ESP_LOGI(TAG, "SPLASH: IE_SIG total=%u distinct=%u hashes=%u recog=%u mism=%u entries=%u",
             (unsigned)ia->total_probe_reqs, (unsigned)ia->distinct_macs,
             (unsigned)ia->distinct_hashes, (unsigned)ia->recognized_macs,
             (unsigned)ia->mismatched_macs, (unsigned)entries);

    display_clear(UI_THEME_BG);
    draw_menu_header("IE");

    if (ia->total_probe_reqs == 0) {
        draw_center_clip(30, "No probes seen", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[2]", "anqp");
        return;
    }

    char line[24];
    const int col0_x = 4;
    const int col1_x = DISPLAY_W / 2 + 2;
    const int row_h  = 8;
    const int body_y = 22;

    snprintf(line, sizeof(line), "Total:    %u", (unsigned)ia->total_probe_reqs);
    display_draw_string(col0_x, body_y + 0 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Distinct: %u", (unsigned)ia->distinct_macs);
    display_draw_string(col0_x, body_y + 1 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Hashes:   %u", (unsigned)ia->distinct_hashes);
    display_draw_string(col0_x, body_y + 2 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Recog:    %u", (unsigned)ia->recognized_macs);
    uint16_t recog_col = ia->recognized_macs > 0 ? COLOR_OK : UI_THEME_MUTED;
    display_draw_string(col0_x, body_y + 3 * row_h, line, recog_col, UI_THEME_BG, 1);

    snprintf(line, sizeof(line), "Mism:  %u", (unsigned)ia->mismatched_macs);
    uint16_t mism_col = ia->mismatched_macs > 0 ? COLOR_DANGER : UI_THEME_MUTED;
    display_draw_string(col1_x, body_y + 0 * row_h, line, mism_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Top:   %u", (unsigned)ia->top_hash_macs);
    display_draw_string(col1_x, body_y + 1 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Drop:  %u", (unsigned)ia->entries_dropped);
    uint16_t drop_col = ia->entries_dropped > 0 ? COLOR_CAUTION : UI_THEME_MUTED;
    display_draw_string(col1_x, body_y + 2 * row_h, line, drop_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "MACs:  %u", (unsigned)entries);
    display_draw_string(col1_x, body_y + 3 * row_h, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    if (entries > 0) {
        draw_action_footer_two(72, "[1]", "explore", "[2]", "anqp");
    } else {
        draw_action_footer_one(72, "[2]", "anqp");
    }
}

static void render_anqp_leak_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    const anqp_analyzer_aggregate_t *aa = anqp_analyzer_get();
    uint16_t entries = anqp_analyzer_entry_count();

    ESP_LOGI(TAG, "SPLASH: ANQP_LEAK total=%u distinct=%u univ=%u laa=%u entries=%u",
             (unsigned)aa->total_queries, (unsigned)aa->distinct_macs,
             (unsigned)aa->universal_macs, (unsigned)aa->laa_macs,
             (unsigned)entries);

    display_clear(UI_THEME_BG);
    draw_menu_header("ANQP");

    if (aa->total_queries == 0) {
        draw_center_clip(30, "No ANQP queries", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[2]", "probe");
        return;
    }

    char line[24];
    const int col0_x = 4;
    const int col1_x = DISPLAY_W / 2 + 2;
    const int row_h  = 8;
    const int body_y = 22;

    snprintf(line, sizeof(line), "Total:    %u", (unsigned)aa->total_queries);
    display_draw_string(col0_x, body_y + 0 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Distinct: %u", (unsigned)aa->distinct_macs);
    display_draw_string(col0_x, body_y + 1 * row_h, line, COLOR_WHITE, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "Univ:     %u", (unsigned)aa->universal_macs);
    uint16_t univ_col = aa->universal_macs > 0 ? COLOR_DANGER : UI_THEME_MUTED;
    display_draw_string(col0_x, body_y + 2 * row_h, line, univ_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "LAA:      %u", (unsigned)aa->laa_macs);
    uint16_t laa_col = aa->laa_macs > 0 ? COLOR_OK : UI_THEME_MUTED;
    display_draw_string(col0_x, body_y + 3 * row_h, line, laa_col, UI_THEME_BG, 1);

    snprintf(line, sizeof(line), "Drop:  %u", (unsigned)aa->entries_dropped);
    uint16_t drop_col = aa->entries_dropped > 0 ? COLOR_CAUTION : UI_THEME_MUTED;
    display_draw_string(col1_x, body_y + 0 * row_h, line, drop_col, UI_THEME_BG, 1);
    snprintf(line, sizeof(line), "MACs:  %u", (unsigned)entries);
    display_draw_string(col1_x, body_y + 1 * row_h, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    if (entries > 0) {
        draw_action_footer_two(72, "[1]", "explore", "[2]", "probe");
    } else {
        draw_action_footer_one(72, "[2]", "probe");
    }
}

#define EXPLORE_VISIBLE_ROWS 5

typedef struct {
    char     label[24];
    uint16_t hits;
    uint16_t flag_col;
    uint8_t  src_mac[6];
    char     ssid[33];
    bool     has_ssid;
    bool     anqp;
} explore_row_t;

static const char *explore_panel_title(void)
{
    switch (s_explore_panel) {
        case EXP_SEQ:   return "Explore SEQ";
        case EXP_IE:    return "Explore IE";
        case EXP_ANQP:  return "Explore ANQP";
        case EXP_PROBE: default: return "Explore PROBE";
    }
}

static ui_mode_t explore_panel_counts_mode(void)
{
    switch (s_explore_panel) {
        case EXP_SEQ:   return UI_MODE_SEQ_LINK;
        case EXP_IE:    return UI_MODE_IE_SIG;
        case EXP_ANQP:  return UI_MODE_ANQP_LEAK;
        case EXP_PROBE: default: return UI_MODE_PROBE_LOG;
    }
}

static void explore_render_counts_panel(void)
{
    switch (s_explore_panel) {
        case EXP_SEQ:   render_seq_link_locked();  break;
        case EXP_IE:    render_ie_sig_locked();    break;
        case EXP_ANQP:  render_anqp_leak_locked(); break;
        case EXP_PROBE: default: render_probe_log_locked(); break;
    }
}

static uint16_t explore_entry_count(void)
{
    switch (s_explore_panel) {
        case EXP_SEQ:   return seq_analyzer_entry_count();
        case EXP_IE:    return ie_signature_entry_count();
        case EXP_ANQP:  return anqp_analyzer_entry_count();
        case EXP_PROBE: default: return probe_req_log_entry_count();
    }
}

static bool explore_get_row(uint16_t idx, explore_row_t *r)
{
    memset(r, 0, sizeof(*r));
    switch (s_explore_panel) {
    case EXP_PROBE: {
        const probe_req_log_entry_t *e = probe_req_log_entry_at(idx);
        if (!e) return false;
        memcpy(r->src_mac, e->src_mac, 6);
        strlcpy(r->ssid, e->ssid, sizeof(r->ssid));
        r->has_ssid = true;
        r->hits = e->hit_count;
        bool hidden = (e->category == SSID_CAT_HIDDEN) || !e->ssid[0];
        snprintf(r->label, sizeof(r->label), "%.22s", hidden ? "<hidden>" : e->ssid);
        if (!hidden && !e->local_visible) r->flag_col = COLOR_DANGER;
        return true;
    }
    case EXP_SEQ: {
        const seq_analyzer_entry_t *e = seq_analyzer_entry_at(idx);
        if (!e) return false;
        memcpy(r->src_mac, e->mac, 6);
        r->hits = e->hit_count;
        snprintf(r->label, sizeof(r->label), "%02X:%02X:%02X", e->mac[3], e->mac[4], e->mac[5]);
        if (e->linked_into) r->flag_col = COLOR_CAUTION;
        return true;
    }
    case EXP_IE: {
        const ie_signature_entry_t *e = ie_signature_entry_at(idx);
        if (!e) return false;
        memcpy(r->src_mac, e->mac, 6);
        r->hits = e->hit_count;
        snprintf(r->label, sizeof(r->label), "%02X:%02X:%02X", e->mac[3], e->mac[4], e->mac[5]);
        if (e->mismatch) r->flag_col = COLOR_DANGER;
        return true;
    }
    case EXP_ANQP: {
        const anqp_analyzer_entry_t *e = anqp_analyzer_entry_at(idx);
        if (!e) return false;
        memcpy(r->src_mac, e->mac, 6);
        r->hits = e->hit_count;
        r->anqp = true;
        snprintf(r->label, sizeof(r->label), "%02X:%02X:%02X", e->mac[3], e->mac[4], e->mac[5]);
        if (e->universal) r->flag_col = COLOR_DANGER;
        return true;
    }
    }
    return false;
}

static void render_probe_explore_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    uint16_t total = explore_entry_count();
    if (total == 0) {
        s_ui_mode = explore_panel_counts_mode();
        explore_render_counts_panel();
        return;
    }
    if (s_explore_cursor >= total) s_explore_cursor = 0;

    ESP_LOGI(TAG, "SPLASH: PROBE_EXPLORE panel=%d cursor=%u/%u",
             (int)s_explore_panel, (unsigned)s_explore_cursor, (unsigned)total);

    display_clear(UI_THEME_BG);
    draw_menu_header(explore_panel_title());

    uint16_t page  = s_explore_cursor / EXPLORE_VISIBLE_ROWS;
    uint16_t start = page * EXPLORE_VISIBLE_ROWS;
    const int row_h  = 9;
    const int body_y = 22;

    char line[40];
    for (uint16_t r = 0; r < EXPLORE_VISIBLE_ROWS; r++) {
        uint16_t idx = start + r;
        if (idx >= total) break;
        explore_row_t row;
        if (!explore_get_row(idx, &row)) break;

        int y = body_y + r * row_h;
        bool focused = (idx == s_explore_cursor);
        uint16_t key_col = row.flag_col ? row.flag_col : COLOR_WHITE;

        if (focused) {
            display_fill_rect(2, y - 1, DISPLAY_W - 4, row_h, key_col);
            snprintf(line, sizeof(line), "%.16s", row.label);
            display_draw_string(4, y, line, UI_THEME_BG, key_col, 1);
            snprintf(line, sizeof(line), "x%u", (unsigned)row.hits);
            int w = (int)strlen(line) * 6;
            display_draw_string(DISPLAY_W - 4 - w, y, line, UI_THEME_BG, key_col, 1);
        } else {
            snprintf(line, sizeof(line), "%.16s", row.label);
            display_draw_string(4, y, line, key_col, UI_THEME_BG, 1);
            snprintf(line, sizeof(line), "x%u", (unsigned)row.hits);
            int w = (int)strlen(line) * 6;
            display_draw_string(DISPLAY_W - 4 - w, y, line, UI_THEME_MUTED, UI_THEME_BG, 1);
        }
    }

    draw_action_footer_two(72, "[1]", "next", "[2]", "dig");
}

static uint16_t probe_dig_total(void)
{
    explore_row_t row;
    if (!explore_get_row(s_explore_cursor, &row)) return 0;
    if (row.has_ssid) return probe_frame_ring_count_for_ssid_mac(row.ssid, row.src_mac);
    return probe_frame_ring_count_for_mac(row.src_mac, row.anqp);
}

static void render_probe_dig_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    explore_row_t row;
    if (!explore_get_row(s_explore_cursor, &row)) {
        s_ui_mode = UI_MODE_PROBE_EXPLORE;
        render_probe_explore_locked();
        return;
    }

    uint16_t total;
    if (row.has_ssid) total = probe_frame_ring_count_for_ssid_mac(row.ssid, row.src_mac);
    else              total = probe_frame_ring_count_for_mac(row.src_mac, row.anqp);

    display_clear(UI_THEME_BG);

    if (total == 0) {
        draw_menu_header_plain("DIG 0/0");
        draw_center_clip(34, "No frames retained", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[hold]", "back");
        return;
    }
    if (s_dig_frame >= total) s_dig_frame = 0;

    const probe_frame_t *f;
    if (row.has_ssid) f = probe_frame_ring_nth_for_ssid_mac(row.ssid, row.src_mac, s_dig_frame);
    else              f = probe_frame_ring_nth_for_mac(row.src_mac, row.anqp, s_dig_frame);
    if (!f) {
        s_ui_mode = UI_MODE_PROBE_EXPLORE;
        render_probe_explore_locked();
        return;
    }

    ESP_LOGI(TAG, "SPLASH: PROBE_DIG panel=%d frame=%u/%u anqp=%d",
             (int)s_explore_panel, (unsigned)s_dig_frame, (unsigned)total, (int)f->is_anqp);

    char title[20];
    snprintf(title, sizeof(title), "DIG %u/%u", (unsigned)(s_dig_frame + 1), (unsigned)total);
    draw_menu_header_plain(title);

    char line[40];

    snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X",
             f->src_mac[0], f->src_mac[1], f->src_mac[2],
             f->src_mac[3], f->src_mac[4], f->src_mac[5]);
    display_draw_string(4, 20, line, COLOR_WHITE, UI_THEME_BG, 1);

    if (f->is_anqp) {
        display_draw_string(4, 29, "ANQP/GAS query", COLOR_HEADER, UI_THEME_BG, 1);
    } else if (row.has_ssid) {
        if (f->ssid[0]) snprintf(line, sizeof(line), "%.26s", f->ssid);
        else            snprintf(line, sizeof(line), "<wildcard>");
        display_draw_string(4, 29, line, UI_THEME_MUTED, UI_THEME_BG, 1);
    } else {
        display_draw_string(4, 29, "probe-request", UI_THEME_MUTED, UI_THEME_BG, 1);
    }

    snprintf(line, sizeof(line), "rssi %d dBm  ch %u",
             (int)f->rssi, (unsigned)f->channel);
    display_draw_string(4, 38, line, COLOR_OK, UI_THEME_BG, 1);

    if (!f->is_anqp) {
        snprintf(line, sizeof(line), "seq %u", (unsigned)f->seq_num);
        display_draw_string(4, 47, line, UI_THEME_MUTED, UI_THEME_BG, 1);
        snprintf(line, sizeof(line), "IE 0x%08lx", (unsigned long)f->ie_hash);
        display_draw_string(4, 56, line, UI_THEME_MUTED, UI_THEME_BG, 1);
    }

    snprintf(line, sizeof(line), "t+%lums  sc%u",
             (unsigned long)f->ts_ms, (unsigned)f->scan_idx);
    display_draw_string(4, 63, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_footer_two(72, "[1]", "next", "[2]", "prev");
}

static void render_ble_explore_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    uint16_t total = ble_filter_count();
    if (total == 0) {
        s_ui_mode = UI_MODE_BLE_CLASSES;
        render_ble_classes_locked();
        return;
    }
    if (s_ble_explore_cursor >= total) s_ble_explore_cursor = 0;

    ESP_LOGI(TAG, "SPLASH: BLE_EXPLORE cursor=%u/%u filter=0x%02X",
             (unsigned)s_ble_explore_cursor, (unsigned)total, s_ble_class_filter);

    display_clear(UI_THEME_BG);
    draw_menu_header("Explore BLE");

    uint16_t page  = s_ble_explore_cursor / EXPLORE_VISIBLE_ROWS;
    uint16_t start = page * EXPLORE_VISIBLE_ROWS;
    const int row_h  = 9;
    const int body_y = 22;

    char line[40];
    for (uint16_t r = 0; r < EXPLORE_VISIBLE_ROWS; r++) {
        uint16_t fidx = start + r;
        if (fidx >= total) break;
        uint16_t raw = ble_filter_at(fidx + 1);
        if (raw == 0xFFFF) break;
        const ble_device_t *d = &s_ble.devices[raw];

        const char *name = d->name[0] ? d->name :
                           (d->vendor[0] ? d->vendor : "(no name)");
        int y = body_y + r * row_h;
        bool focused = (fidx == s_ble_explore_cursor);
        uint16_t cls_col = ble_class_row_color(ble_effective_class(d));

        if (focused) {
            display_fill_rect(2, y - 1, DISPLAY_W - 4, row_h, cls_col);
            snprintf(line, sizeof(line), "%.16s", name);
            display_draw_string(4, y, line, UI_THEME_BG, cls_col, 1);
            snprintf(line, sizeof(line), "%d", (int)d->rssi);
            int w = (int)strlen(line) * 6;
            display_draw_string(DISPLAY_W - 4 - w, y, line, UI_THEME_BG, cls_col, 1);
        } else {
            snprintf(line, sizeof(line), "%.16s", name);
            display_draw_string(4, y, line, cls_col, UI_THEME_BG, 1);
            snprintf(line, sizeof(line), "%d", (int)d->rssi);
            int w = (int)strlen(line) * 6;
            display_draw_string(DISPLAY_W - 4 - w, y, line, UI_THEME_MUTED, UI_THEME_BG, 1);
        }
    }

    draw_action_footer_two(72, "[1]", "next", "[2]", "dig");
}

static void render_ble_dig_locked(void)
{
    if (s_advisor_mode != ADVISOR_MODE_ADV) {
        s_ui_mode = UI_MODE_MAIN;
        render_main_locked();
        return;
    }

    uint16_t dev_total = ble_filter_count();
    uint16_t raw = ble_filter_at(s_ble_explore_cursor + 1);
    if (dev_total == 0 || raw == 0xFFFF) {
        s_ui_mode = UI_MODE_BLE_EXPLORE;
        render_ble_explore_locked();
        return;
    }
    const ble_device_t *d = &s_ble.devices[raw];

    uint16_t total = ble_adv_ring_count_for_addr(d->addr);

    display_clear(UI_THEME_BG);

    if (total == 0) {
        draw_menu_header_plain("ADV 0/0");
        draw_center_clip(34, "No frames retained", UI_THEME_MUTED, UI_THEME_BG, 1);
        draw_action_footer_one(72, "[hold]", "back");
        return;
    }
    if (s_ble_dig_frame >= total) s_ble_dig_frame = 0;

    const ble_adv_frame_t *f = ble_adv_ring_nth_for_addr(d->addr, s_ble_dig_frame);
    if (!f) {
        s_ui_mode = UI_MODE_BLE_EXPLORE;
        render_ble_explore_locked();
        return;
    }

    ESP_LOGI(TAG, "SPLASH: BLE_DIG frame=%u/%u len=%u",
             (unsigned)s_ble_dig_frame, (unsigned)total, (unsigned)f->data_len);

    char title[20];
    snprintf(title, sizeof(title), "ADV %u/%u", (unsigned)(s_ble_dig_frame + 1), (unsigned)total);
    draw_menu_header_plain(title);

    char line[40];
    snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X",
             f->addr[0], f->addr[1], f->addr[2], f->addr[3], f->addr[4], f->addr[5]);
    display_draw_string(4, 20, line, COLOR_WHITE, UI_THEME_BG, 1);

    const char *phy = (f->prim_phy == 3) ? "Coded" : (f->prim_phy == 2) ? "2M" : "1M";
    snprintf(line, sizeof(line), "rssi %d  phy %s", (int)f->rssi, phy);
    display_draw_string(4, 29, line, COLOR_OK, UI_THEME_BG, 1);

    if (f->tx_power == 127) snprintf(line, sizeof(line), "tx n/a  props 0x%02X", f->props);
    else                    snprintf(line, sizeof(line), "tx %d  props 0x%02X", (int)f->tx_power, f->props);
    display_draw_string(4, 38, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    char hex[40];
    int hp = 0;
    uint8_t show = f->data_len < 8 ? f->data_len : 8;
    for (uint8_t i = 0; i < show && hp < (int)sizeof(hex) - 3; i++)
        hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X", f->data[i]);
    snprintf(line, sizeof(line), "len %u: %.16s", (unsigned)f->data_len, hex);
    display_draw_string(4, 47, line, COLOR_HEADER, UI_THEME_BG, 1);

    if (f->data_len > 8) {
        hp = 0;
        for (uint8_t i = 8; i < f->data_len && i < 16 && hp < (int)sizeof(hex) - 3; i++)
            hp += snprintf(hex + hp, sizeof(hex) - hp, "%02X", f->data[i]);
        display_draw_string(4, 56, hex, COLOR_HEADER, UI_THEME_BG, 1);
    }

    snprintf(line, sizeof(line), "t+%lums  sc%u",
             (unsigned long)f->ts_ms, (unsigned)f->scan_idx);
    display_draw_string(4, 63, line, UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_footer_two(72, "[1]", "next", "[2]", "prev");
}

#define DL_ROW_COUNT 2
static void render_download_confirm_locked(void)
{
    char line[24];

    ESP_LOGI(TAG, "SPLASH: DOWNLOAD_CONFIRM timeout=%umin sel=%u",
             (unsigned)download_mode_get_timeout_minutes(), (unsigned)s_dl_sel);

    display_clear(UI_THEME_BG);
    draw_menu_header("LAUNCH AP");

    if (s_dl_sel >= DL_ROW_COUNT) s_dl_sel = 0;

    int y = 30;
    for (uint8_t i = 0; i < DL_ROW_COUNT; i++) {
        bool focus = (i == s_dl_sel);
        if (i == 0)
            snprintf(line, sizeof(line), "%c Start AP", focus ? '>' : ' ');
        else
            snprintf(line, sizeof(line), "%c Auto-off: %u min", focus ? '>' : ' ',
                     (unsigned)download_mode_get_timeout_minutes());
        display_draw_string(10, y, line,
                            focus ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);
        y += 11;
    }

    draw_menu_footer();
}

#define QR_BOX_PX 72
static const int s_qr_x0 = 4;
static const int s_qr_y0 = 4;

static void qr_draw_cb(esp_qrcode_handle_t qr)
{
    int size   = esp_qrcode_get_size(qr);
    int border = 2;
    int total  = size + 2 * border;
    int scale  = QR_BOX_PX / total;
    if (scale < 1) scale = 1;
    int px = total * scale;

    display_fill_rect(s_qr_x0, s_qr_y0, px, px, COLOR_WHITE);
    led_reassert();
    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            if (esp_qrcode_get_module(qr, x, y)) {
                display_fill_rect(s_qr_x0 + (border + x) * scale,
                                  s_qr_y0 + (border + y) * scale,
                                  scale, scale, COLOR_BLACK);
            }
        }
    }
}

#define DL_RIGHT_X     76
#define DL_COUNT_Y     44
#define DL_JOINED_Y    64
static void draw_download_countdown_locked(void)
{
    char line[20];

    display_fill_rect(DL_RIGHT_X, DL_COUNT_Y - 1, DISPLAY_W - DL_RIGHT_X,
                      DISPLAY_H - (DL_COUNT_Y - 1), UI_THEME_BG);
    dl_assert_led_locked();

    uint32_t secs = download_mode_get_seconds_remaining();
    snprintf(line, sizeof(line), "%02u:%02u",
             (unsigned)(secs / 60), (unsigned)(secs % 60));
    uint16_t col = (secs <= 60) ? COLOR_CAUTION : COLOR_SAFE;
    display_draw_string(DL_RIGHT_X, DL_COUNT_Y, line, col, UI_THEME_BG, 2);
    dl_assert_led_locked();

    snprintf(line, sizeof(line), "joined %u/2",
             (unsigned)download_mode_get_client_count());
    display_draw_string(DL_RIGHT_X, DL_JOINED_Y, line, UI_THEME_MUTED, UI_THEME_BG, 1);
    display_draw_string(DL_RIGHT_X, 73, "[hold] stop", UI_THEME_MUTED, UI_THEME_BG, 1);
    dl_assert_led_locked();
}

static void render_download_active_locked(void)
{
    download_state_t st = download_mode_get_state();

    ESP_LOGI(TAG, "SPLASH: DOWNLOAD_ACTIVE state=%d", (int)st);

    display_clear(UI_THEME_BG);
    dl_assert_led_locked();

    if (st != DL_AP_ACTIVE) {

        draw_center_clip(34,
            (st == DL_AP_STOPPING) ? "Stopping..." : "Starting AP...",
            COLOR_OK, UI_THEME_BG, 1);
        dl_assert_led_locked();
        return;
    }

    const char *ssid = download_mode_get_ssid();
    const char *pass = download_mode_get_passphrase();
    bool joined = (download_mode_get_client_count() > 0);

    char payload[64];
    if (joined) {
        snprintf(payload, sizeof(payload), "http://192.168.4.1/");
    } else {
        snprintf(payload, sizeof(payload), "WIFI:T:WPA2;S:%s;P:%s;;", ssid, pass);
    }
    esp_qrcode_config_t qcfg = ESP_QRCODE_CONFIG_DEFAULT();
    qcfg.display_func       = qr_draw_cb;
    qcfg.max_qrcode_version = 4;
    qcfg.qrcode_ecc_level   = ESP_QRCODE_ECC_LOW;
    if (esp_qrcode_generate(&qcfg, payload) != ESP_OK) {
        display_draw_string(s_qr_x0, 34, "QR err", COLOR_DANGER, UI_THEME_BG, 1);
    }
    dl_assert_led_locked();

    display_draw_string(DL_RIGHT_X, 4,  ssid, COLOR_WHITE, UI_THEME_BG, 1);
    if (joined) {
        display_draw_string(DL_RIGHT_X, 18, "scan to open", UI_THEME_MUTED, UI_THEME_BG, 1);
        display_draw_string(DL_RIGHT_X, 28, "192.168.4.1", COLOR_OK, UI_THEME_BG, 1);
    } else {
        display_draw_string(DL_RIGHT_X, 18, "pass:", UI_THEME_MUTED, UI_THEME_BG, 1);
        display_draw_string(DL_RIGHT_X, 28, pass, COLOR_OK, UI_THEME_BG, 1);
    }

    s_dl_last_drawn_joined = joined ? 1 : 0;
    draw_download_countdown_locked();
}

typedef struct {
    const char *role;
    const char *name;
    const char *url;
} credit_entry_t;

static const credit_entry_t s_credits[] = {
    { "AUTHOR",      "jLaHire",  "https://github.com/jlahire"   },
    { "CONTRIBUTOR", "Arty",     "https://github.com/Runndownn" },
    { "CONTRIBUTOR", "SedK-CSS", "https://github.com/SedK-CSS"  },
};
#define CREDIT_COUNT ((uint8_t)(sizeof(s_credits) / sizeof(s_credits[0])))

static void render_credits_locked(void)
{
    if (s_credit_index >= CREDIT_COUNT) s_credit_index = 0;
    const credit_entry_t *c = &s_credits[s_credit_index];

    ESP_LOGI(TAG, "SPLASH: CREDITS idx=%u/%u name=%s url=%s",
             (unsigned)(s_credit_index + 1), (unsigned)CREDIT_COUNT, c->name, c->url);

    display_clear(UI_THEME_BG);

    esp_qrcode_config_t qcfg = ESP_QRCODE_CONFIG_DEFAULT();
    qcfg.display_func       = qr_draw_cb;
    qcfg.max_qrcode_version = 4;
    qcfg.qrcode_ecc_level   = ESP_QRCODE_ECC_LOW;
    if (esp_qrcode_generate(&qcfg, c->url) != ESP_OK) {
        display_draw_string(s_qr_x0, 34, "QR err", COLOR_DANGER, UI_THEME_BG, 1);
    }

    const int rw = DISPLAY_W - DL_RIGHT_X;
    display_draw_string(DL_RIGHT_X, 4,  c->role, UI_THEME_MUTED, UI_THEME_BG, 1);
    display_draw_string(DL_RIGHT_X, 16, c->name, COLOR_HEADER,   UI_THEME_BG, 1);
    display_draw_string(DL_RIGHT_X, 28, "scan QR", UI_THEME_MUTED, UI_THEME_BG, 1);

    draw_action_pair_region(DL_RIGHT_X, rw, 54, "[1]", "next");
    draw_action_pair_region(DL_RIGHT_X, rw, 64, "[2]", "back");
}

#define MENU_ACTIVITY(slug, MODE_ENUM, render_fn)                     \
    static void slug##_render(void *ctx) { (void)ctx; render_fn(); }  \
    static void slug##_on_enter(void *ctx) {                          \
        (void)ctx;                                                    \
        s_ui_mode = (MODE_ENUM);                                      \
        render_fn();                                                  \
    }                                                                 \
    static const ui_activity_t slug##_activity = {                    \
        .name     = #slug,                                            \
        .on_enter = slug##_on_enter,                                  \
        .render   = slug##_render,                                    \
    }

MENU_ACTIVITY(options,       UI_MODE_OPTIONS,       render_options_locked);

MENU_ACTIVITY(wifi_list,     UI_MODE_WIFI_LIST,     render_wifi_locked);
MENU_ACTIVITY(ble_list,      UI_MODE_BLE_LIST,      render_ble_locked);
MENU_ACTIVITY(details_wifi,  UI_MODE_DETAILS_WIFI,  render_details_wifi_locked);
MENU_ACTIVITY(details_ble,   UI_MODE_DETAILS_BLE,   render_details_ble_locked);

MENU_ACTIVITY(env_summary,   UI_MODE_ENV_SUMMARY,   render_env_summary_locked);

MENU_ACTIVITY(credits,       UI_MODE_CREDITS,       render_credits_locked);

static void menu_render(void);

static void render_ui_locked(void)
{
    switch (s_ui_mode) {
    case UI_MODE_MAIN:          render_main_locked();          break;
    case UI_MODE_MENU:          menu_render();                 break;
    case UI_MODE_PUP:           render_pup_locked();           break;
    case UI_MODE_PUP_INTERACT:  render_pup_interact_locked();  break;
    case UI_MODE_PUP_DIG:       render_pup_dig_locked();       break;
    case UI_MODE_PUP_TROPHIES:  render_pup_trophies_locked();  break;
    case UI_MODE_PUP_TROPHY_DETAIL: render_pup_trophy_detail_locked(); break;

    case UI_MODE_ENV_SUMMARY:
    case UI_MODE_OPTIONS:
    case UI_MODE_CREDITS:
    case UI_MODE_WIFI_LIST:
    case UI_MODE_BLE_LIST:
    case UI_MODE_DETAILS_WIFI:
    case UI_MODE_DETAILS_BLE: {
        const ui_activity_t *a = ui_activity_current();
        if (a && a->render) a->render(NULL);
        break;
    }
    case UI_MODE_BLE_CLASSES:   render_ble_classes_locked();   break;
    case UI_MODE_PROBE_LOG: render_probe_log_locked(); break;
    case UI_MODE_SEQ_LINK:      render_seq_link_locked();      break;
    case UI_MODE_IE_SIG:        render_ie_sig_locked();        break;
    case UI_MODE_ANQP_LEAK:     render_anqp_leak_locked();     break;
    case UI_MODE_PROBE_EXPLORE: render_probe_explore_locked(); break;
    case UI_MODE_PROBE_DIG:     render_probe_dig_locked();     break;
    case UI_MODE_BLE_EXPLORE:   render_ble_explore_locked();   break;
    case UI_MODE_BLE_DIG:       render_ble_dig_locked();       break;
    case UI_MODE_DOWNLOAD_CONFIRM: render_download_confirm_locked(); break;
    case UI_MODE_DOWNLOAD_ACTIVE:  render_download_active_locked();  break;
    case UI_MODE_SCANNING: break;
    case UI_MODE_WALK: break;
    default:                    render_main_locked();          break;
    }

    led_reassert();
}

typedef struct menu_screen menu_screen_t;

typedef struct {
    const char *label;
    const char *(*value)(void);
    void       (*select)(void);
    bool       (*hidden)(void);
} menu_row_t;

struct menu_screen {
    const char     *title;
    const menu_row_t *rows;
    uint8_t         n_rows;
    uint8_t         cursor;
};

#define MENU_STACK_MAX 4
static menu_screen_t *s_menu_stack[MENU_STACK_MAX];
static uint8_t        s_menu_depth = 0;

static uint8_t menu_visible(const menu_screen_t *m, uint8_t *vis, uint8_t *cur_pos)
{
    uint8_t n = 0;
    if (cur_pos) *cur_pos = 0;
    for (uint8_t i = 0; i < m->n_rows; i++) {
        if (m->rows[i].hidden && m->rows[i].hidden()) continue;
        if (cur_pos && i == m->cursor) *cur_pos = n;
        if (n < 16) vis[n] = i;
        n++;
    }
    return n;
}

static void draw_menu_footer(void)
{
    const int y = 72;
    display_fill_rect(0, y - 1, DISPLAY_W, 9, UI_THEME_BG);
    display_draw_string(2,   y, "[1]",    COLOR_SAFE,    UI_THEME_BG, 1);
    display_draw_string(20,  y, "Next",   COLOR_WHITE,   UI_THEME_BG, 1);
    display_draw_string(50,  y, "[2]",    COLOR_OK,      UI_THEME_BG, 1);
    display_draw_string(68,  y, "Sel",    COLOR_WHITE,   UI_THEME_BG, 1);
    display_draw_string(92,  y, "[hold]", COLOR_CAUTION, UI_THEME_BG, 1);
    display_draw_string(128, y, "Back",   COLOR_WHITE,   UI_THEME_BG, 1);
}

static void menu_render_screen(menu_screen_t *m)
{
    uint8_t vis[16];
    uint8_t nvis = menu_visible(m, vis, NULL);

    display_clear(UI_THEME_BG);
    draw_menu_header(m->title);
    if (nvis == 0) { draw_menu_footer(); return; }

    bool on_visible = false;
    for (uint8_t k = 0; k < nvis; k++) if (vis[k] == m->cursor) { on_visible = true; break; }
    if (!on_visible) m->cursor = vis[0];

    int y = 24;
    for (uint8_t k = 0; k < nvis; k++) {
        const menu_row_t *r = &m->rows[vis[k]];
        bool focus = (vis[k] == m->cursor);

        uint16_t fg = focus ? COLOR_OK : UI_THEME_MUTED;

        display_draw_string(6, y, focus ? ">" : " ",
                            focus ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);
        if (r->value) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%s:", r->label);
            display_draw_string(16, y, buf, fg, UI_THEME_BG, 1);
            display_draw_string(96, y, r->value(),
                                focus ? COLOR_OK : UI_THEME_MUTED, UI_THEME_BG, 1);
        } else {
            display_draw_string(16, y, r->label, fg, UI_THEME_BG, 1);
        }
        y += 10;
    }
    draw_menu_footer();
}

static void menu_render(void)
{
    if (s_menu_depth) menu_render_screen(s_menu_stack[s_menu_depth - 1]);
}

static void menu_open_root(menu_screen_t *m)
{
    ui_activity_switch(NULL, NULL);
    uint8_t vis[16];
    (void)menu_visible(m, vis, NULL);
    m->cursor = m->n_rows ? vis[0] : 0;
    s_menu_depth = 0;
    s_menu_stack[s_menu_depth++] = m;
    s_ui_mode = UI_MODE_MENU;
    render_ui_locked();
}

static void menu_push(menu_screen_t *m)
{
    if (s_menu_depth < MENU_STACK_MAX) {
        uint8_t vis[16];
        (void)menu_visible(m, vis, NULL);
        m->cursor = m->n_rows ? vis[0] : 0;
        s_menu_stack[s_menu_depth++] = m;
    }
    s_ui_mode = UI_MODE_MENU;
    render_ui_locked();
}

static void menu_pop(void)
{
    if (s_menu_depth > 1) {
        s_menu_depth--;
        s_ui_mode = UI_MODE_MENU;
        render_ui_locked();
    } else {
        s_menu_depth = 0;
        s_ui_mode = UI_MODE_MAIN;
        render_ui_locked();
    }
}

static void menu_return_from_leaf(void)
{
    ui_activity_switch(NULL, NULL);
    if (s_menu_depth) {
        s_ui_mode = UI_MODE_MENU;
    } else {
        s_ui_mode = UI_MODE_MAIN;
    }
    render_ui_locked();
}

static void menu_cursor_next(void)
{
    if (!s_menu_depth) return;
    menu_screen_t *m = s_menu_stack[s_menu_depth - 1];
    uint8_t vis[16], cur = 0;
    uint8_t nvis = menu_visible(m, vis, &cur);
    if (nvis == 0) return;
    m->cursor = vis[(cur + 1) % nvis];
    render_ui_locked();
}

static void menu_activate(void)
{
    if (!s_menu_depth) return;
    menu_screen_t *m = s_menu_stack[s_menu_depth - 1];
    const menu_row_t *r = &m->rows[m->cursor];
    if (r->select) r->select();
}

static menu_screen_t settings_menu, device_menu, lights_menu;

static const char *menuval_mode(void)
{
    return (s_advisor_mode == ADVISOR_MODE_ADV) ? "Adv" : "Lite";
}
static const char *menuval_brightness(void)
{
    static char b[8];
    snprintf(b, sizeof(b), "%u%%", (unsigned)s_brightness_steps[s_screen_brightness_idx]);
    return b;
}
static const char *menuval_led(void)     { return s_led_enabled     ? "ON" : "OFF"; }
static const char *menuval_auto_ap(void) { return s_auto_ap_enabled ? "ON" : "OFF"; }

static bool menurow_lite_hidden(void) { return s_advisor_mode != ADVISOR_MODE_ADV; }

static void menusel_toggle_mode(void)
{

    s_advisor_mode = (s_advisor_mode == ADVISOR_MODE_ADV) ? ADVISOR_MODE_LITE : ADVISOR_MODE_ADV;
    settings_save();
    render_ui_locked();
    ESP_LOGI(TAG, "MENU: mode -> %s", menuval_mode());
}
static void menusel_cycle_brightness(void)
{
    s_screen_brightness_idx = (uint8_t)((s_screen_brightness_idx + 1) % BRIGHTNESS_STEPS_COUNT);
    settings_apply();
    settings_save();
    render_ui_locked();
    ESP_LOGI(TAG, "MENU: brightness -> %u%%", (unsigned)s_brightness_steps[s_screen_brightness_idx]);
}
static void menusel_toggle_led(void)
{
    s_led_enabled = !s_led_enabled;
    settings_save();
    if (!s_led_enabled) led_off();
    render_ui_locked();
    ESP_LOGI(TAG, "MENU: led -> %s", s_led_enabled ? "on" : "off");
}
static void menusel_toggle_auto_ap(void)
{
    s_auto_ap_enabled = !s_auto_ap_enabled;
    settings_save();
    render_ui_locked();
    ESP_LOGI(TAG, "MENU: auto_ap -> %s", s_auto_ap_enabled ? "on" : "off");
}
static void menusel_open_device(void) { menu_push(&device_menu); }
static void menusel_open_lights(void) { menu_push(&lights_menu); }
static void menusel_open_credits(void)
{

    s_credit_index = 0;
    ui_activity_switch(&credits_activity, NULL);
    ESP_LOGI(TAG, "MENU: open CREDITS");
}
static void menusel_open_launch_ap(void)
{

    s_dl_sel = 0;
    s_ui_mode = UI_MODE_DOWNLOAD_CONFIRM;
    render_ui_locked();
    ESP_LOGI(TAG, "MENU: open LAUNCH AP");
}

static const menu_row_t settings_rows[] = {
    { "Mode",      menuval_mode,    menusel_toggle_mode,    NULL },
    { "Device",    NULL,            menusel_open_device,    NULL },
    { "Launch AP", NULL,            menusel_open_launch_ap, menurow_lite_hidden },
    { "Auto AP",   menuval_auto_ap, menusel_toggle_auto_ap, menurow_lite_hidden },
};
static const menu_row_t device_rows[] = {
    { "Lights",  NULL, menusel_open_lights,  NULL },
    { "Credits", NULL, menusel_open_credits, NULL },
};
static const menu_row_t lights_rows[] = {
    { "Screen", menuval_brightness, menusel_cycle_brightness, NULL },
    { "LED",    menuval_led,        menusel_toggle_led,       NULL },
};
static menu_screen_t settings_menu = { "SETTINGS", settings_rows, 4, 0 };
static menu_screen_t device_menu   = { "DEVICE",   device_rows,   2, 0 };
static menu_screen_t lights_menu   = { "LIGHTS",   lights_rows,   2, 0 };

static void log_full_scan_dump(const ap_score_t *scores, uint16_t score_count,
                                const ble_results_t *ble);

static bool ap_threat_before(const ap_score_t *a, const ap_score_t *b)
{
    if (a->threat_level != b->threat_level) return a->threat_level > b->threat_level;
    return a->identity_score > b->identity_score;
}

static bool ble_threat_before(const ble_device_t *a, const ble_device_t *b)
{
    if (a->suppressed != b->suppressed) return !a->suppressed;
    if (a->threat_level != b->threat_level) return a->threat_level > b->threat_level;
    return a->identity_score > b->identity_score;
}

static void reorder_threat_first_aps(ap_score_t *s, uint16_t n)
{
    for (uint16_t i = 1; i < n; i++) {
        ap_score_t key = s[i];
        int j = (int)i - 1;
        while (j >= 0 && ap_threat_before(&key, &s[j])) { s[j + 1] = s[j]; j--; }
        s[j + 1] = key;
    }
}

static void reorder_signal_first_aps(ap_score_t *s, uint16_t n)
{
    for (uint16_t i = 1; i < n; i++) {
        ap_score_t key = s[i];
        int j = (int)i - 1;
        while (j >= 0 && key.rssi > s[j].rssi) { s[j + 1] = s[j]; j--; }
        s[j + 1] = key;
    }
}

static void reorder_threat_first_ble(ble_device_t *d, uint16_t n)
{
    for (uint16_t i = 1; i < n; i++) {
        ble_device_t key = d[i];
        int j = (int)i - 1;
        while (j >= 0 && ble_threat_before(&key, &d[j])) { d[j + 1] = d[j]; j--; }
        d[j + 1] = key;
    }
}

static void enter_scan_stage(const char *subject)
{
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_ui_mode = UI_MODE_SCANNING;
    display_scan_stage_static(subject);
    led_reassert();
    xSemaphoreGive(s_state_mutex);
}

static void pup_count_class(uint8_t cls, pup_scan_stats_t *st)
{
    switch (cls) {
    case EUI_CLASS_PHONE:
    case EUI_CLASS_TABLET:
    case EUI_CLASS_MOBILE:           st->phone++;    break;
    case EUI_CLASS_LAPTOP:           st->laptop++;   break;
    case EUI_CLASS_WEARABLE:         st->wearable++; break;
    case EUI_CLASS_AUDIO:            st->audio++;    break;
    case EUI_CLASS_MEDICAL:          st->medical++;  break;
    case EUI_CLASS_VEHICLE:
    case EUI_CLASS_AUTOMOTIVE:       st->vehicle++;  break;
    case EUI_CLASS_MAKER_BOARD:      st->maker++;    break;
    case EUI_CLASS_DEV_MODULE:       st->devmod++;   break;
    case EUI_CLASS_BEACON:           st->beacon++;   break;
    case EUI_CLASS_POS_PAYMENT:      st->pos++;      break;
    case EUI_CLASS_ACCESS_CONTROL:   st->access++;   break;
    case EUI_CLASS_INFRASTRUCTURE:   st->infra++;    break;
    case EUI_CLASS_TRACKER:          st->tracker++;  break;
    case EUI_CLASS_DRONE:            st->drone++;    break;
    default: break;
    }
}

static void pup_collect_stats(const ap_score_t *scores, uint16_t count,
                              const ble_results_t *ble, pup_scan_stats_t *st)
{
    memset(st, 0, sizeof(*st));
    st->wifi_n = count;
    st->ble_n  = ble->count;
    st->flock  = flock_detect_distinct();

    uint8_t envt = 0;

    for (uint16_t i = 0; i < count; i++) {
        const ap_score_t *ap = &scores[i];
        if (ap->suppressed) continue;
        if (ap->threat_level > envt) envt = ap->threat_level;

        pup_trophy_smell(ap->vendor);
        pup_count_class(ap->device_class, st);

        if (!ap->ssid[0])               st->hidden++;
        if (ap->band_5g)                st->band5g++;
        if (ap->rssi >= -35)            st->strong_wifi++;
        if (ap->auth == WIFI_AUTH_OPEN) st->open_nets++;
        switch (ap->auth) {
        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
        case WIFI_AUTH_WPA3_ENTERPRISE:
        case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
        case WIFI_AUTH_WPA3_ENT_192:    st->wpa3++; break;
        default: break;
        }

        uint16_t fl = ap->eui_flags;
        if ((fl & EUI_FLAG_ENTERPRISE_GRADE) ||
            ap->device_class == EUI_CLASS_ENTERPRISE_AP ||
            ap->auth == WIFI_AUTH_ENTERPRISE)                 st->enterprise++;
        if ((fl & EUI_FLAG_CONSUMER_GRADE) ||
            ap->device_class == EUI_CLASS_CONSUMER_AP)        st->consumer++;
        if ((fl & EUI_FLAG_IOT_DEVICE) ||
            ap->device_class == EUI_CLASS_IOT_HUB ||
            ap->device_class == EUI_CLASS_IOT_LEAF)           st->iot++;
        if ((fl & EUI_FLAG_SURVEILLANCE) ||
            ap->device_class == EUI_CLASS_SURVEILLANCE_CAM)   st->surveil++;
        if ((fl & EUI_FLAG_INVESTIGATION) ||
            ap->device_class == EUI_CLASS_INVESTIGATION ||
            ap->device_class == EUI_CLASS_ATTACK_SIGNAL)      st->investigation++;
        if (fl & EUI_FLAG_KNOWN_MALICIOUS)                    st->malicious++;

        if (icontains(ap->vendor, "axon enterprise"))         st->axon++;

        if (ap->pwnagotchi)    st->pwnagotchi++;
        if (ap->deauth_flood)  st->deauth++;
        if (ap->pmkid_exposed) st->pmkid++;
        if (ap->twin_detected || ap->open_clone ||
            ap->karma_suspect || ap->vendor_mismatch)         st->twin++;
    }

    for (uint16_t i = 0; i < ble->count; i++) {
        const ble_device_t *d = &ble->devices[i];
        if (d->suppressed) continue;
        if (d->threat_level > envt) envt = d->threat_level;

        pup_trophy_smell(d->vendor);
        pup_trophy_smell(d->company_name);

        uint8_t  cls = ble_effective_class(d);
        uint16_t fl  = d->eui_flags | d->bt_company_flags |
                       d->mfg_rule_flags | d->uuid16_flags;
        pup_count_class(cls, st);

        if ((fl & EUI_FLAG_IOT_DEVICE) ||
            cls == EUI_CLASS_IOT_HUB || cls == EUI_CLASS_IOT_LEAF) st->iot++;
        if ((fl & EUI_FLAG_SURVEILLANCE) ||
            cls == EUI_CLASS_SURVEILLANCE_CAM)                st->surveil++;
        if ((fl & EUI_FLAG_INVESTIGATION) ||
            cls == EUI_CLASS_INVESTIGATION ||
            cls == EUI_CLASS_ATTACK_SIGNAL)                   st->investigation++;
        if (fl & EUI_FLAG_KNOWN_MALICIOUS)                    st->malicious++;
        if (icontains(d->vendor, "axon enterprise") ||
            icontains(d->company_name, "axon enterprise"))    st->axon++;

        if (d->is_airtag) {
            st->airtag++;
            if (cls != EUI_CLASS_TRACKER) st->tracker++;
        }
        if (d->has_rid && cls != EUI_CLASS_DRONE) st->drone++;
        if (d->distance_dm != 0xFFFF && d->distance_dm <= 10) st->close_ble++;
    }

    st->env_threat = envt;
}

static uint8_t least_congested_2g_channel(void);

static void do_scan(void)
{
    static scan_results_t  results;
    static EXT_RAM_BSS_ATTR ap_score_t      scores_tmp[ANALYZER_MAX_APS];
    static EXT_RAM_BSS_ATTR ble_results_t   ble_tmp;
    uint8_t scan_2g = 0, scan_5g = 0;
    TickType_t stage_start = 0, stage_elapsed = 0;
    bool adv  = (s_advisor_mode == ADVISOR_MODE_ADV);

    bool deep = adv && !s_regular_scan_override;
    s_regular_scan_override = false;

    static bool s_boot_scan_done = false;
    bool boot_scan = !s_boot_scan_done;
    s_boot_scan_done = true;

    memset(&results,   0, sizeof(results));
    memset(scores_tmp, 0, ANALYZER_MAX_APS * sizeof(ap_score_t));
    memset(&ble_tmp,   0, sizeof(ble_tmp));

    ESP_LOGI(TAG, "SPLASH: SCANNING_WIFI");
    enter_scan_stage("WiFi");
    led_apply(128, 0, 128, 8);
    stage_start = xTaskGetTickCount();

    esp_err_t wifi_err = deep
        ? wifi_scan_run_broad(&results, WIFI_ADV_ACTIVE_SWEEPS, WIFI_ADV_MAX_MS)
        : wifi_scan_run(&results);
    if (wifi_err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi scan failed");
        return;
    }

    for (uint16_t i = 0; i < results.count; i++) {
        if (results.entries[i].band_5g) scan_5g++; else scan_2g++;
    }

    bool retain_detail = adv;
    probe_req_log_set_retention_mode(retain_detail);
    seq_analyzer_set_retention_mode(retain_detail);
    ie_signature_set_retention_mode(retain_detail);
    anqp_analyzer_set_retention_mode(retain_detail);
    probe_frame_ring_set_retention_mode(retain_detail);
    probe_req_log_begin_scan();
    flock_detect_begin_scan();
    sta_tracker_begin_scan();
    seq_analyzer_begin_scan();
    ie_signature_begin_scan();
    anqp_analyzer_begin_scan();
    probe_frame_ring_begin_scan();
    s_capture_scan_idx++;
    wifi_sniffer_run(&results, SNIFF_DWELL_MS, adv);

    for (uint16_t i = 0; i < results.count; i++) {
        probe_req_log_add_beacon_ssid(results.entries[i].ssid);
    }
    uint16_t sniff_n = wifi_sniffer_bssid_count();
    for (uint16_t i = 0; i < sniff_n; i++) {
        const sniffer_rec_t *r = wifi_sniffer_at(i);
        if (r && r->ssid[0]) probe_req_log_add_beacon_ssid(r->ssid);
    }

    for (uint16_t i = 0; i < sniff_n && results.count < WIFI_SCAN_MAX_APS; i++) {
        const sniffer_rec_t *r = wifi_sniffer_at(i);
        if (!r || !r->beacon_seen) continue;
        bool known = false;
        for (uint16_t j = 0; j < results.count; j++) {
            if (memcmp(results.entries[j].bssid, r->bssid, 6) == 0) { known = true; break; }
        }
        if (known) continue;
        ap_record_t *e = &results.entries[results.count++];
        memset(e, 0, sizeof(*e));
        strlcpy(e->ssid, r->ssid, sizeof(e->ssid));
        memcpy(e->bssid, r->bssid, 6);
        e->rssi    = r->rssi;
        e->channel = r->channel;
        e->band_5g = (r->channel >= 36);

        e->auth = r->has_rsn ? WIFI_AUTH_WPA2_PSK
                             : (r->privacy ? WIFI_AUTH_WEP : WIFI_AUTH_OPEN);
    }

    probe_req_log_finalize();
    sta_tracker_finalize();
    seq_analyzer_finalize();
    ie_signature_finalize();
    anqp_analyzer_finalize();

    uint16_t score_count = 0;

    analyzer_run(&results, NULL, scores_tmp, &score_count);
    stage_elapsed = xTaskGetTickCount() - stage_start;
    if (pdTICKS_TO_MS(stage_elapsed) < WIFI_STAGE_MS) {
        vTaskDelay(pdMS_TO_TICKS(WIFI_STAGE_MS - pdTICKS_TO_MS(stage_elapsed)));
    }

    ESP_LOGI(TAG, "SPLASH: SCANNING_BLE");
    enter_scan_stage("BLUETOOTH");
    {
        size_t free8     = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        size_t largest8  = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
        size_t free_int  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t largest_i = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t free_dma  = heap_caps_get_free_size(MALLOC_CAP_DMA);
        size_t min_ever  = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
        ESP_LOGW(TAG, "HEAP pre-BLE: 8bit free=%u largest=%u | INT free=%u largest=%u | DMA free=%u | min_ever=%u",
                 (unsigned)free8, (unsigned)largest8,
                 (unsigned)free_int, (unsigned)largest_i,
                 (unsigned)free_dma, (unsigned)min_ever);
        heap_caps_print_heap_info(MALLOC_CAP_8BIT);
    }
    stage_start = xTaskGetTickCount();
    ble_adv_ring_set_retention_mode(retain_detail);
    ble_adv_ring_begin_scan();

    uint32_t ble_ms = deep ? BLE_ADV_SCAN_MS
                           : (boot_scan ? BLE_SCAN_MS : BLE_SNAPSHOT_SCAN_MS);
    ble_scan_run_ex(&ble_tmp, ble_ms, deep, deep);
    stage_elapsed = xTaskGetTickCount() - stage_start;
    if (pdTICKS_TO_MS(stage_elapsed) < BLE_STAGE_MS) {
        vTaskDelay(pdMS_TO_TICKS(BLE_STAGE_MS - pdTICKS_TO_MS(stage_elapsed)));
    }

    analyzer_run(&results, &ble_tmp, scores_tmp, &score_count);

    if (adv) {
        reorder_threat_first_aps(scores_tmp, score_count);
        reorder_threat_first_ble(ble_tmp.devices, ble_tmp.count);
    } else {

        reorder_signal_first_aps(scores_tmp, score_count);
    }

    analyzer_xref_ble(scores_tmp, score_count, &ble_tmp);

    pdc_build(scores_tmp, score_count, &ble_tmp);

    for (uint16_t i = 0; i < score_count; i++) {
        vetter_result_t vtmp;
        vetter_run(&scores_tmp[i], &ble_tmp, &vtmp);
        ESP_LOGI(TAG, "VET[%u] ssid=\"%s\" blocked=%u summary=%s",
                 (unsigned)i, scores_tmp[i].ssid,
                 vtmp.blocked ? 1u : 0u, vtmp.summary);
    }

    for (uint16_t i = 0; i < score_count; i++) {
        capture_emit_wifi_ap(&scores_tmp[i], s_capture_scan_idx);
        capture_emit_alerts_for_ap(&scores_tmp[i], s_capture_scan_idx);
    }
    for (uint16_t i = 0; i < ble_tmp.count; i++) {
        capture_emit_ble_device(&ble_tmp.devices[i], s_capture_scan_idx);
        capture_emit_tracker_if_applicable(&ble_tmp.devices[i], s_capture_scan_idx);
        capture_emit_drone_rid_if_applicable(&ble_tmp.devices[i], s_capture_scan_idx);
        capture_emit_alerts_for_ble(&ble_tmp.devices[i], s_capture_scan_idx);
    }

    {
        uint16_t sn = wifi_sniffer_bssid_count();
        for (uint16_t i = 0; i < sn; i++) {
            const sniffer_rec_t *sr = wifi_sniffer_at(i);
            if (sr && sr->has_rid)
                capture_emit_drone_rid_wifi(sr, s_capture_scan_idx);
        }
    }
    capture_emit_device_clusters(s_capture_scan_idx);
    capture_emit_ble_addr_stats(&ble_tmp, s_capture_scan_idx);
    bool cap_adv = (s_advisor_mode == ADVISOR_MODE_ADV);
    capture_emit_probe_req_log(probe_req_log_get(), s_capture_scan_idx, cap_adv);

    capture_emit_seq_fingerprint_log(seq_analyzer_get(), s_capture_scan_idx, cap_adv);
    capture_emit_ie_signature_log(ie_signature_get(), s_capture_scan_idx, cap_adv);
    capture_emit_anqp_log(anqp_analyzer_get(), s_capture_scan_idx, cap_adv);

    capture_emit_station_log(s_capture_scan_idx);

    capture_emit_channel_activity(scores_tmp, score_count, s_capture_scan_idx);

    {
        crowd_estimate_t crowd;
        analyzer_crowd_estimate(&ble_tmp, sta_tracker_count(),
                                probe_req_log_get()->total_probe_reqs, &crowd);
        capture_emit_crowd_density(&crowd, s_capture_scan_idx);
    }

    {
        ps_result_t ps;
        public_safety_begin(&ps);
        for (uint16_t i = 0; i < score_count; i++)
            if (!scores_tmp[i].suppressed) public_safety_eval_wifi(&scores_tmp[i], &ps);
        for (uint16_t i = 0; i < ble_tmp.count; i++)
            if (!ble_tmp.devices[i].suppressed) public_safety_eval_ble(&ble_tmp.devices[i], &ps);
        public_safety_finalize(&ps);
        capture_emit_law_enforcement_presence(&ps, s_capture_scan_idx);
    }

    {
        mr_result_t mr;
        medical_responder_begin(&mr);
        for (uint16_t i = 0; i < score_count; i++)
            if (!scores_tmp[i].suppressed) medical_responder_eval_wifi(&scores_tmp[i], &mr);
        for (uint16_t i = 0; i < ble_tmp.count; i++)
            if (!ble_tmp.devices[i].suppressed) medical_responder_eval_ble(&ble_tmp.devices[i], &mr);
        medical_responder_finalize(&mr);
        capture_emit_medical_responder_presence(&mr, s_capture_scan_idx);
    }

    {
        uint16_t cams = sta_tracker_camera_count();
        for (uint16_t i = 0; i < score_count; i++) {
            const ap_score_t *ap = &scores_tmp[i];
            if (ap->suppressed) continue;
            if ((ap->eui_flags & EUI_FLAG_SURVEILLANCE) ||
                ap->device_class == EUI_CLASS_SURVEILLANCE_CAM) cams++;
        }
        for (uint16_t i = 0; i < ble_tmp.count; i++) {
            const ble_device_t *d = &ble_tmp.devices[i];
            if (d->suppressed) continue;
            uint16_t fl = d->eui_flags | d->bt_company_flags | d->mfg_rule_flags |
                          d->uuid16_flags;
            if ((fl & EUI_FLAG_SURVEILLANCE) ||
                ble_effective_class(d) == EUI_CLASS_SURVEILLANCE_CAM) cams++;
        }
        const crowd_estimate_t *cd = analyzer_last_crowd();
        const ps_result_t      *ps = public_safety_last();
        const mr_result_t      *mr = medical_responder_last();

        s_env_ind = (environment_indicators_t){0};
        s_env_ind.camera_count       = cams;
        s_env_ind.camera_conf        = cams ? 70 : 0;
        s_env_ind.public_safety_low  = ps->estimated_officers_low;
        s_env_ind.public_safety_high = ps->estimated_officers_high;
        s_env_ind.public_safety_conf = ps->confidence;
        s_env_ind.phone_like_count   = cd->device_evidence;
        s_env_ind.phone_like_conf    = cd->device_evidence ? 40 : 0;
        s_env_ind.medical_count      = mr->matches;
        s_env_ind.medical_conf       = mr->confidence;
        capture_emit_environment_indicators(&s_env_ind, s_capture_scan_idx);
    }

    vp_feed_result_t pup = virtual_pup_feed(score_count, ble_tmp.count);
    if (pup.leveled_up) {
        ESP_LOGI(TAG, "PUP: leveled up to %u (+%u xp)",
                 (unsigned)pup.new_level, (unsigned)pup.xp_gained);
    }

    pup_scan_stats_t tstats;
    pup_collect_stats(scores_tmp, score_count, &ble_tmp, &tstats);
    vp_status_t vst;
    virtual_pup_get(&vst);
    uint32_t pup_age = (s_boot_count > vst.birth_boot)
                           ? (s_boot_count - vst.birth_boot) : 0;
    pup_trophy_feed_result_t trophies =
        pup_trophy_feed(&tstats, s_boot_count, pup.new_level, pup_age);
    vp_feed_result_t bonus = virtual_pup_grant_xp(trophies.bonus_xp);
    bool pup_leveled = pup.leveled_up || bonus.leveled_up;
    uint16_t pup_level = bonus.new_level;

    ESP_LOGI(TAG, "SPLASH: SCORING_RESULTS");

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_ui_mode = UI_MODE_SCANNING;
    s_anim_dig = true;
    display_advisor_scoring_results(score_count, ble_tmp.count);
    xSemaphoreGive(s_state_mutex);
    vTaskDelay(pdMS_TO_TICKS(SCORE_STAGE_MS));

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_anim_dig = false;
    s_ui_mode = UI_MODE_MAIN;
    xSemaphoreGive(s_state_mutex);

    if (pup_leveled) {
        xSemaphoreTake(s_state_mutex, portMAX_DELAY);
        render_pup_levelup(pup_level,
                           virtual_pup_title_for_level(pup_level));
        xSemaphoreGive(s_state_mutex);
        if (s_led_enabled) led_apply(0, 200, 0, 16);
        vTaskDelay(pdMS_TO_TICKS(1800));
    }

    uint8_t show_n = trophies.new_count;
    if (show_n > 3) show_n = 3;
    for (uint8_t t = 0; t < show_n; t++) {
        xSemaphoreTake(s_state_mutex, portMAX_DELAY);
        render_pup_trophy_award(trophies.new_ids[t]);
        xSemaphoreGive(s_state_mutex);
        if (s_led_enabled) led_apply(255, 160, 0, 16);
        vTaskDelay(pdMS_TO_TICKS(1500));
    }

    uint16_t ble_suppressed = 0;
    for (uint16_t i = 0; i < ble_tmp.count; i++) {
        if (ble_tmp.devices[i].suppressed) ble_suppressed++;
    }
    ESP_LOGI(TAG, "Scan: %u nets (raw APs:%u)  2G:%u  5G:%u  BLE:%u (raw:%u)",
             score_count, (unsigned)results.count, scan_2g, scan_5g,
             (unsigned)(ble_tmp.count - ble_suppressed), ble_tmp.count);

    log_full_scan_dump(scores_tmp, score_count, &ble_tmp);

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    memcpy(s_scores, scores_tmp, score_count * sizeof(ap_score_t));
    s_score_count = score_count;
    memcpy(&s_ble, &ble_tmp, sizeof(ble_results_t));
    s_n_2g        = scan_2g;
    s_n_5g        = scan_5g;
    s_scan_valid  = true;
    s_ui_mode     = UI_MODE_ENV_SUMMARY;
    s_wifi_index  = (s_advisor_mode == ADVISOR_MODE_LITE) ? lite_best_index() : 1;
    s_ble_index   = 1;
    xSemaphoreGive(s_state_mutex);

    bool auto_ap = (s_advisor_mode == ADVISOR_MODE_ADV) && s_auto_ap_enabled;

    if (auto_ap) {
        xSemaphoreTake(s_state_mutex, portMAX_DELAY);
        ui_activity_switch(NULL, NULL);
        download_mode_set_channel(least_congested_2g_channel());
        download_mode_request_enable();
        s_dl_last_drawn_state = 0xFF;
        s_ui_mode = UI_MODE_DOWNLOAD_ACTIVE;
        xSemaphoreGive(s_state_mutex);
        led_apply(0, 0, 255, 8);
        ESP_LOGI(TAG, "Auto AP: scan done -> launch AP (timeout %u min)",
                 (unsigned)download_mode_get_timeout_minutes());
        return;
    }

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    ui_activity_switch(&env_summary_activity, NULL);
    xSemaphoreGive(s_state_mutex);

    led_for_verdict(analyzer_threat_to_verdict(env_threat_level()));
}

#define DUMP_TAG "sc_dump"

static void log_addr6(const char *prefix, const uint8_t a[6])
{
    ESP_LOGI(DUMP_TAG, "%s%02X:%02X:%02X:%02X:%02X:%02X",
             prefix, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void dump_one_ap(uint16_t idx, const ap_score_t *s,
                         const sniffer_rec_t *sr,
                         const vetter_result_t *v)
{
    ESP_LOGI(DUMP_TAG, "=== AP[%u] === ssid=\"%s\"", idx, s->ssid);
    ESP_LOGI(DUMP_TAG, "DUMP ident:  bssid=%02X:%02X:%02X:%02X:%02X:%02X "
             "band=%s ch=%u rssi=%d laa=%u suppressed=%u",
             s->bssid[0], s->bssid[1], s->bssid[2],
             s->bssid[3], s->bssid[4], s->bssid[5],
             s->band_5g ? "5GHz" : "2.4GHz",
             (unsigned)s->channel,
             (int)s->rssi, mac_is_laa(s->bssid) ? 1u : 0u,
             s->suppressed ? 1u : 0u);
    ESP_LOGI(DUMP_TAG, "DUMP vendor: \"%s\" match_len=%u class=%u(%s) flags=0x%04X",
             s->vendor[0] ? s->vendor : "(none)",
             (unsigned)s->mac_match_len, (unsigned)s->device_class,
             eui_class_label(s->device_class), (unsigned)s->eui_flags);
    ESP_LOGI(DUMP_TAG, "DUMP crypto: auth=%d rsn=%u pmf_req=%u pmf_cap=%u wps=%u "
             "rsn_grp=%02X%02X%02X-%02u beacon_iv=%u",
             (int)s->auth, s->has_rsn ? 1u : 0u,
             s->rsn_pmf_required ? 1u : 0u, 0u,
             s->has_wps ? 1u : 0u,
             s->rsn_group_oui[0], s->rsn_group_oui[1], s->rsn_group_oui[2],
             (unsigned)s->rsn_group_suite, (unsigned)s->beacon_interval);
    ESP_LOGI(DUMP_TAG, "DUMP meta:   country=\"%s\" ie_hash=%08lX wps_mfg=\"%s\" "
             "wps_model=\"%s\"",
             s->country_code[0] ? s->country_code : "?",
             (unsigned long)s->ie_pattern_hash,
             s->wps_manufacturer[0] ? s->wps_manufacturer : "(none)",
             s->wps_model_name[0]   ? s->wps_model_name   : "(none)");
    for (uint8_t k = 0; k < s->vendor_ie_count; k++) {
        ESP_LOGI(DUMP_TAG, "DUMP vIE[%u]: %02X:%02X:%02X name=\"%s\"",
                 k,
                 s->vendor_ie_ouis[k][0], s->vendor_ie_ouis[k][1],
                 s->vendor_ie_ouis[k][2],
                 s->vendor_ie_names[k] ? s->vendor_ie_names[k] : "(unresolved)");
    }
    ESP_LOGI(DUMP_TAG, "DUMP L2L3:   cdp=%u(\"%s\" org=\"%s\" flags=0x%04X cls=%u) "
             "lldp=%u(\"%s\" org=\"%s\" flags=0x%04X cls=%u) "
             "dhcp=%u(vc=\"%s\" opt55_len=%u flags=0x%04X cls=%u) "
             "signal_count=%u",
             s->cdp_count, s->cdp_device_id,
             sr && sr->cdp_org_name ? sr->cdp_org_name : "(none)",
             sr ? sr->cdp_flags : 0, sr ? sr->cdp_class : 0,
             s->lldp_count, s->lldp_system_name,
             sr && sr->lldp_org_name ? sr->lldp_org_name : "(none)",
             sr ? sr->lldp_flags : 0, sr ? sr->lldp_class : 0,
             s->dhcp_count, s->dhcp_vendor_class,
             sr ? sr->dhcp_opt55_len : 0,
             sr ? sr->dhcp_flags : 0, sr ? sr->dhcp_class : 0,
             s->l2l3_signal_count);
    ESP_LOGI(DUMP_TAG, "DUMP score:  base=%u hygiene=-%u identity=%u/%u threat=%u(%s)",
             s->base_quality, s->hygiene,
             s->identity_score, s->identity_conf,
             (unsigned)s->threat_level, analyzer_threat_label(s->threat_level));

    char sig[96];
    sig[0] = '\0';
    #define SIGADD(cond, tok) do { if (cond) { \
        if (sig[0]) strlcat(sig, " ", sizeof(sig)); \
        strlcat(sig, tok, sizeof(sig)); } } while (0)
    SIGADD(s->twin_detected,      "twin");
    SIGADD(s->open_clone,         "open_clone");
    SIGADD(s->karma_suspect,      "karma");
    SIGADD(s->deauth_flood,       "deauth_flood");
    SIGADD(s->pwnagotchi,         "pwnagotchi");
    SIGADD(s->vendor_mismatch,    "vendor_mismatch");
    SIGADD(s->auto_fail,          "auto_fail");
    SIGADD(s->same_oui_multiband, "same_oui_mb");
    #undef SIGADD
    ESP_LOGI(DUMP_TAG, "DUMP signals:%s (radio_count=%u)",
             sig[0] ? sig : " none", s->radio_count);
    if (v) {
        ESP_LOGI(DUMP_TAG, "DUMP vetter: ssid=%d bloc=%d cryp=%d laa=%d twin=%d "
                 "cln=%d blocked=%u",
                 (int)v->check[0], (int)v->check[1], (int)v->check[2],
                 (int)v->check[3], (int)v->check[4], (int)v->check[5],
                 v->blocked ? 1u : 0u);
        for (uint8_t k = 0; k < 6; k++) {
            const char *reason = vetter_check_reason(s, v, k);
            if (reason) ESP_LOGI(DUMP_TAG, "DUMP vet_r[%u]: %s", k, reason);
        }
        ESP_LOGI(DUMP_TAG, "DUMP summary: %s", v->summary);
    }
}

static void dump_one_ble(uint16_t idx, const ble_device_t *d)
{
    static const char *subtype_str[] = {"public","static","rpa","nrpa"};
    ESP_LOGI(DUMP_TAG, "=== BLE[%u] === name=\"%s\"", idx,
             d->name[0] ? d->name : "(no name)");
    log_addr6("DUMP ble_addr: ", d->addr);

    ESP_LOGI(DUMP_TAG, "DUMP ble_id:   subtype=%s vendor=\"%s\" match_len=%u "
             "class=%u(%s) flags=0x%04X%s%s%s",
             d->addr_subtype < 4 ? subtype_str[d->addr_subtype] : "?",
             d->vendor[0] ? d->vendor : "(none)",
             (unsigned)d->mac_match_len,
             (unsigned)d->device_class, eui_class_label(d->device_class),
             (unsigned)d->eui_flags,
             d->scannable ? " scannable" : "",
             d->is_airtag ? " airtag"    : "",
             d->suppressed ? " suppressed" : "");
    ESP_LOGI(DUMP_TAG, "DUMP ble_bt:   cid=0x%04X comp=\"%s\" cls=%u flags=0x%04X "
             "pl=%02X.%02X u16=%u u32=%u u128=%u",
             (unsigned)d->mfg_company_id,
             d->company_name[0] ? d->company_name : "(none)",
             (unsigned)d->bt_company_class, (unsigned)d->bt_company_flags,
             d->mfg_payload[0], d->mfg_payload[1],
             d->num_uuids16, d->num_uuids32, d->num_uuids128);
    for (uint8_t k = 0; k < d->num_uuids16; k++) {
        ESP_LOGI(DUMP_TAG, "DUMP ble_u16[%u]: 0x%04X", k, (unsigned)d->uuids16[k]);
    }
    ESP_LOGI(DUMP_TAG, "DUMP ble_cat:  rule=\"%s\" cls=%u sub=0x%02X flags=0x%04X",
             d->mfg_rule_name ? d->mfg_rule_name : "(none)",
             (unsigned)d->mfg_rule_class, (unsigned)d->mfg_rule_subtype,
             (unsigned)d->mfg_rule_flags);
    ESP_LOGI(DUMP_TAG, "DUMP ble_apl:  sub=0x%02X name=\"%s\" cls=%u flags=0x%04X "
                       "state=0x%02X ev=\"%s\"",
             (unsigned)d->apple_subtype,
             d->apple_subtype_name ? d->apple_subtype_name : "(none)",
             (unsigned)d->apple_subtype_class, (unsigned)d->apple_subtype_flags,
             (unsigned)d->apple_state,
             d->apple_evidence[0] ? d->apple_evidence : "");
    ESP_LOGI(DUMP_TAG, "DUMP ble_ms:   name=\"%s\" cls=%u flags=0x%04X",
             d->ms_subtype_name ? d->ms_subtype_name : "(none)",
             (unsigned)d->ms_subtype_class, (unsigned)d->ms_subtype_flags);
    ESP_LOGI(DUMP_TAG, "DUMP ble_fp:   model=0x%06lX name=\"%s\"",
             (unsigned long)d->fastpair_model_id,
             d->fastpair_name ? d->fastpair_name : "(none)");
    ESP_LOGI(DUMP_TAG, "DUMP ble_uuid: u32=\"%s\" cls=%u flags=0x%04X | "
             "u128=\"%s\" cls=%u flags=0x%04X",
             d->uuid32_name  ? d->uuid32_name  : "(none)",
             (unsigned)d->uuid32_class,  (unsigned)d->uuid32_flags,
             d->uuid128_name ? d->uuid128_name : "(none)",
             (unsigned)d->uuid128_class, (unsigned)d->uuid128_flags);
    ESP_LOGI(DUMP_TAG, "DUMP ble_nm:   name_rule=\"%s\" cls=%u flags=0x%04X",
             d->name_rule_name ? d->name_rule_name : "(none)",
             (unsigned)d->name_rule_class, (unsigned)d->name_rule_flags);
    const char *phy_str = (d->prim_phy == 1) ? "1M"
                        : (d->prim_phy == 2) ? "2M"
                        : (d->prim_phy == 3) ? "Coded"
                        : "?";
    ESP_LOGI(DUMP_TAG, "DUMP ble_sig:  rssi=%d tx=%d dist=%udm phy=%s",
             (int)d->rssi,
             d->tx_power == 127 ? -59 : (int)d->tx_power,
             (unsigned)(d->distance_dm == 0xFFFF ? 0 : d->distance_dm),
             phy_str);
    uint16_t t = d->trust_q88;
    uint16_t t_int  = t >> 8;
    uint16_t t_frac = ((t & 0xFF) * 10000) >> 8;
    ESP_LOGI(DUMP_TAG, "DUMP ble_scr:  base=%u trust=%u.%04u(q88=%u) "
             "identity=%u/%u threat=%u(%s)",
             d->base_quality, (unsigned)t_int, (unsigned)t_frac, (unsigned)t,
             d->identity_score, d->identity_conf,
             (unsigned)d->threat_level, analyzer_threat_label(d->threat_level));
    uint8_t eff_cls = ble_effective_class(d);
    uint8_t eff_cls_certain = ble_effective_class_certain(d);
    ESP_LOGI(DUMP_TAG, "DUMP ble_conf: vendor=%u class=%u src=%s eff_cls=%u(%s) "
             "eff_cls_certain=%u(%s)",
             (unsigned)d->vendor_conf, (unsigned)d->class_conf,
             ble_class_source_label(d->class_source),
             (unsigned)eff_cls, eui_class_label(eff_cls),
             (unsigned)eff_cls_certain, eui_class_label(eff_cls_certain));
}

static void log_full_scan_dump(const ap_score_t *scores, uint16_t score_count,
                                const ble_results_t *ble)
{
    ESP_LOGI(DUMP_TAG, "=================== FULL SCAN DUMP ====================");
    ESP_LOGI(DUMP_TAG, "DUMP totals: wifi_nets=%u ble_devices=%u",
             score_count, ble ? ble->count : 0);
    for (uint16_t i = 0; i < score_count; i++) {
        const sniffer_rec_t *sr = wifi_sniffer_get(scores[i].bssid);
        vetter_result_t vr;
        vetter_run(&scores[i], ble, &vr);
        dump_one_ap(i, &scores[i], sr, &vr);
    }
    if (ble) {
        for (uint16_t i = 0; i < ble->count; i++) {
            dump_one_ble(i, &ble->devices[i]);
        }
    }

    const probe_req_log_aggregate_t *sl = probe_req_log_get();
    ESP_LOGI(DUMP_TAG, "=== PROBE-REQ LOG ===");
    ESP_LOGI(DUMP_TAG, "DUMP flock_candidate: hits=%u distinct=%u  "
             "(wildcard probe from a Flock OUI; shared-OEM, candidate only)",
             (unsigned)flock_detect_hits(), (unsigned)flock_detect_distinct());
    ESP_LOGI(DUMP_TAG, "DUMP camera_sweep: stations=%u cameras=%u "
             "(client OUI = surveillance vendor)",
             (unsigned)sta_tracker_count(), (unsigned)sta_tracker_camera_count());
    for (uint16_t i = 0; i < sta_tracker_entry_count(); i++) {
        const sta_entry_t *e = sta_tracker_at(i);
        if (!e || !e->is_camera) continue;

        ESP_LOGI(DUMP_TAG, "DUMP camera_sta: %02X:%02X:%02X:%02X:%02X:%02X "
                 "vendor=%s frames=%u up=%u dn=%u rnd=%u rssi=%d/%d ch=%u "
                 "bssid=%02X:%02X:%02X:%02X:%02X:%02X dur=%lums",
                 e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
                 e->vendor ? e->vendor : "?", (unsigned)e->frames,
                 (unsigned)e->frames_uplink, (unsigned)e->frames_downlink,
                 e->randomized ? 1u : 0u, (int)e->rssi_last, (int)e->rssi_best,
                 (unsigned)e->channel,
                 e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
                 (unsigned long)(e->last_seen_ms - e->first_seen_ms));
    }
    ESP_LOGI(DUMP_TAG, "DUMP probe_total:    %u  (directed=%u)  "
             "detail=%u (dropped=%u)",
             (unsigned)sl->total_probe_reqs,
             (unsigned)sl->directed_probe_reqs,
             (unsigned)sl->detail_entries,
             (unsigned)sl->detail_dropped);
    ESP_LOGI(DUMP_TAG, "DUMP probe_pii:      %u",
             (unsigned)sl->counts[SSID_CAT_PII]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_corp:     %u",
             (unsigned)sl->counts[SSID_CAT_CORPORATE]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_hotel:    %u",
             (unsigned)sl->counts[SSID_CAT_HOTEL]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_airport:  %u",
             (unsigned)sl->counts[SSID_CAT_AIRPORT]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_isp:      %u",
             (unsigned)sl->counts[SSID_CAT_ISP]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_openchain:%u",
             (unsigned)sl->counts[SSID_CAT_GENERIC]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_other:    %u",
             (unsigned)sl->counts[SSID_CAT_OTHER]);
    ESP_LOGI(DUMP_TAG, "DUMP probe_hidden:   %u",
             (unsigned)sl->counts[SSID_CAT_HIDDEN]);

    ESP_LOGI(DUMP_TAG, "DUMP probe_local:    %u  remote_saved:%u",
             (unsigned)sl->local_visible_probes,
             (unsigned)sl->remote_saved_probes);

    uint16_t probe_n = probe_req_log_entry_count();
    if (probe_n > 0) {
        for (uint16_t i = 0; i < probe_n; i++) {
            const probe_req_log_entry_t *pe = probe_req_log_entry_at(i);
            if (!pe) continue;
            const char *flag = (pe->category == SSID_CAT_HIDDEN)
                                   ? "hidden"
                                   : (pe->local_visible ? "local" : "REMOTE");
            ESP_LOGI(DUMP_TAG,
                     "DUMP probe[%u]: ssid=\"%s\" mac=%02X:%02X:%02X:%02X:%02X:%02X "
                     "cat=%s %s scan=%u..%u hits=%u",
                     (unsigned)i,
                     pe->ssid[0] ? pe->ssid : "(hidden)",
                     pe->src_mac[0], pe->src_mac[1], pe->src_mac[2],
                     pe->src_mac[3], pe->src_mac[4], pe->src_mac[5],
                     ssid_category_label(pe->category), flag,
                     (unsigned)pe->first_seen_scan,
                     (unsigned)pe->last_seen_scan,
                     (unsigned)pe->hit_count);
        }
    }

    const seq_analyzer_aggregate_t *sa = seq_analyzer_get();
    ESP_LOGI(DUMP_TAG, "=== SEQ LINKABILITY ===");
    ESP_LOGI(DUMP_TAG, "DUMP seq_total:      %u  (distinct_macs=%u)",
             (unsigned)sa->total_probe_reqs,
             (unsigned)sa->distinct_macs);
    ESP_LOGI(DUMP_TAG, "DUMP seq_linked:     %u  (apparent_devices=%u)",
             (unsigned)sa->linked_pairs,
             (unsigned)sa->apparent_devices);
    ESP_LOGI(DUMP_TAG, "DUMP seq_chipset:    seq11=%u  seq12=%u  (dropped=%u)",
             (unsigned)sa->chipset_seq11,
             (unsigned)sa->chipset_seq12,
             (unsigned)sa->entries_dropped);

    const ie_signature_aggregate_t *ia = ie_signature_get();
    ESP_LOGI(DUMP_TAG, "=== IE SIGNATURES ===");
    ESP_LOGI(DUMP_TAG, "DUMP ie_total:       %u  (distinct_macs=%u)",
             (unsigned)ia->total_probe_reqs,
             (unsigned)ia->distinct_macs);
    ESP_LOGI(DUMP_TAG, "DUMP ie_hashes:      distinct=%u  top=0x%08lx  top_macs=%u  dropped=%u",
             (unsigned)ia->distinct_hashes,
             (unsigned long)ia->top_hash,
             (unsigned)ia->top_hash_macs,
             (unsigned)ia->entries_dropped);
    ESP_LOGI(DUMP_TAG, "DUMP ie_xcheck:      recognized=%u  mismatched=%u",
             (unsigned)ia->recognized_macs,
             (unsigned)ia->mismatched_macs);

    const anqp_analyzer_aggregate_t *aa = anqp_analyzer_get();
    ESP_LOGI(DUMP_TAG, "=== ANQP LEAKAGE ===");
    ESP_LOGI(DUMP_TAG, "DUMP anqp_total:     %u  (distinct_macs=%u)",
             (unsigned)aa->total_queries,
             (unsigned)aa->distinct_macs);
    ESP_LOGI(DUMP_TAG, "DUMP anqp_leak:      universal=%u  laa=%u  (dropped=%u)",
             (unsigned)aa->universal_macs,
             (unsigned)aa->laa_macs,
             (unsigned)aa->entries_dropped);

    ESP_LOGI(DUMP_TAG, "=== DEVICE CLUSTERS ===");
    ESP_LOGI(DUMP_TAG, "DUMP clusters: %u  (edges=%u)",
             (unsigned)pdc_cluster_count(), (unsigned)pdc_edge_count());
    for (uint8_t c = 0; c < pdc_cluster_count(); c++) {
        const pdc_cluster_t *cl = pdc_cluster_get(c);
        if (!cl) continue;
        ESP_LOGI(DUMP_TAG, "DUMP cluster[%u]: members=%u conf=%u%%",
                 c, (unsigned)cl->total_members, (unsigned)cl->confidence);
        for (uint8_t e = 0; e < pdc_edge_count(); e++) {
            const pdc_edge_t *ed = pdc_edge_get(e);
            if (!ed || pdc_cluster_of(ed->kind_a, ed->idx_a) != (int8_t)c)
                continue;
            ESP_LOGI(DUMP_TAG,
                     "DUMP   edge: %s[%u] <-> %s[%u]  %s %u%%",
                     ed->kind_a == PDC_NODE_WIFI ? "wifi" : "ble", ed->idx_a,
                     ed->kind_b == PDC_NODE_WIFI ? "wifi" : "ble", ed->idx_b,
                     pdc_evidence_label(ed->evidence), ed->confidence);
        }
    }

    {
        capture_ring_stats_t cs;
        capture_ring_get_stats(&cs);
        ESP_LOGI(DUMP_TAG, "=== CAPTURE RING ===");
        ESP_LOGI(DUMP_TAG, "DUMP capture_ring: cap=%u used=%u recs_live=%u "
                 "recs_total=%u dropped=%u bytes_total=%llu",
                 (unsigned)cs.capacity, (unsigned)cs.bytes_used,
                 (unsigned)cs.records_current, (unsigned)cs.records_total,
                 (unsigned)cs.records_dropped,
                 (unsigned long long)cs.bytes_total);
    }

    ESP_LOGI(DUMP_TAG, "=================== END SCAN DUMP =====================");
}

static void scan_anim_task(void *arg)
{
    const int step = 6;
    const int xmin = display_scan_walk_x_min();
    const int xmax = display_scan_walk_x_max();
    int x = xmin, dir = +1;
    int sniff_frame = 0;
    int walk_div = 0;
    int dig_frame = 0, dig_div = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(80));
        if (!s_state_mutex) continue;
        xSemaphoreTake(s_state_mutex, portMAX_DELAY);
        if ((s_ui_mode == UI_MODE_SCANNING && s_anim_dig) ||
            s_ui_mode == UI_MODE_PUP_DIG) {

            display_score_dig_frame(dig_frame);
            led_reassert();
            if (++dig_div >= 2) { dig_div = 0; dig_frame = (dig_frame + 1) % 3; }
        } else if (s_ui_mode == UI_MODE_SCANNING || s_ui_mode == UI_MODE_WALK) {

            if (++walk_div >= 2) {
                walk_div = 0;
                display_scan_walk_frame(x, dir < 0, sniff_frame);
                led_reassert();
                sniff_frame ^= 1;
                if (dir > 0) {
                    if (x >= xmax) { dir = -1; sniff_frame = 0; }
                    else { x += step; if (x > xmax) x = xmax; }
                } else {
                    if (x <= xmin) { dir = +1; sniff_frame = 0; }
                    else { x -= step; if (x < xmin) x = xmin; }
                }
            }
        } else {
            x = xmin; dir = +1; sniff_frame = 0;
            walk_div = 0; dig_frame = 0; dig_div = 0;
        }
        xSemaphoreGive(s_state_mutex);
    }
}

static uint8_t least_congested_2g_channel(void);

typedef struct {
    pup_walk_summary_t cur;
    bool abort;
    bool cap_hit;
} walk_ctx_t;

static void walk_on_enter(void *ctx)
{
    (void)ctx;
    virtual_pup_walk_start();
    s_walk_end_requested = false;

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    s_ui_mode = UI_MODE_WALK;
    display_walk_screen(virtual_pup_name(), 0, 0, 0, false);
    xSemaphoreGive(s_state_mutex);
    if (s_led_enabled) led_apply(0, 128, 64, 8);
}

static void walk_loop(void *ctx)
{
    walk_ctx_t *w = (walk_ctx_t *)ctx;
    static scan_results_t  walk_wifi;
    static EXT_RAM_BSS_ATTR ap_score_t walk_scores[ANALYZER_MAX_APS];
    static EXT_RAM_BSS_ATTR ble_results_t walk_ble;
    static uint32_t walk_slice = 0;

    bool include_5g = (walk_slice++ % WIFI_WARDRIVE_5G_EVERY) == 0;
    memset(&walk_wifi, 0, sizeof(walk_wifi));
    if (wifi_scan_run_wardrive(&walk_wifi, include_5g) == ESP_OK) {
        uint16_t walk_score_count = 0;
        memset(walk_scores, 0, sizeof(walk_scores));
        analyzer_run(&walk_wifi, NULL, walk_scores, &walk_score_count);
        for (uint16_t i = 0; i < walk_score_count; i++) {
            const ap_score_t *ap = &walk_scores[i];
            bool safe = ap->auth != WIFI_AUTH_OPEN && ap->auth != WIFI_AUTH_WEP;
            virtual_pup_walk_note_wifi_ap(ap, safe);
        }
        virtual_pup_walk_end_wifi_sweep();
    }
    if (s_walk_end_requested) { w->abort = true; return; }

    memset(&walk_ble, 0, sizeof(walk_ble));
    if (ble_scan_run_ex(&walk_ble, WALK_BLE_WINDOW_MS, true, false) == ESP_OK) {
        for (uint16_t i = 0; i < walk_ble.count; i++)
            virtual_pup_walk_note_ble_device(&walk_ble.devices[i]);
        virtual_pup_walk_end_ble_window();
    }

    virtual_pup_walk_get_current(&w->cur);
    if (w->cur.duration_sec >= WALK_MAX_SEC) w->cap_hit = true;
}

static void walk_render(void *ctx)
{
    walk_ctx_t *w = (walk_ctx_t *)ctx;
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    if (s_ui_mode == UI_MODE_WALK)
        display_walk_screen(virtual_pup_name(), w->cur.duration_sec,
                            w->cur.wifi_unique_bssid, w->cur.ble_unique_devices, false);
    xSemaphoreGive(s_state_mutex);
}

static void walk_on_exit(void *ctx)
{
    (void)ctx;

    pup_walk_summary_t done = {0};
    if (virtual_pup_walk_end(&done)) {
        virtual_pup_grant_xp(done.xp_awarded);
        s_capture_scan_idx++;
        for (uint16_t i = 0; i < virtual_pup_walk_wifi_count(); i++) {
            const ap_score_t *ap = virtual_pup_walk_wifi_at(i);
            if (ap) {
                capture_emit_wifi_ap_walk(ap, s_capture_scan_idx, done.walk_id);
                capture_emit_alerts_for_ap(ap, s_capture_scan_idx);
            }
        }
        for (uint16_t i = 0; i < virtual_pup_walk_ble_count(); i++) {
            const ble_device_t *d = virtual_pup_walk_ble_at(i);
            if (d) {
                capture_emit_ble_device_walk(d, s_capture_scan_idx, done.walk_id);
                capture_emit_tracker_if_applicable(d, s_capture_scan_idx);
                capture_emit_drone_rid_if_applicable(d, s_capture_scan_idx);
                capture_emit_alerts_for_ble(d, s_capture_scan_idx);
            }
        }
        capture_emit_pup_walk(&done);
    }

    virtual_pup_walk_release();

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    display_walk_screen(virtual_pup_name(), done.duration_sec,
                        done.wifi_unique_bssid, done.ble_unique_devices, true);
    xSemaphoreGive(s_state_mutex);
    vTaskDelay(pdMS_TO_TICKS(1500));

    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    download_mode_set_channel(least_congested_2g_channel());
    download_mode_request_enable();
    s_dl_last_drawn_state = 0xFF;
    s_ui_mode = UI_MODE_DOWNLOAD_ACTIVE;
    led_apply(0, 0, 255, 8);
    render_ui_locked();
    xSemaphoreGive(s_state_mutex);
}

static const ui_activity_t walk_activity = {
    .name     = "walk",
    .on_enter = walk_on_enter,
    .loop     = walk_loop,
    .render   = walk_render,
    .on_exit  = walk_on_exit,
};

static void do_walk(void)
{
    walk_ctx_t ctx = {0};
    ui_activity_switch(&walk_activity, &ctx);

    while (!s_walk_end_requested) {
        ctx.abort = false;
        walk_activity.loop(&ctx);
        if (ctx.abort) break;
        walk_activity.render(&ctx);
        if (ctx.cap_hit) break;
    }

    ui_activity_switch(NULL, &ctx);
}

static void scan_task(void *arg)
{

    s_regular_scan_override = true;
    do_scan();
    for (;;) {

        xTaskNotifyWait(0, 0, NULL, portMAX_DELAY);
        if (s_walk_requested) {
            s_walk_requested = false;
            do_walk();
        } else {
            do_scan();
        }
    }
}

static void capture_task(void *arg)
{
    (void)arg;
    for (;;) {
        xTaskNotifyWait(0, 0, NULL, portMAX_DELAY);
        uint8_t  ch   = s_capture_channel;
        uint32_t msdur = (uint32_t)s_capture_secs * 1000;
        s_capture_scan_idx++;
        if (s_capture_kind == 0) {
            wifi_csi_probe_run(ch, msdur);
            capture_emit_csi(s_capture_scan_idx);
        } else if (s_capture_kind == 2) {

            pcap_capture_run(s_pcap_channels, s_pcap_channel_count,
                             s_capture_secs, s_capture_scan_idx);
            capture_emit_pcap_capture(pcap_capture_meta(), s_capture_scan_idx);
        } else {
            wifi_sniffer_sta_window(ch, msdur);
            capture_emit_station_log(s_capture_scan_idx);
        }

        if (s_state_mutex) {
            xSemaphoreTake(s_state_mutex, portMAX_DELAY);

            download_mode_set_channel(least_congested_2g_channel());
            download_mode_request_enable();
            s_dl_last_drawn_state = 0xFF;
            s_ui_mode = UI_MODE_DOWNLOAD_ACTIVE;
            led_apply(0, 0, 255, 8);
            render_ui_locked();
            xSemaphoreGive(s_state_mutex);
        }
    }
}

static uint8_t least_congested_2g_channel(void)
{
    uint16_t load[14] = {0};
    for (uint16_t i = 0; i < s_score_count; i++) {
        if (s_scores[i].band_5g) continue;
        uint8_t ch = s_scores[i].channel;
        if (ch >= 1 && ch <= 13) load[ch]++;
    }
    const uint8_t cands[] = {1, 6, 11};
    uint8_t best = 6;
    uint16_t best_load = 0xFFFF;
    for (size_t i = 0; i < sizeof(cands); i++) {
        if (load[cands[i]] < best_load) { best_load = load[cands[i]]; best = cands[i]; }
    }
    return best;
}

void app_request_scan_after_download(void)
{
    s_rescan_after_dl = true;
    download_mode_request_disable(CAP_END_SCAN_START);
}

void app_request_walk_after_download(void)
{
    s_walk_after_dl = true;
    download_mode_request_disable(CAP_END_SCAN_START);
}

static void request_capture_after_download(uint8_t kind, uint8_t channel, uint16_t seconds)
{
    if (channel < 1 || channel > 177) channel = 6;
    if (seconds < 1 || seconds > 30)  seconds = 5;
    s_capture_kind     = kind;
    s_capture_channel  = channel;
    s_capture_secs     = seconds;
    s_capture_after_dl = true;
    download_mode_request_disable(CAP_END_SCAN_START);
}

void app_request_sta_capture_after_download(uint8_t channel, uint16_t seconds)
{
    request_capture_after_download(1, channel, seconds);
}

void app_request_csi_after_download(uint8_t channel, uint16_t seconds)
{
    request_capture_after_download(0, channel, seconds);
}

void app_request_pcap_after_download(const uint8_t *channels, uint8_t n)
{
    if (!channels || n == 0) return;
    if (n > PCAP_MAX_CHANNELS) n = PCAP_MAX_CHANNELS;
    memcpy(s_pcap_channels, channels, n);
    s_pcap_channel_count = n;
    s_capture_kind     = 2;
    s_capture_secs     = 10;
    s_capture_after_dl = true;
    download_mode_request_disable(CAP_END_SCAN_START);
}

void app_scan_channels_json(char *buf, size_t buflen)
{
    typedef struct { uint8_t ch; uint8_t band5; uint16_t aps; } chan_d_t;
    chan_d_t d[48];
    uint8_t n = 0;
    for (uint16_t i = 0; i < s_score_count; i++) {
        uint8_t ch = s_scores[i].channel;
        bool b5 = s_scores[i].band_5g;
        if (ch == 0) continue;
        uint8_t k = 0;
        for (; k < n; k++) if (d[k].ch == ch && d[k].band5 == b5) break;
        if (k == n) {
            if (n >= sizeof(d) / sizeof(d[0])) continue;
            d[n].ch = ch; d[n].band5 = b5; d[n].aps = 0; n++;
        }
        d[k].aps++;
    }

    for (uint8_t i = 1; i < n; i++) {
        for (uint8_t j = i; j > 0 && d[j].ch < d[j - 1].ch; j--) {
            chan_d_t t = d[j]; d[j] = d[j - 1]; d[j - 1] = t;
        }
    }
    size_t o = 0;
    o += snprintf(buf + o, buflen - o, "{\"count\":%u,\"channels\":[", (unsigned)n);
    for (uint8_t i = 0; i < n && o < buflen - 40; i++) {
        o += snprintf(buf + o, buflen - o, "%s{\"ch\":%u,\"band\":%u,\"aps\":%u}",
                      i ? "," : "", (unsigned)d[i].ch, d[i].band5 ? 5 : 2,
                      (unsigned)d[i].aps);
    }
    snprintf(buf + o, buflen - o, "]}");
}

static void dl_tick_cb(void *arg)
{
    if (!s_state_mutex) return;
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    if (s_ui_mode == UI_MODE_DOWNLOAD_ACTIVE) {
        download_state_t st = download_mode_get_state();
        if (st == DL_PASSIVE_SCAN) {

            s_dl_last_drawn_state = 0xFF;
            s_dl_last_drawn_joined = 0xFF;
            if (s_rescan_after_dl) {
                s_rescan_after_dl = false;
                s_ui_mode = UI_MODE_SCANNING;
                display_scan_stage_static("WiFi");
                led_apply(128, 0, 128, 8);
                s_force_rescan = true;
                ESP_LOGI(TAG, "WebAP scan-start: AP down, rescan armed");
            } else if (s_walk_after_dl) {

                s_walk_after_dl = false;
                s_walk_requested = true;
                s_ui_mode = UI_MODE_WALK;
                display_walk_screen(virtual_pup_name(), 0, 0, 0, false);
                s_force_rescan = true;
                ESP_LOGI(TAG, "WebAP walk-start: AP down, walk armed");
            } else if (s_capture_after_dl) {

                s_capture_after_dl = false;
                s_ui_mode = UI_MODE_SCANNING;
                display_scan_stage_static(s_capture_kind == 0 ? "CSI"
                                          : s_capture_kind == 2 ? "PCAP" : "STA");
                led_apply(128, 0, 128, 8);
                if (s_capture_task_handle)
                    xTaskNotify(s_capture_task_handle, 0, eNoAction);
                ESP_LOGI(TAG, "WebAP capture: AP down, %s armed (ch %u, %us)",
                         s_capture_kind == 0 ? "CSI" : "STA",
                         (unsigned)s_capture_channel, (unsigned)s_capture_secs);
            } else {
                s_ui_mode = UI_MODE_MAIN;
                render_ui_locked();
                led_for_verdict(analyzer_threat_to_verdict(env_threat_level()));
            }
        } else if ((uint8_t)st != s_dl_last_drawn_state ||
                   (st == DL_AP_ACTIVE &&
                    (download_mode_get_client_count() > 0) != (s_dl_last_drawn_joined == 1))) {

            s_dl_last_drawn_state = (uint8_t)st;
            render_download_active_locked();
            dl_assert_led_locked();
        } else {
            draw_download_countdown_locked();
            dl_assert_led_locked();
        }
    }
    xSemaphoreGive(s_state_mutex);
}

typedef enum {
    BTN_EVENT_NONE = 0,
    BTN_EVENT_SINGLE,
    BTN_EVENT_DOUBLE,
    BTN_EVENT_LONG,
} button_event_t;

static volatile button_event_t s_injected_btn = BTN_EVENT_NONE;

static bool s_screensaver;
static bool screensaver_eligible(void)
{
    switch (s_ui_mode) {
    case UI_MODE_SCANNING:
    case UI_MODE_WALK:
    case UI_MODE_DOWNLOAD_ACTIVE:
        return false;
    default:
        return true;
    }
}
static void screensaver_enter(void)
{
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    display_logo_frame(LOGO_HOLD_FRAME);
    led_reassert();
    xSemaphoreGive(s_state_mutex);
    s_screensaver = true;
    ESP_LOGI(TAG, "screensaver: logo (idle)");
}
static void screensaver_wake(void)
{
    s_screensaver = false;
    xSemaphoreTake(s_state_mutex, portMAX_DELAY);
    render_ui_locked();
    xSemaphoreGive(s_state_mutex);
    ESP_LOGI(TAG, "screensaver: wake");
}

static button_event_t wait_button_event(void)
{
    uint32_t idle_ms = 0;
    for (;;) {

        if (s_injected_btn != BTN_EVENT_NONE) {
            button_event_t inj = s_injected_btn;
            s_injected_btn = BTN_EVENT_NONE;
            s_screensaver = false;
            return inj;
        }

        if (gpio_get_level(PIN_BOOT) != 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            idle_ms += 20;
            if (!s_screensaver && idle_ms >= SCREENSAVER_MS && screensaver_eligible())
                screensaver_enter();
            continue;
        }
        idle_ms = 0;

        if (s_screensaver) {
            screensaver_wake();
            vTaskDelay(pdMS_TO_TICKS(30));
            while (gpio_get_level(PIN_BOOT) == 0) vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        vTaskDelay(pdMS_TO_TICKS(30));
        if (gpio_get_level(PIN_BOOT) != 0) continue;

        uint32_t held = 0;
        while (gpio_get_level(PIN_BOOT) == 0 && held < LONG_HOLD_MS) {
            vTaskDelay(pdMS_TO_TICKS(20));
            held += 20;
        }

        if (gpio_get_level(PIN_BOOT) == 0 && held >= LONG_HOLD_MS) {
            while (gpio_get_level(PIN_BOOT) == 0) vTaskDelay(pdMS_TO_TICKS(20));
            return BTN_EVENT_LONG;
        }

        uint32_t gap = 0;
        while (gap < DOUBLE_CLICK_GAP_MS) {
            vTaskDelay(pdMS_TO_TICKS(20));
            gap += 20;

            if (gpio_get_level(PIN_BOOT) == 0) {

                vTaskDelay(pdMS_TO_TICKS(30));
                if (gpio_get_level(PIN_BOOT) != 0) continue;

                while (gpio_get_level(PIN_BOOT) == 0) vTaskDelay(pdMS_TO_TICKS(20));
                return BTN_EVENT_DOUBLE;
            }
        }

        return BTN_EVENT_SINGLE;
    }
}

static void button_task(void *arg)
{
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << PIN_BOOT),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);

    for (;;) {
        button_event_t ev = wait_button_event();

        xSemaphoreTake(s_state_mutex, portMAX_DELAY);

        if (s_ui_mode == UI_MODE_ENV_SUMMARY) {

            if (ev == BTN_EVENT_SINGLE) {
                ui_activity_switch(NULL, NULL);
                s_ui_mode = UI_MODE_MAIN;
                render_main_locked();
                ESP_LOGI(TAG, "ENV_SUMMARY: one -> MAIN");
            } else if (ev == BTN_EVENT_DOUBLE) {
                ui_activity_switch(NULL, NULL);
                s_ui_mode = UI_MODE_PUP;
                render_ui_locked();
                ESP_LOGI(TAG, "ENV_SUMMARY: two -> PUP");
            } else if (ev == BTN_EVENT_LONG) {
                ui_activity_switch(NULL, NULL);
                s_force_rescan = true;
                s_ui_mode = UI_MODE_SCANNING;
                display_scan_stage_static("WiFi");
                led_apply(128, 0, 128, 8);
                ESP_LOGI(TAG, "ENV_SUMMARY: hold -> rescan");
            }

        } else if (s_ui_mode == UI_MODE_PUP) {

            if (ev == BTN_EVENT_SINGLE) {
                s_ui_mode = UI_MODE_PUP_INTERACT;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP: one -> PUP_INTERACT");
            } else if (ev == BTN_EVENT_DOUBLE) {
                ui_activity_switch(&env_summary_activity, NULL);
                ESP_LOGI(TAG, "PUP: two -> ENV_SUMMARY");
            } else if (ev == BTN_EVENT_LONG) {

                s_walk_requested = true;
                s_ui_mode = UI_MODE_WALK;
                display_walk_screen(virtual_pup_name(), 0, 0, 0, false);
                s_force_rescan = true;
                ESP_LOGI(TAG, "PUP: hold -> start Sniff Walk");
            }

        } else if (s_ui_mode == UI_MODE_WALK) {

            if (ev == BTN_EVENT_LONG) {
                s_walk_end_requested = true;
                ESP_LOGI(TAG, "WALK: hold -> end walk");
            }

        } else if (s_ui_mode == UI_MODE_PUP_INTERACT) {

            if (ev == BTN_EVENT_SINGLE) {
                s_ui_mode = UI_MODE_PUP_DIG;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_INTERACT: one -> PUP_DIG");
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_trophy_cursor = 0;
                s_ui_mode = UI_MODE_PUP_TROPHIES;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_INTERACT: two -> PUP_TROPHIES");
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_PUP;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_INTERACT: hold -> PUP");
            }

        } else if (s_ui_mode == UI_MODE_PUP_DIG) {

            if (ev == BTN_EVENT_SINGLE) {
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_DIG: one -> dig more");
            } else if (ev == BTN_EVENT_DOUBLE || ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_PUP_INTERACT;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_DIG: back -> PUP_INTERACT");
            }

        } else if (s_ui_mode == UI_MODE_PUP_TROPHIES) {

            if (ev == BTN_EVENT_SINGLE) {
                uint16_t total = pup_trophy_earned_count();
                if (total) s_trophy_cursor = (s_trophy_cursor + 1) % total;
                render_ui_locked();
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (pup_trophy_earned_count()) {
                    s_ui_mode = UI_MODE_PUP_TROPHY_DETAIL;
                    ESP_LOGI(TAG, "PUP_TROPHIES: two -> DETAIL");
                }
                render_ui_locked();
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_PUP_INTERACT;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_TROPHIES: hold -> PUP_INTERACT");
            }

        } else if (s_ui_mode == UI_MODE_PUP_TROPHY_DETAIL) {

            if (ev == BTN_EVENT_SINGLE) {
                uint16_t total = pup_trophy_earned_count();
                if (total) s_trophy_cursor = (s_trophy_cursor + 1) % total;
                render_ui_locked();
            } else if (ev == BTN_EVENT_DOUBLE || ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_PUP_TROPHIES;
                render_ui_locked();
                ESP_LOGI(TAG, "PUP_TROPHY_DETAIL: back -> PUP_TROPHIES");
            }

        } else if (s_ui_mode == UI_MODE_MAIN) {

            if (s_main_sel >= MAIN_ROW_COUNT) s_main_sel = 0;
            if (ev == BTN_EVENT_SINGLE) {
                s_main_sel = (uint8_t)((s_main_sel + 1) % MAIN_ROW_COUNT);
                render_ui_locked();
                ESP_LOGI(TAG, "MAIN: one -> row %u/%u", s_main_sel, (unsigned)MAIN_ROW_COUNT);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (s_main_sel == 0) {
                    ui_activity_switch(&options_activity, NULL);
                    ESP_LOGI(TAG, "MAIN: sel -> RESULTS");
                } else if (s_main_sel == 1) {
                    menu_open_root(&settings_menu);
                    ESP_LOGI(TAG, "MAIN: sel -> SETTINGS (menu)");
                } else {
                    s_force_rescan = true;
                    s_ui_mode = UI_MODE_SCANNING;
                    display_scan_stage_static("WiFi");
                    led_apply(128, 0, 128, 8);
                    ESP_LOGI(TAG, "MAIN: sel -> rescan");
                }
            } else if (ev == BTN_EVENT_LONG) {
                if (s_scan_valid) {
                    ui_activity_switch(&env_summary_activity, NULL);
                    ESP_LOGI(TAG, "MAIN: hold -> ENV_SUMMARY");
                } else {
                    ESP_LOGI(TAG, "MAIN: hold -> (root, no scan)");
                }
            }

        } else if (s_ui_mode == UI_MODE_MENU) {

            if (ev == BTN_EVENT_SINGLE) {
                menu_cursor_next();
            } else if (ev == BTN_EVENT_DOUBLE) {
                menu_activate();
            } else if (ev == BTN_EVENT_LONG) {
                menu_pop();
            }

        } else if (s_ui_mode == UI_MODE_OPTIONS) {

            results_pane_t panes[5];
            uint8_t n = results_panes(panes);
            if (s_results_pane >= n) s_results_pane = 0;

            if (ev == BTN_EVENT_SINGLE) {
                s_results_pane = (uint8_t)((s_results_pane + 1) % n);
                render_ui_locked();
                ESP_LOGI(TAG, "RESULTS: one -> row %u/%u", s_results_pane, n);
            } else if (ev == BTN_EVENT_DOUBLE) {
                switch (panes[s_results_pane]) {
                case RPANE_WIFI:
                    s_wifi_index = 1;
                    ui_activity_switch(&wifi_list_activity, NULL);
                    ESP_LOGI(TAG, "RESULTS: sel -> WIFI");
                    break;
                case RPANE_BLE:
                    s_ble_index = 1;
                    ui_activity_switch(&ble_list_activity, NULL);
                    ESP_LOGI(TAG, "RESULTS: sel -> BLE");
                    break;
                case RPANE_PROBES:
                    ui_activity_switch(NULL, NULL);
                    s_ui_mode = UI_MODE_PROBE_LOG;
                    render_ui_locked();
                    ESP_LOGI(TAG, "RESULTS: sel -> PROBE_LOG");
                    break;
                case RPANE_PUP:
                    ui_activity_switch(NULL, NULL);
                    s_ui_mode = UI_MODE_PUP;
                    render_ui_locked();
                    ESP_LOGI(TAG, "RESULTS: sel -> PUP");
                    break;
                default:
                    ui_activity_switch(NULL, NULL);
                    s_ui_mode = UI_MODE_MAIN;
                    render_ui_locked();
                    ESP_LOGI(TAG, "RESULTS: sel -> MAIN");
                    break;
                }
            } else if (ev == BTN_EVENT_LONG) {

                ui_activity_switch(NULL, NULL);
                if (s_scan_valid) {
                    ui_activity_switch(&env_summary_activity, NULL);
                    ESP_LOGI(TAG, "RESULTS: hold -> ENV_SUMMARY");
                } else {
                    s_ui_mode = UI_MODE_MAIN;
                    render_ui_locked();
                    ESP_LOGI(TAG, "RESULTS: hold -> MAIN (no scan)");
                }
            }

        } else if (s_ui_mode == UI_MODE_DOWNLOAD_CONFIRM) {

            if (s_dl_sel >= DL_ROW_COUNT) s_dl_sel = 0;
            if (ev == BTN_EVENT_SINGLE) {
                s_dl_sel = (uint8_t)((s_dl_sel + 1) % DL_ROW_COUNT);
                render_ui_locked();
                ESP_LOGI(TAG, "DOWNLOAD_CONFIRM: one -> row %u/%u", s_dl_sel, DL_ROW_COUNT);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (s_dl_sel == 0) {
                    download_mode_set_channel(least_congested_2g_channel());
                    download_mode_request_enable();
                    s_dl_last_drawn_state = 0xFF;
                    s_ui_mode = UI_MODE_DOWNLOAD_ACTIVE;
                    led_apply(0, 0, 255, 8);
                    render_ui_locked();
                    ESP_LOGI(TAG, "DOWNLOAD_CONFIRM: sel -> enable AP");
                } else {
                    uint8_t m = download_mode_get_timeout_minutes();
                    uint8_t next = (m == 15) ? 30 : (m == 30) ? 60 : 15;
                    download_mode_set_timeout_minutes(next);
                    render_ui_locked();
                    ESP_LOGI(TAG, "DOWNLOAD_CONFIRM: sel -> timeout %u", (unsigned)next);
                }
            } else if (ev == BTN_EVENT_LONG) {
                menu_return_from_leaf();
                ESP_LOGI(TAG, "DOWNLOAD_CONFIRM: hold -> SETTINGS (menu)");
            }

        } else if (s_ui_mode == UI_MODE_DOWNLOAD_ACTIVE) {

            if (ev == BTN_EVENT_LONG) {
                download_mode_request_disable(CAP_END_USER_DISABLE);
                ESP_LOGI(TAG, "DOWNLOAD_ACTIVE: hold -> disable AP");
            }

        } else if (s_ui_mode == UI_MODE_CREDITS) {

            if (ev == BTN_EVENT_SINGLE) {
                s_credit_index = (uint8_t)((s_credit_index + 1) % CREDIT_COUNT);
                render_ui_locked();
                ESP_LOGI(TAG, "CREDITS: one -> idx %u", s_credit_index);
            } else if (ev == BTN_EVENT_DOUBLE || ev == BTN_EVENT_LONG) {
                menu_return_from_leaf();
                ESP_LOGI(TAG, "CREDITS: back -> DEVICE");
            }

        } else if (s_ui_mode == UI_MODE_WIFI_LIST) {
            if (s_advisor_mode == ADVISOR_MODE_LITE) {

                if (ev == BTN_EVENT_SINGLE) {
                    if (s_score_count > 0)
                        s_wifi_index = lite_next_index(s_wifi_index);
                    render_ui_locked();
                    ESP_LOGI(TAG, "WIFI(Lite): one -> next idx %u/%u",
                             s_wifi_index, s_score_count);
                } else if (ev == BTN_EVENT_DOUBLE) {
                    if (s_score_count > 0) {
                        s_details_page  = 0;
                        s_details_total = 1;
                        ui_activity_switch(&details_wifi_activity, NULL);
                        ESP_LOGI(TAG, "WIFI(Lite): two -> DETAILS idx %u",
                                 s_wifi_index);
                    }
                } else if (ev == BTN_EVENT_LONG) {
                    ui_activity_switch(&options_activity, NULL);
                    ESP_LOGI(TAG, "WIFI(Lite): hold -> RESULTS");
                }
            } else {

                if (ev == BTN_EVENT_SINGLE) {
                    if (s_score_count > 0) {
                        s_wifi_index++;
                        if (s_wifi_index > wifi_disp_count()) s_wifi_index = 1;
                    }
                    render_ui_locked();
                    ESP_LOGI(TAG, "WIFI: one -> idx %u/%u",
                             s_wifi_index, s_score_count);
                } else if (ev == BTN_EVENT_DOUBLE) {
                    if (s_score_count > 0) {
                        s_details_page  = 0;
                        s_details_total = 1;
                        ui_activity_switch(&details_wifi_activity, NULL);
                        ESP_LOGI(TAG, "WIFI: two -> DETAILS idx %u", s_wifi_index);
                    }
                } else if (ev == BTN_EVENT_LONG) {
                    s_results_pane = 0;
                    ui_activity_switch(&options_activity, NULL);
                    ESP_LOGI(TAG, "WIFI: hold -> RESULTS");
                }
            }

        } else if (s_ui_mode == UI_MODE_BLE_LIST) {
            if (s_advisor_mode == ADVISOR_MODE_LITE) {

                if (ev == BTN_EVENT_SINGLE) {
                    uint16_t total = ble_filter_count();
                    if (total > 0) {
                        s_ble_index++;
                        if (s_ble_index > total) s_ble_index = 1;
                    }
                    render_ui_locked();
                    ESP_LOGI(TAG, "BLE(Lite): one -> next idx %u/%u",
                             s_ble_index, total);
                } else if (ev == BTN_EVENT_DOUBLE) {
                    if (s_ble.count > 0) {
                        s_details_page  = 0;
                        s_details_total = 1;
                        ui_activity_switch(&details_ble_activity, NULL);
                        ESP_LOGI(TAG, "BLE(Lite): two -> DETAILS idx %u", s_ble_index);
                    }
                } else if (ev == BTN_EVENT_LONG) {
                    s_ble_class_filter = BLE_CLASS_FILTER_NONE;
                    ui_activity_switch(&options_activity, NULL);
                    ESP_LOGI(TAG, "BLE(Lite): hold -> RESULTS");
                }
            } else {

                if (ev == BTN_EVENT_SINGLE) {
                    uint16_t total = ble_filter_count();
                    if (total > 0) {
                        s_ble_index++;
                        if (s_ble_index > total) s_ble_index = 1;
                    }
                    render_ui_locked();
                    ESP_LOGI(TAG, "BLE: one -> idx %u/%u (filter=%s)",
                             s_ble_index, total,
                             ble_filter_label() ? ble_filter_label() : "(none)");
                } else if (ev == BTN_EVENT_DOUBLE) {
                    if (s_ble.count > 0) {
                        s_details_page  = 0;
                        s_details_total = 1;
                        ui_activity_switch(&details_ble_activity, NULL);
                        ESP_LOGI(TAG, "BLE: two -> DETAILS idx %u", s_ble_index);
                    }
                } else if (ev == BTN_EVENT_LONG) {

                    s_ble_class_filter = BLE_CLASS_FILTER_NONE;
                    ui_activity_switch(NULL, NULL);
                    s_ui_mode = UI_MODE_BLE_CLASSES;
                    s_ble_class_focus = 0;
                    render_ui_locked();
                    ESP_LOGI(TAG, "BLE: hold -> CLASSES (filter cleared)");
                }
            }

        } else if (s_ui_mode == UI_MODE_DETAILS_WIFI) {
            if (ev == BTN_EVENT_SINGLE) {
                if (s_details_total > 0)
                    s_details_page = (uint8_t)((s_details_page + 1) % s_details_total);
                render_ui_locked();
                ESP_LOGI(TAG, "DETAILS_WIFI: one -> page %u/%u",
                         (unsigned)(s_details_page + 1), s_details_total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (s_advisor_mode == ADVISOR_MODE_LITE) {

                    if (s_score_count > 0)
                        s_wifi_index = lite_next_index(s_wifi_index);
                    s_details_page = 0;
                    render_ui_locked();
                    ESP_LOGI(TAG, "DETAILS_WIFI(Lite): two -> next idx %u",
                             s_wifi_index);
                } else {

                    if (s_score_count > 0) {
                        s_wifi_index++;
                        if (s_wifi_index > wifi_disp_count()) s_wifi_index = 1;
                    }
                    s_details_page = 0;
                    render_ui_locked();
                    ESP_LOGI(TAG, "DETAILS_WIFI: two -> next idx %u/%u",
                             s_wifi_index, s_score_count);
                }
            } else if (ev == BTN_EVENT_LONG) {
                s_details_page = 0;
                ui_activity_switch(&wifi_list_activity, NULL);
                ESP_LOGI(TAG, "DETAILS_WIFI: hold -> WIFI_LIST idx %u", s_wifi_index);
            }

        } else if (s_ui_mode == UI_MODE_DETAILS_BLE) {
            if (ev == BTN_EVENT_SINGLE) {
                if (s_details_total > 0)
                    s_details_page = (uint8_t)((s_details_page + 1) % s_details_total);
                render_ui_locked();
                ESP_LOGI(TAG, "DETAILS_BLE: one -> page %u/%u",
                         (unsigned)(s_details_page + 1), s_details_total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (s_advisor_mode == ADVISOR_MODE_LITE) {

                    uint16_t total = ble_filter_count();
                    if (total > 0) {
                        s_ble_index++;
                        if (s_ble_index > total) s_ble_index = 1;
                    }
                    s_details_page = 0;
                    render_ui_locked();
                    ESP_LOGI(TAG, "DETAILS_BLE(Lite): two -> next idx %u/%u",
                             s_ble_index, total);
                } else {

                    uint16_t total = ble_filter_count();
                    if (total > 0) {
                        s_ble_index++;
                        if (s_ble_index > total) s_ble_index = 1;
                    }
                    s_details_page = 0;
                    render_ui_locked();
                    ESP_LOGI(TAG, "DETAILS_BLE: two -> next idx %u/%u",
                             s_ble_index, total);
                }
            } else if (ev == BTN_EVENT_LONG) {

                s_details_page = 0;
                ui_activity_switch(&ble_list_activity, NULL);
                ESP_LOGI(TAG, "DETAILS_BLE: hold -> BLE_LIST idx %u", s_ble_index);
            }

        } else if (s_ui_mode == UI_MODE_BLE_CLASSES) {

            if (ev == BTN_EVENT_SINGLE) {
                s_ble_class_focus++;
                render_ui_locked();
                ESP_LOGI(TAG, "CLASSES: one -> focus %u", s_ble_class_focus);
            } else if (ev == BTN_EVENT_LONG) {
                s_results_pane = 1;
                ui_activity_switch(&options_activity, NULL);
                ESP_LOGI(TAG, "CLASSES: hold -> RESULTS");
            } else if (ev == BTN_EVENT_DOUBLE) {

                uint16_t counts[BLE_CLASS_ROW_COUNT];
                memset(counts, 0, sizeof(counts));
                uint16_t unknown_count = 0;
                for (uint16_t i = 0; i < s_ble.count; i++) {
                    if (s_ble.devices[i].suppressed) continue;
                    uint8_t c = ble_effective_class(&s_ble.devices[i]);
                    bool bucketed = false;
                    for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
                        if (s_ble_class_rows[b].class_id == c) {
                            counts[b]++; bucketed = true; break;
                        }
                    }
                    if (!bucketed) unknown_count++;
                }
                uint8_t visible_class[BLE_CLASS_ROW_COUNT + 1];
                uint8_t n_visible = 0;
                for (uint8_t b = 0; b < BLE_CLASS_ROW_COUNT; b++) {
                    if (counts[b] > 0) visible_class[n_visible++] = s_ble_class_rows[b].class_id;
                }
                if (unknown_count > 0) visible_class[n_visible++] = BLE_CLASS_FILTER_UNKNOWN;

                if (n_visible == 0) {
                    ESP_LOGI(TAG, "CLASSES: two -> no rows, staying");
                    render_ui_locked();
                } else {
                    uint8_t focus = s_ble_class_focus;
                    if (focus >= n_visible) focus = 0;
                    s_ble_class_filter   = visible_class[focus];
                    s_ble_explore_cursor = 0;
                    s_ui_mode            = UI_MODE_BLE_EXPLORE;
                    render_ui_locked();
                    ESP_LOGI(TAG, "CLASSES: two -> BLE_EXPLORE filter=0x%02X",
                             s_ble_class_filter);
                }
            }

        } else if (s_ui_mode == UI_MODE_PROBE_LOG) {

            if (ev == BTN_EVENT_SINGLE) {
                if (probe_req_log_entry_count() > 0) {
                    s_explore_panel  = EXP_PROBE;
                    s_explore_cursor = 0;
                    s_ui_mode        = UI_MODE_PROBE_EXPLORE;
                    render_ui_locked();
                    ESP_LOGI(TAG, "PROBE_LOG: one -> EXPLORE");
                } else {
                    ESP_LOGI(TAG, "PROBE_LOG: one -> no entries, staying");
                }
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_ui_mode = UI_MODE_SEQ_LINK;
                render_ui_locked();
                ESP_LOGI(TAG, "PROBE_LOG: two -> SEQ_LINK");
            } else if (ev == BTN_EVENT_LONG) {
                s_results_pane = 2;
                ui_activity_switch(&options_activity, NULL);
                ESP_LOGI(TAG, "PROBE_LOG: hold -> RESULTS");
            }

        } else if (s_ui_mode == UI_MODE_SEQ_LINK) {

            if (ev == BTN_EVENT_SINGLE) {
                if (seq_analyzer_entry_count() > 0) {
                    s_explore_panel  = EXP_SEQ;
                    s_explore_cursor = 0;
                    s_ui_mode        = UI_MODE_PROBE_EXPLORE;
                    render_ui_locked();
                    ESP_LOGI(TAG, "SEQ_LINK: one -> EXPLORE");
                } else {
                    ESP_LOGI(TAG, "SEQ_LINK: one -> no entries, staying");
                }
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_ui_mode = UI_MODE_IE_SIG;
                render_ui_locked();
                ESP_LOGI(TAG, "SEQ_LINK: two -> IE_SIG");
            } else if (ev == BTN_EVENT_LONG) {
                s_results_pane = 2;
                ui_activity_switch(&options_activity, NULL);
                ESP_LOGI(TAG, "SEQ_LINK: hold -> RESULTS");
            }

        } else if (s_ui_mode == UI_MODE_IE_SIG) {

            if (ev == BTN_EVENT_SINGLE) {
                if (ie_signature_entry_count() > 0) {
                    s_explore_panel  = EXP_IE;
                    s_explore_cursor = 0;
                    s_ui_mode        = UI_MODE_PROBE_EXPLORE;
                    render_ui_locked();
                    ESP_LOGI(TAG, "IE_SIG: one -> EXPLORE");
                } else {
                    ESP_LOGI(TAG, "IE_SIG: one -> no entries, staying");
                }
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_ui_mode = UI_MODE_ANQP_LEAK;
                render_ui_locked();
                ESP_LOGI(TAG, "IE_SIG: two -> ANQP_LEAK");
            } else if (ev == BTN_EVENT_LONG) {
                s_results_pane = 2;
                ui_activity_switch(&options_activity, NULL);
                ESP_LOGI(TAG, "IE_SIG: hold -> RESULTS");
            }

        } else if (s_ui_mode == UI_MODE_ANQP_LEAK) {

            if (ev == BTN_EVENT_SINGLE) {
                if (anqp_analyzer_entry_count() > 0) {
                    s_explore_panel  = EXP_ANQP;
                    s_explore_cursor = 0;
                    s_ui_mode        = UI_MODE_PROBE_EXPLORE;
                    render_ui_locked();
                    ESP_LOGI(TAG, "ANQP_LEAK: one -> EXPLORE");
                } else {
                    ESP_LOGI(TAG, "ANQP_LEAK: one -> no entries, staying");
                }
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_ui_mode = UI_MODE_PROBE_LOG;
                render_ui_locked();
                ESP_LOGI(TAG, "ANQP_LEAK: two -> PROBE_LOG (wrap)");
            } else if (ev == BTN_EVENT_LONG) {
                s_results_pane = 2;
                ui_activity_switch(&options_activity, NULL);
                ESP_LOGI(TAG, "ANQP_LEAK: hold -> RESULTS");
            }

        } else if (s_ui_mode == UI_MODE_PROBE_EXPLORE) {

            uint16_t total = explore_entry_count();
            if (ev == BTN_EVENT_SINGLE) {
                if (total > 0) s_explore_cursor = (uint16_t)((s_explore_cursor + 1) % total);
                render_ui_locked();
                ESP_LOGI(TAG, "EXPLORE: one -> cursor %u/%u",
                         (unsigned)s_explore_cursor, (unsigned)total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_dig_frame = 0;
                s_ui_mode   = UI_MODE_PROBE_DIG;
                render_ui_locked();
                ESP_LOGI(TAG, "EXPLORE: two -> DIG cursor=%u", (unsigned)s_explore_cursor);
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = explore_panel_counts_mode();
                render_ui_locked();
                ESP_LOGI(TAG, "EXPLORE: hold -> counts panel");
            }

        } else if (s_ui_mode == UI_MODE_PROBE_DIG) {

            uint16_t total = probe_dig_total();
            if (ev == BTN_EVENT_SINGLE) {
                if (total > 0) {
                    s_dig_frame++;
                    if (s_dig_frame >= total) s_dig_frame = 0;
                }
                render_ui_locked();
                ESP_LOGI(TAG, "DIG: one -> frame %u/%u",
                         (unsigned)s_dig_frame, (unsigned)total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (total > 0) s_dig_frame = (s_dig_frame == 0) ? (uint16_t)(total - 1)
                                                               : (uint16_t)(s_dig_frame - 1);
                render_ui_locked();
                ESP_LOGI(TAG, "DIG: two -> frame %u/%u",
                         (unsigned)s_dig_frame, (unsigned)total);
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_PROBE_EXPLORE;
                render_ui_locked();
                ESP_LOGI(TAG, "DIG: hold -> EXPLORE");
            }

        } else if (s_ui_mode == UI_MODE_BLE_EXPLORE) {

            uint16_t total = ble_filter_count();
            if (ev == BTN_EVENT_SINGLE) {
                if (total > 0) s_ble_explore_cursor = (uint16_t)((s_ble_explore_cursor + 1) % total);
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_EXPLORE: one -> cursor %u/%u",
                         (unsigned)s_ble_explore_cursor, (unsigned)total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                s_ble_dig_frame = 0;
                s_ui_mode       = UI_MODE_BLE_DIG;
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_EXPLORE: two -> DIG cursor=%u", (unsigned)s_ble_explore_cursor);
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_BLE_CLASSES;
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_EXPLORE: hold -> CLASSES");
            }

        } else if (s_ui_mode == UI_MODE_BLE_DIG) {

            uint16_t raw = ble_filter_at(s_ble_explore_cursor + 1);
            uint16_t total = (raw == 0xFFFF) ? 0
                             : ble_adv_ring_count_for_addr(s_ble.devices[raw].addr);
            if (ev == BTN_EVENT_SINGLE) {
                if (total > 0) {
                    s_ble_dig_frame++;
                    if (s_ble_dig_frame >= total) s_ble_dig_frame = 0;
                }
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_DIG: one -> frame %u/%u",
                         (unsigned)s_ble_dig_frame, (unsigned)total);
            } else if (ev == BTN_EVENT_DOUBLE) {
                if (total > 0) s_ble_dig_frame = (s_ble_dig_frame == 0) ? (uint16_t)(total - 1)
                                                                       : (uint16_t)(s_ble_dig_frame - 1);
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_DIG: two -> frame %u/%u",
                         (unsigned)s_ble_dig_frame, (unsigned)total);
            } else if (ev == BTN_EVENT_LONG) {
                s_ui_mode = UI_MODE_BLE_EXPLORE;
                render_ui_locked();
                ESP_LOGI(TAG, "BLE_DIG: hold -> BLE_EXPLORE");
            }
        }

        xSemaphoreGive(s_state_mutex);
    }
}

static TaskHandle_t s_scan_task_handle = NULL;

static void rescan_watchdog_task(void *arg)
{
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(200));
        if (s_force_rescan) {
            s_force_rescan = false;

            if (s_scan_task_handle && !download_mode_is_active())
                xTaskNotify(s_scan_task_handle, 0, eNoAction);
        }
    }
}

static void on_usb_cmd(const char *cmd, const char *args)
{
    static const char *CAP_DUMP_TAG = "CAP_DUMP";
    if (strcmp(cmd, "dumpring") == 0) {
        capture_ring_reader_t r;
        capture_ring_reader_open(&r);
        static char buf[4096];
        size_t emitted = 0;
        for (;;) {
            size_t n = capture_ring_reader_next(&r, buf, sizeof(buf));
            if (n == 0) break;
            ESP_LOGI(CAP_DUMP_TAG, "%s", buf);
            emitted++;
            if (emitted % 32 == 0) vTaskDelay(1);
        }
        ESP_LOGI(TAG, "dumpring: %u records emitted", (unsigned)emitted);
    } else if (strcmp(cmd, "footer") == 0) {
        capture_emit_footer(CAP_END_SHUTDOWN,
                            s_score_count, s_ble.count,
                            0, 0, 0, s_capture_scan_idx);
        ESP_LOGI(TAG, "footer emitted");
    } else if (strcmp(cmd, "selftest") == 0) {
        self_test_run(args);
    } else if (strcmp(cmd, "csi") == 0) {

        uint8_t  ch = 6;
        uint32_t secs = 3;
        if (args && args[0]) {
            char *end = NULL;
            unsigned long a = strtoul(args, &end, 10);
            if (a >= 1 && a <= 177) ch = (uint8_t)a;
            if (end && *end) {
                unsigned long b = strtoul(end, NULL, 10);
                if (b >= 1 && b <= 30) secs = (uint32_t)b;
            }
        }
        wifi_csi_probe_run(ch, secs * 1000);
    } else if (strcmp(cmd, "sta") == 0) {

        uint16_t n = sta_tracker_entry_count();
        ESP_LOGI(TAG, "STA dump: %u stations (%u cameras) from last scan",
                 (unsigned)n, (unsigned)sta_tracker_camera_count());
        for (uint16_t i = 0; i < n; i++) {
            const sta_entry_t *e = sta_tracker_at(i);
            if (!e) continue;
            ESP_LOGI(TAG,
                     "STA[%u] %02X:%02X:%02X:%02X:%02X:%02X vendor=%s cls=%u "
                     "frames=%u up=%u dn=%u rnd=%u cam=%u rssi=%d/%d ch=%u "
                     "bssid=%02X:%02X:%02X:%02X:%02X:%02X dur=%lums",
                     (unsigned)i,
                     e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
                     e->vendor ? e->vendor : "?", (unsigned)e->device_class,
                     (unsigned)e->frames, (unsigned)e->frames_uplink,
                     (unsigned)e->frames_downlink, e->randomized ? 1u : 0u,
                     e->is_camera ? 1u : 0u, (int)e->rssi_last, (int)e->rssi_best,
                     (unsigned)e->channel,
                     e->bssid[0], e->bssid[1], e->bssid[2],
                     e->bssid[3], e->bssid[4], e->bssid[5],
                     (unsigned long)(e->last_seen_ms - e->first_seen_ms));
        }
    } else if (strcmp(cmd, "1") == 0 || strcmp(cmd, "2") == 0 || strcmp(cmd, "3") == 0) {

        button_event_t ev = (cmd[0] == '1') ? BTN_EVENT_SINGLE :
                            (cmd[0] == '2') ? BTN_EVENT_DOUBLE : BTN_EVENT_LONG;
        if (s_injected_btn != BTN_EVENT_NONE)
            ESP_LOGW(TAG, "btn: previous injection not yet consumed, overwriting");
        s_injected_btn = ev;
        ESP_LOGI(TAG, "btn: injected %s",
                 ev == BTN_EVENT_SINGLE ? "click (1)" :
                 ev == BTN_EVENT_DOUBLE ? "double (2)" : "hold (3)");
    } else if (strcmp(cmd, "pup") == 0) {
        vp_status_t st;
        virtual_pup_get(&st);
        ESP_LOGI(TAG, "PUP avatar=%u L%u (%s) xp=%llu  +%llu/%llu to next",
                 (unsigned)st.avatar, (unsigned)st.level,
                 virtual_pup_title_label(st.title),
                 (unsigned long long)st.total_xp,
                 (unsigned long long)st.xp_into_level,
                 (unsigned long long)st.xp_for_level);
        ESP_LOGI(TAG, "PUP lifetime wifi=%u ble=%u born@boot=%u",
                 (unsigned)st.lifetime_wifi, (unsigned)st.lifetime_ble,
                 (unsigned)st.birth_boot);
        pup_trophy_dump();
    } else {
        ESP_LOGW(TAG, "usb cmd: unknown '%s'", cmd);
    }
}

static void sc_probe_chip_and_psram(void)
{
    esp_chip_info_t info = {0};
    esp_chip_info(&info);
    ESP_LOGW(TAG, "CHIP: model=%d cores=%d revision=v%d.%d features=0x%lx",
             (int)info.model, (int)info.cores,
             (int)(info.revision / 100), (int)(info.revision % 100),
             (unsigned long)info.features);
#if CONFIG_SPIRAM
    if (esp_psram_is_initialized()) {
        size_t psize = esp_psram_get_size();
        ESP_LOGW(TAG, "PSRAM: detected size=%u B (%u MB)",
                 (unsigned)psize, (unsigned)(psize / (1024 * 1024)));
        ESP_LOGW(TAG, "PSRAM: SPIRAM cap free=%u largest=%u",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
    } else {
        ESP_LOGW(TAG, "PSRAM: NOT detected — chip has no usable PSRAM");
    }
#else
    ESP_LOGW(TAG, "PSRAM: probe disabled (CONFIG_SPIRAM not set)");
#endif
}

void app_main(void)
{

    ESP_LOGI(TAG, "boot: reset_reason=%d", (int)esp_reset_reason());

    sc_probe_chip_and_psram();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    spi_bus_config_t bus = {
        .mosi_io_num     = PIN_MOSI,
        .miso_io_num     = PIN_MISO,
        .sclk_io_num     = PIN_SCK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = DISPLAY_W * DISPLAY_H * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI_HOST, &bus, SPI_DMA_CH_AUTO));

    led_state_preload();
    ESP_ERROR_CHECK(led_init(SPI_HOST));
    ESP_ERROR_CHECK(display_init(SPI_HOST));
    display_set_post_blit_cb(led_post_blit_guard);
    led_off();
    ESP_ERROR_CHECK(usb_console_init());

    settings_load();

    ESP_ERROR_CHECK(wifi_scanner_init());
    download_mode_init();
    ESP_ERROR_CHECK(ble_scanner_init());
    probe_req_log_init();
    seq_analyzer_init();
    ie_signature_init();
    anqp_analyzer_init();
    probe_frame_ring_init();
    ble_adv_ring_init();

    esp_err_t eui_err = eui_db_init();
    if (eui_err != ESP_OK)
        ESP_LOGW(TAG, "EUI DB unavailable — vendor lookup disabled");

    uint32_t boot_count = 0;
    {
        nvs_handle_t h;
        if (nvs_open(CFG_NS, NVS_READWRITE, &h) == ESP_OK) {
            nvs_get_u32(h, "boot_count", &boot_count);
            boot_count++;
            nvs_set_u32(h, "boot_count", boot_count);
            nvs_commit(h);
            nvs_close(h);
        }
    }
    s_boot_count = boot_count;
    virtual_pup_init(boot_count);
    virtual_pup_walk_init();
    pup_trophy_init();

    esp_err_t cap_err = capture_ring_init(4 * 1024 * 1024, 2 * 1024 * 1024);
    if (cap_err == ESP_OK) {
        capture_writer_init(boot_count);
        capture_emit_header();
        capture_emit_codebook();
    } else {
        ESP_LOGE(TAG, "capture_ring unavailable — JSONL export disabled");
    }
    if (pcap_capture_init() != ESP_OK)
        ESP_LOGW(TAG, "pcap buffer unavailable — packet scan disabled");
    usb_console_set_cmd_cb(on_usb_cmd);

    esp_log_level_set("wifi", ESP_LOG_WARN);

    s_state_mutex = xSemaphoreCreateMutex();
    configASSERT(s_state_mutex);

    boot_assert_led();

    for (int frame = 0; frame < 10; frame++) {
        display_logo_frame(frame);
        boot_assert_led();
        vTaskDelay(pdMS_TO_TICKS(420));
    }
    vTaskDelay(pdMS_TO_TICKS(2200));

    display_splash_credit();
    boot_assert_led();
    vTaskDelay(pdMS_TO_TICKS(2000));

    ESP_LOGI(TAG, "SniffCheck Advisor ready — scanning on boot");

    xTaskCreate(usb_console_task,    "sc_echo",    4096,  NULL, 3, NULL);
    xTaskCreate(button_task,         "sc_btn",     6144,  NULL, 4, NULL);
    xTaskCreate(rescan_watchdog_task,"sc_wdog",    1024,  NULL, 2, NULL);
    xTaskCreate(scan_anim_task,      "sc_anim",    3072,  NULL, 4, NULL);
    xTaskCreate(scan_task,           "sc_scan",    10240, NULL, 5,
                &s_scan_task_handle);

    xTaskCreate(capture_task,        "sc_capture", 6144,  NULL, 5,
                &s_capture_task_handle);

    {
        esp_timer_handle_t dl_tick;
        const esp_timer_create_args_t targs = {
            .callback = dl_tick_cb,
            .name     = "sc_dltick",
        };
        ESP_ERROR_CHECK(esp_timer_create(&targs, &dl_tick));
        ESP_ERROR_CHECK(esp_timer_start_periodic(dl_tick, 1000000));
    }

    for (;;) vTaskDelay(pdMS_TO_TICKS(10000));
}
