#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"
#include "qrcode.h"

#include "cluster_pins.h"
#include "cluster_proto.h"
#include "node_display.h"
#include "led.h"

#include <math.h>
#include "capture_ring.h"
#include "download_mode.h"
#include "download_http.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "pup_trophy.h"
#include "master_shim.h"
#include "cluster_web.h"

static const char *TAG = "cluster-master";

#define N_ARMS 2
static const struct { uint8_t addr; uint8_t index; const char *band; } ARMS[N_ARMS] = {
    { CL_ARM1_ADDR, 1, "2.4/BLE" },
    { CL_ARM2_ADDR, 2, "5G/BLE"  },
};

typedef struct {
    cl_status_t last;
    uint32_t    ok, polls;
    int64_t     last_ok_us;
    uint32_t    last_ingest_seq;
    bool        prev_online;
} arm_link_t;

static arm_link_t s_link[N_ARMS];
static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev[N_ARMS];

typedef enum { REQ_NONE = 0, REQ_SCAN, REQ_WALK, REQ_STOPWALK } arm_req_t;
static volatile arm_req_t s_req;
static bool s_walking;

static char   s_line[3400];
static size_t s_linelen;

static void led_blank_cb(void) { led_off(); }

void master_on_rescan_request(void)     { s_req = REQ_SCAN; ESP_LOGI(TAG, "WebAP: rescan"); }
void master_on_walk_request(bool start) { s_req = start ? REQ_WALK : REQ_STOPWALK;
                                          ESP_LOGI(TAG, "WebAP: walk %s", start ? "start" : "stop"); }

static void i2c_master_setup(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port          = CL_I2C_PORT,
        .sda_io_num        = CL_I2C_SDA_GPIO,
        .scl_io_num        = CL_I2C_SCL_GPIO,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &s_bus));
    for (int i = 0; i < N_ARMS; i++) {
        i2c_device_config_t dc = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address  = ARMS[i].addr,
            .scl_speed_hz    = CL_I2C_HZ,
        };
        ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &dc, &s_dev[i]));
    }
    ESP_LOGI(TAG, "I2C master up: arms 0x%02x/0x%02x", CL_ARM1_ADDR, CL_ARM2_ADDR);
}

static void arm_broadcast(cl_cmd_t cmd, uint8_t arg)
{
    cl_cmd_frame_t f; cl_cmd_build(&f, cmd, arg);
    for (int i = 0; i < N_ARMS; i++)
        i2c_master_transmit(s_dev[i], (const uint8_t *)&f, sizeof(f), 100);
}

static char s_stamped[3600];
static void ring_write_stamped(size_t len)
{
    double lat, lon; float acc; int64_t wall;
    bool have = cluster_web_gps(&lat, &lon, &acc, &wall);
    s_line[len] = '\0';
    bool meta = (len < 2 || s_line[0] != '{' ||
                 strstr(s_line, "\"type\":\"codebook\"") ||
                 strstr(s_line, "\"type\":\"header\"") ||
                 strstr(s_line, "\"type\":\"footer\""));
    if (!have || meta) { capture_ring_write(s_line, len); return; }

    char ins[112]; int m;
    if (isnan(lat))
        m = snprintf(ins, sizeof(ins), "\"ts_wall\":%lld,", (long long)wall);
    else
        m = snprintf(ins, sizeof(ins),
                     "\"ts_wall\":%lld,\"lat\":%.6f,\"lon\":%.6f,\"gps_acc\":%.1f,\"gps_src\":\"phone\",",
                     (long long)wall, lat, lon, acc);
    if (m <= 0 || (size_t)m + len + 1 > sizeof(s_stamped)) { capture_ring_write(s_line, len); return; }
    s_stamped[0] = '{';
    memcpy(s_stamped + 1, ins, m);
    memcpy(s_stamped + 1 + m, s_line + 1, len - 1);
    capture_ring_write(s_stamped, 1 + m + len - 1);
}

static void ingest_feed(const uint8_t *p, uint16_t n, uint32_t *recs)
{
    for (uint16_t k = 0; k < n; k++) {
        uint8_t b = p[k];
        if (b == '\n') {
            if (s_linelen > 0) { ring_write_stamped(s_linelen); (*recs)++; }
            s_linelen = 0;
        } else if (s_linelen < sizeof(s_line) - 1) {
            s_line[s_linelen++] = b;
        } else {
            s_linelen = 0;
        }
    }
}

static bool ingest_arm(int i, uint32_t seq)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = 0, recs = 0;
    s_linelen = 0;
    int64_t t0 = esp_timer_get_time();

    do {
        cl_getreq_t g; cl_getreq_build(&g, off);
        if (i2c_master_transmit(s_dev[i], (const uint8_t *)&g, sizeof(g), 100) != ESP_OK)
            return false;

        vTaskDelay(pdMS_TO_TICKS(2));
        if (i2c_master_receive(s_dev[i], (uint8_t *)&ch, sizeof(ch), 200) != ESP_OK)
            return false;
        if (!cl_chunk_valid(&ch) || ch.scan_seq != seq || ch.offset != off)
            return false;
        total = ch.total_len;
        ingest_feed(ch.payload, ch.len, &recs);
        off += ch.len;
        if (ch.len == 0) break;
    } while (off < total);

    if (s_linelen > 0) { ring_write_stamped(s_linelen); recs++; }
    ESP_LOGI(TAG, "ingest arm%d seq=%lu: %lu bytes, %lu recs, %lldms",
             ARMS[i].index, (unsigned long)seq, (unsigned long)off,
             (unsigned long)recs, (long long)(esp_timer_get_time() - t0) / 1000);
    return true;
}

static void poll_arm(int i)
{
    arm_link_t *L = &s_link[i];
    cl_status_t st;
    L->polls++;
    if (i2c_master_receive(s_dev[i], (uint8_t *)&st, sizeof(st), 100) == ESP_OK
        && cl_status_valid(&st)) {
        L->last = st; L->ok++; L->last_ok_us = esp_timer_get_time();

        if (st.scanset_ready && st.scanset_len > 0 && st.scan_seq != L->last_ingest_seq) {
            if (ingest_arm(i, st.scan_seq)) L->last_ingest_seq = st.scan_seq;
        }
    }
}

#define QR_BOX_PX 72
#define QR_X0 4
#define QR_Y0 4
#define RCOL  80

static int s_qr_box = QR_BOX_PX;

static void qr_draw_cb(esp_qrcode_handle_t qr)
{
    int size  = esp_qrcode_get_size(qr);
    int border = 2, total = size + 2 * border;
    int scale = s_qr_box / total; if (scale < 1) scale = 1;
    int px = total * scale;
    display_fill_rect(QR_X0, QR_Y0, px, px, COLOR_WHITE);
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (esp_qrcode_get_module(qr, x, y))
                display_fill_rect(QR_X0 + (border + x) * scale,
                                  QR_Y0 + (border + y) * scale, scale, scale, COLOR_BLACK);
}

static void draw_arm_line(int i)
{
    bool fresh = s_link[i].prev_online;
    char line[24];
    display_fill_rect(RCOL, 38 + i * 10, DISPLAY_W - RCOL, 9, COLOR_NEARBLACK);
    snprintf(line, sizeof(line), "A%d %s %s", ARMS[i].index, ARMS[i].band,
             fresh ? "OK" : "--");
    display_draw_string(RCOL, 38 + i * 10, line, fresh ? COLOR_GREEN : COLOR_RED,
                        COLOR_NEARBLACK, 1);
}

static void draw_join_screen(bool joined)
{
    display_clear(COLOR_NEARBLACK);
    const char *ssid = download_mode_get_ssid();
    const char *pass = download_mode_get_passphrase();

    char payload[80];
    if (joined) snprintf(payload, sizeof(payload), "http://192.168.4.1/");
    else        snprintf(payload, sizeof(payload), "WIFI:T:WPA2;S:%s;P:%s;;", ssid, pass);
    s_qr_box = QR_BOX_PX;
    esp_qrcode_config_t qcfg = ESP_QRCODE_CONFIG_DEFAULT();
    qcfg.display_func       = qr_draw_cb;
    qcfg.max_qrcode_version = 4;
    qcfg.qrcode_ecc_level   = ESP_QRCODE_ECC_LOW;
    if (esp_qrcode_generate(&qcfg, payload) != ESP_OK)
        display_draw_string(QR_X0, 34, "QR err", COLOR_RED, COLOR_NEARBLACK, 1);

    display_draw_string(RCOL, 4, "DOG PARK", COLOR_HEADER, COLOR_NEARBLACK, 1);
    if (joined) {
        display_draw_string(RCOL, 15, "scan to open", COLOR_WHITE, COLOR_NEARBLACK, 1);
        display_draw_string(RCOL, 26, "192.168.4.1", COLOR_AMBER, COLOR_NEARBLACK, 1);
    } else {
        display_draw_string(RCOL, 15, ssid, COLOR_WHITE, COLOR_NEARBLACK, 1);
        display_draw_string(RCOL, 26, pass, COLOR_AMBER, COLOR_NEARBLACK, 1);
    }
    for (int i = 0; i < N_ARMS; i++) draw_arm_line(i);
}

void master_cluster_log_json(char *buf, size_t buflen)
{
    snprintf(buf, buflen, "{\"log\":[]}");
}

void master_cluster_sentinel_json(char *buf, size_t buflen)
{
    snprintf(buf, buflen, "{\"mask\":0,\"total\":0,\"recent\":0,\"seq\":0,\"cats\":[],\"byoi\":[],\"last\":null}");
}
void master_on_sentinel_cfg(const char *body, int len) { (void)body; (void)len; }

void master_on_epup_label(const char *label) { (void)label; }

void master_cluster_places_json(char *buf, size_t buflen) { snprintf(buf, buflen, "{\"cur\":-1,\"places\":[]}"); }
void master_cluster_hits_json(char *buf, size_t buflen)   { snprintf(buf, buflen, "{\"base\":0,\"hits\":[]}"); }
void master_on_place_label(const char *body, int len)     { (void)body; (void)len; }
void master_on_settime(uint32_t epoch)                    { (void)epoch; }
void master_on_brain_reset(void)                          { }

void master_cluster_status_json(char *buf, size_t buflen)
{
    int64_t now = esp_timer_get_time();
    capture_ring_stats_t rs; capture_ring_get_stats(&rs);
    int off = snprintf(buf, buflen, "{\"arms\":[");
    for (int i = 0; i < N_ARMS && off > 0 && off < (int)buflen; i++) {
        bool fresh = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
        off += snprintf(buf + off, buflen - off,
            "%s{\"i\":%u,\"band\":\"%s\",\"online\":%s,\"state\":%u,\"wifi\":%u,\"ble\":%u,\"seq\":%lu}",
            i ? "," : "", ARMS[i].index, ARMS[i].band, fresh ? "true" : "false",
            s_link[i].last.state, s_link[i].last.wifi_seen, s_link[i].last.ble_seen,
            (unsigned long)s_link[i].last_ingest_seq);
    }
    snprintf(buf + off, buflen - off, "],\"walking\":%s,\"recs\":%u}",
             s_walking ? "true" : "false", (unsigned)rs.records_current);
}

static void master_task(void *arg)
{
    (void)arg;

    for (int f = 0; f < 10; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(160)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(1200));

    int screen = 0;
    bool joined = false, cluster_web_up = false;
    int64_t last_log = 0;

    for (;;) {
        for (int i = 0; i < N_ARMS; i++) poll_arm(i);

        if (!cluster_web_up) {
            httpd_handle_t sv = download_http_server();
            if (sv && cluster_web_start(sv) == ESP_OK) cluster_web_up = true;
        }

        arm_req_t req = s_req; s_req = REQ_NONE;
        if (req == REQ_WALK)          { arm_broadcast(CL_CMD_WALK, 1); s_walking = true; }
        else if (req == REQ_STOPWALK) { arm_broadcast(CL_CMD_WALK, 0); s_walking = false; }
        else if (req == REQ_SCAN) {
            if (s_walking) { arm_broadcast(CL_CMD_WALK, 0); s_walking = false; }
            arm_broadcast(CL_CMD_SCAN, CL_SCAN_ADV);
        }

        if (!download_mode_is_active())
            download_mode_request_enable();

        int64_t now = esp_timer_get_time();

        if (!download_mode_is_active()) {
            if (screen != 1) {
                display_clear(COLOR_NEARBLACK);
                display_draw_string(2, 34, "Starting AP...", COLOR_AMBER, COLOR_NEARBLACK, 1);
                screen = 1;
            }
        } else {
            bool now_joined = download_mode_get_client_count() > 0;
            if (screen != 2 || now_joined != joined) {
                joined = now_joined;
                draw_join_screen(joined); screen = 2;
                for (int i = 0; i < N_ARMS; i++) s_link[i].prev_online = false;
            }

            for (int i = 0; i < N_ARMS; i++) {
                bool fresh = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
                if (fresh != s_link[i].prev_online) {
                    s_link[i].prev_online = fresh;
                    draw_arm_line(i);
                }
            }
        }

        if (now - last_log >= 2000000LL) {
            last_log = now;
            capture_ring_stats_t rs; capture_ring_get_stats(&rs);
            ESP_LOGI(TAG, "arms:1=%s(seq%lu) 2=%s(seq%lu) | WebAP %s | ring recs=%u walking=%d",
                     s_link[0].ok && (now-s_link[0].last_ok_us)<1500000LL ? "OK":"--",
                     (unsigned long)s_link[0].last_ingest_seq,
                     s_link[1].ok && (now-s_link[1].last_ok_us)<1500000LL ? "OK":"--",
                     (unsigned long)s_link[1].last_ingest_seq,
                     download_mode_is_active() ? "up" : "starting",
                     (unsigned)rs.records_current, (int)s_walking);
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "SniffCheck Cluster MASTER boot");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    spi_bus_config_t bus = {
        .mosi_io_num   = CL_LCD_MOSI, .miso_io_num = CL_LCD_MISO, .sclk_io_num = CL_LCD_SCK,
        .quadwp_io_num = -1, .quadhd_io_num = -1,
        .max_transfer_sz = DISPLAY_W * DISPLAY_H * (int)sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CL_LCD_SPI_HOST, &bus, SPI_DMA_CH_AUTO));
    ESP_ERROR_CHECK(led_init(CL_LCD_SPI_HOST));
    ESP_ERROR_CHECK(display_init(CL_LCD_SPI_HOST));
    display_set_post_blit_cb(led_blank_cb);
    led_off();

    master_shim_set_session("dogpark-0001", "dogpark-0.4");
    ESP_ERROR_CHECK(capture_ring_init(4 * 1024 * 1024, 2 * 1024 * 1024));
    virtual_pup_init(1);
    virtual_pup_walk_init();
    pup_trophy_init();

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_country_t country = { .cc = "US", .schan = 1, .nchan = 11,
                               .policy = WIFI_COUNTRY_POLICY_MANUAL };
    esp_wifi_set_country(&country);
    download_mode_init();

    const char *seed =
        "{\"type\":\"info\",\"src\":\"cluster-master\",\"msg\":\"cluster head online\"}";
    capture_ring_write(seed, strlen(seed));

    i2c_master_setup();
    xTaskCreate(master_task, "master", 6144, NULL, 5, NULL);
}
