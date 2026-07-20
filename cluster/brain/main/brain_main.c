#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"

#include "cluster_pins.h"
#include "cluster_proto.h"
#include "node_display.h"
#include "led.h"
#include "qrcode.h"
#include "epup_brain.h"

#include "capture_ring.h"
#include "download_mode.h"
#include "download_http.h"
#include "master_shim.h"
#include "cluster_web.h"
#include "sentinel.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "pup_trophy.h"

#define FW_CKPT "brain-1.0"

#define BRAIN_I2C_HZ  1000000

static const char *TAG = "cluster-brain";

#define N_ARMS 2
static const struct { uint8_t addr; uint8_t index; const char *band; } ARMS[N_ARMS] = {
    { CL_ARM1_ADDR, 1, "2.4+5 A/BLE" },
    { CL_ARM2_ADDR, 2, "2.4+5 B/BLE" },
};

#define BRAIN_PLAN_DWELL_LITE   80
#define BRAIN_PLAN_DWELL_ADV    160
#define BRAIN_PLAN_BLE_EVERY_N  4

typedef struct {
    cl_status_t last;
    uint32_t    ok, polls;
    int64_t     last_ok_us;
    uint32_t    last_ingest_seq;
    bool        planned;
} arm_link_t;

static arm_link_t s_link[N_ARMS];
static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev[N_ARMS];

static i2c_master_dev_handle_t s_s3_dev;
static uint32_t s_s3_pushes, s_s3_fail;
static uint32_t s_bus_resets;

#define BRAIN_ARM_CAP   (64 * 1024)
#define BRAIN_MERGE_CAP (96 * 1024)
#define MERGE_MAX_KEYS  4096

typedef struct {
    uint8_t  *buf;
    uint32_t  len, recs;
    bool      have;
} arm_slot_t;
static arm_slot_t s_arm[2];

static uint8_t  *s_merge_buf;
static uint32_t  s_merge_len, s_merge_uniq, s_merge_dup, s_merge_count;
static uint64_t  s_keys[MERGE_MAX_KEYS];
static int       s_nkeys;

#define CL_CHUNK_SETTLE_US  300

static void led_blank_cb(void) { led_off(); }
static void render_screen(const char *state_txt);
static void draw_join_screen(bool joined);

static uint64_t fnv1a(const char *s, int n)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}

static int find_str(const char *s, int n, const char *pat, char *out, int outsz)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) {
        if (memcmp(s + i, pat, pl) == 0) {
            int k = i + pl, o = 0;
            while (k < n && s[k] != '"' && o < outsz - 1) out[o++] = s[k++];
            out[o] = '\0';
            return o;
        }
    }
    return 0;
}

static int line_key(const char *line, int n, char *kb, int kbsz)
{
    char type[24], id[40];
    if (!find_str(line, n, "\"type\":\"", type, sizeof type)) return 0;
    if (!find_str(line, n, "\"bssid\":\"", id, sizeof id) &&
        !find_str(line, n, "\"addr\":\"",  id, sizeof id)) return 0;
    int o = snprintf(kb, kbsz, "%s|%s", type, id);
    return o < kbsz ? o : kbsz - 1;
}

static bool key_seen(uint64_t h)
{
    for (int i = 0; i < s_nkeys; i++) if (s_keys[i] == h) return true;
    return false;
}

static void do_merge(void)
{
    s_nkeys = 0;
    uint32_t out = 0, uniq = 0, dup = 0;
    for (int ai = 0; ai < 2; ai++) {
        const char *b = (const char *)s_arm[ai].buf;
        uint32_t n = s_arm[ai].len, i = 0;
        while (i < n) {
            uint32_t j = i;
            while (j < n && b[j] != '\n') j++;
            uint32_t linelen = j - i;
            if (linelen > 0) {
                char key[72];
                int kl = line_key(b + i, (int)linelen, key, sizeof key);
                if (kl > 0) {
                    uint64_t h = fnv1a(key, kl);
                    if (key_seen(h)) {
                        dup++;
                    } else {
                        if (s_nkeys < MERGE_MAX_KEYS) s_keys[s_nkeys++] = h;
                        uniq++;
                        if (s_merge_buf && out + linelen + 1 <= BRAIN_MERGE_CAP) {
                            memcpy(s_merge_buf + out, b + i, linelen);
                            out += linelen;
                            s_merge_buf[out++] = '\n';
                        }
                    }
                }
            }
            i = j + 1;
        }
    }
    s_merge_len  = out;
    s_merge_uniq = uniq;
    s_merge_dup  = dup;
    s_merge_count++;
}

static void ring_feed_scanset(const uint8_t *buf, uint32_t len)
{
    uint32_t i = 0;
    while (i < len) {
        uint32_t j = i;
        while (j < len && buf[j] != '\n') j++;
        if (j > i) capture_ring_write((const char *)(buf + i), j - i);
        i = j + 1;
    }
}

#define ALOG_N   48
#define ALOG_LEN 72
typedef struct { int64_t us; char text[ALOG_LEN]; } alog_entry_t;
static alog_entry_t      s_alog[ALOG_N];
static volatile uint32_t s_alog_head, s_alog_count;
static portMUX_TYPE      s_alog_mux = portMUX_INITIALIZER_UNLOCKED;

static void alog(const char *fmt, ...)
{
    char tmp[ALOG_LEN];
    va_list ap; va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    for (char *p = tmp; *p; p++) if (*p == '"' || *p == '\\') *p = '\'';
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_alog_mux);
    uint32_t i = s_alog_head;
    s_alog[i].us = now;
    strlcpy(s_alog[i].text, tmp, ALOG_LEN);
    s_alog_head = (i + 1) % ALOG_N;
    if (s_alog_count < ALOG_N) s_alog_count++;
    portEXIT_CRITICAL(&s_alog_mux);
    ESP_LOGI(TAG, "alog: %s", tmp);
}

void master_cluster_log_json(char *buf, size_t buflen)
{
    portENTER_CRITICAL(&s_alog_mux);
    uint32_t n = s_alog_count, head = s_alog_head;
    portEXIT_CRITICAL(&s_alog_mux);
    int off = snprintf(buf, buflen, "{\"log\":[");
    for (uint32_t k = 0; k < n && off > 0 && off < (int)buflen; k++) {
        uint32_t idx = (head + ALOG_N - 1 - k) % ALOG_N;
        off += snprintf(buf + off, buflen - off, "%s{\"t\":%lld,\"s\":\"%s\"}",
                        k ? "," : "", (long long)(s_alog[idx].us / 1000000),
                        s_alog[idx].text);
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

static struct { bool online; uint32_t recs, flagged, windows; int64_t last_ok_us; } s_s3;

static char *s_sent_json;   static int s_sent_json_len;
static char *s_hits_json;   static int s_hits_json_len;
static SemaphoreHandle_t s_s3_mux;

static char             s_cfg_pending[512];
static volatile int     s_cfg_pending_len;
static volatile bool    s_cfg_req;
static volatile uint32_t s_clock_pending;
static volatile bool    s_clock_req;

static void poll_s3(void)
{
    cl_getreq_t g; cl_getreq_build_cmd(&g, CL_CMD_STATUS_SEL, 0);
    if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100) != ESP_OK) return;
    esp_rom_delay_us(CL_CHUNK_SETTLE_US);
    cl_status_t st;
    if (i2c_master_receive(s_s3_dev, (uint8_t *)&st, sizeof(st), 100) == ESP_OK
        && cl_status_valid(&st) && st.arm_index == CL_S3_ADDR) {
        s_s3.online   = true;
        s_s3.recs     = st.scanset_len;
        s_s3.flagged  = st.wifi_seen;
        s_s3.windows  = st.scan_seq;
        s_s3.last_ok_us = esp_timer_get_time();
    }
}

static int fetch_s3_blob(uint8_t cmd, char *dst, int cap)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = 0;
    for (;;) {
        cl_getreq_t g; cl_getreq_build_cmd(&g, cmd, off);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100) != ESP_OK) return -1;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        if (i2c_master_receive(s_s3_dev, (uint8_t *)&ch, sizeof(ch), 200) != ESP_OK) return -1;
        if (!cl_chunk_valid(&ch) || ch.offset != off) return -1;
        total = ch.total_len;
        if (ch.len && (int)(off + ch.len) < cap) memcpy(dst + off, ch.payload, ch.len);
        off += ch.len;
        if (ch.len == 0 || off >= total) break;
    }
    if ((int)off >= cap) off = cap - 1;
    dst[off] = '\0';
    return (int)off;
}

static void refresh_s3_blobs(void)
{
    static char tmp[6144];
    if (!s_sent_json || !s_hits_json) return;
    int n = fetch_s3_blob(CL_CMD_GET_SENT, tmp, sizeof tmp);
    if (n > 0 && xSemaphoreTake(s_s3_mux, portMAX_DELAY) == pdTRUE) {
        memcpy(s_sent_json, tmp, n + 1); s_sent_json_len = n; xSemaphoreGive(s_s3_mux);
    }
    n = fetch_s3_blob(CL_CMD_GET_HITS, tmp, sizeof tmp);
    if (n > 0 && xSemaphoreTake(s_s3_mux, portMAX_DELAY) == pdTRUE) {
        memcpy(s_hits_json, tmp, n + 1); s_hits_json_len = n; xSemaphoreGive(s_s3_mux);
    }
}

static void push_sentcfg_to_s3(const char *body, int n)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = (uint32_t)n;
    for (;;) {
        memset(&ch, 0, sizeof ch);
        ch.type = CL_PUT_SENTCFG; ch.scan_seq = 0; ch.total_len = total; ch.offset = off;
        uint16_t len = 0;
        if (off < total) {
            uint32_t rem = total - off;
            len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
            memcpy(ch.payload, body + off, len);
        }
        ch.len = len; cl_chunk_seal(&ch);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&ch, sizeof(ch), 100) != ESP_OK) break;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        off += len;
        if (len == 0) break;
    }
}

static void push_clock_to_s3(uint32_t epoch)
{
    cl_getreq_t g; cl_getreq_build_cmd(&g, CL_CMD_SET_CLOCK, epoch);
    i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100);
}

typedef enum { REQ_NONE = 0, REQ_SCAN, REQ_WALK, REQ_STOPWALK } req_t;
static volatile req_t s_req;
static bool s_walking;
static bool s_boot_scanned;
static bool s_rescan_once;
static volatile bool s_reset_req;
static volatile uint32_t s_epoch_base;

static int json_field(const char *b, int n, const char *pat, char *out, int outsz)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) if (memcmp(b + i, pat, pl) == 0) {
        int k = i + pl, o = 0;
        while (k < n && b[k] != '"' && o < outsz - 1) out[o++] = b[k++];
        out[o] = '\0'; return o;
    }
    return 0;
}
static long json_int(const char *b, int n, const char *key, long dflt)
{
    char pat[24]; snprintf(pat, sizeof pat, "\"%s\":", key);
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) if (memcmp(b + i, pat, pl) == 0)
        return strtol(b + i + pl, NULL, 10);
    return dflt;
}

void master_on_rescan_request(void)     { s_req = REQ_SCAN;  alog("scan started (WebAP)"); }
void master_on_walk_request(bool start) { s_req = start ? REQ_WALK : REQ_STOPWALK;
                                          alog("walk %s (WebAP)", start ? "started" : "stopped"); }

void master_on_epup_label(const char *label) { epup_brain_place_label(-1, label); alog("ePup place named"); }
void master_on_place_label(const char *body, int n)
{
    long idx = json_int(body, n, "idx", -1);
    char label[48] = {0};
    json_field(body, n, "\"label\":\"", label, sizeof label);
    if (idx < 0 || idx >= CL_PLACE_MAX) return;
    epup_brain_place_label((int)idx, label);
    alog("environment renamed");
}

void master_on_brain_reset(void) { s_reset_req = true; alog("brain HARD RESET requested"); }

void master_on_settime(uint32_t epoch)
{
    if (epoch < 1700000000UL) return;
    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);
    s_epoch_base = epoch - up;
    s_clock_pending = epoch; s_clock_req = true;
}

void master_on_sentinel_cfg(const char *body, int n)
{
    if (n <= 0 || n >= (int)sizeof(s_cfg_pending)) return;
    memcpy(s_cfg_pending, body, n);
    s_cfg_pending[n] = '\0';
    s_cfg_pending_len = n;
    s_cfg_req = true;
    alog("sentinel config updated");
}

void master_cluster_sentinel_json(char *buf, size_t buflen)
{
    bool served = false;
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_sent_json_len > 0 && s_sent_json_len < (int)buflen) {
            memcpy(buf, s_sent_json, s_sent_json_len + 1);
            served = true;
        }
        xSemaphoreGive(s_s3_mux);
    }
    if (!served)
        snprintf(buf, buflen, "{\"armed\":false,\"mask\":0,\"total\":0,\"recent\":0,\"seq\":0,"
                              "\"cats\":[],\"byoi\":[],\"last\":{\"label\":\"\",\"mac\":\"\"}}");
}

void master_cluster_hits_json(char *buf, size_t buflen)
{
    bool served = false;
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_hits_json_len > 0 && s_hits_json_len < (int)buflen) {
            memcpy(buf, s_hits_json, s_hits_json_len + 1);
            served = true;
        }
        xSemaphoreGive(s_s3_mux);
    }
    if (!served)
        snprintf(buf, buflen, "{\"base\":%lu,\"hits\":[]}", (unsigned long)s_epoch_base);
}

void master_cluster_places_json(char *buf, size_t buflen)
{
    cl_places_t pl; epup_brain_places(&pl);
    if (!cl_places_valid(&pl)) { snprintf(buf, buflen, "{\"cur\":-1,\"places\":[]}"); return; }
    int off = snprintf(buf, buflen, "{\"cur\":%d,\"places\":[", pl.cur);
    for (int i = 0; i < pl.count && off > 0 && off < (int)buflen; i++) {
        const cl_place_entry_t *e = &pl.entries[i];
        char lbl[16]; strlcpy(lbl, e->label, sizeof lbl);
        off += snprintf(buf + off, buflen - off,
            "%s{\"idx\":%u,\"label\":\"%s\",\"scans\":%lu,\"landmarks\":%u,\"known\":%s,\"current\":%s}",
            i ? "," : "", e->idx, lbl, (unsigned long)e->scans, e->landmarks,
            (e->flags & CL_PLACE_F_KNOWN)   ? "true" : "false",
            (e->flags & CL_PLACE_F_CURRENT) ? "true" : "false");
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

void master_cluster_status_json(char *buf, size_t buflen)
{
    int64_t now = esp_timer_get_time();
    capture_ring_stats_t rs; capture_ring_get_stats(&rs);
    int off = snprintf(buf, buflen, "{\"arms\":[");
    for (int i = 0; i < N_ARMS && off > 0 && off < (int)buflen; i++) {
        bool fresh = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
        long age_ms = s_link[i].ok ? (long)((now - s_link[i].last_ok_us) / 1000) : -1;
        off += snprintf(buf + off, buflen - off,
            "%s{\"i\":%u,\"band\":\"%s\",\"online\":%s,\"state\":%u,\"wifi\":%u,\"ble\":%u,\"seq\":%lu,"
            "\"age_ms\":%ld,\"ok\":%lu,\"polls\":%lu,\"planned\":%s}",
            i ? "," : "", ARMS[i].index, ARMS[i].band, fresh ? "true" : "false",
            s_link[i].last.state, s_link[i].last.wifi_seen, s_link[i].last.ble_seen,
            (unsigned long)s_link[i].last_ingest_seq,
            age_ms, (unsigned long)s_link[i].ok, (unsigned long)s_link[i].polls,
            s_link[i].planned ? "true" : "false");
    }
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    off += snprintf(buf + off, buflen - off,
                    "],\"brain\":{\"addr\":%u,\"online\":true,\"age_ms\":0,\"ok\":%lu,\"polls\":%lu},"
                    "\"walking\":%s,\"recs\":%u,\"ckpt\":\"%s\"",
                    CL_BRAIN_ADDR, (unsigned long)s_merge_count, (unsigned long)s_merge_count,
                    s_walking ? "true" : "false", (unsigned)rs.records_current, FW_CKPT);
    epup_summary_t ep; epup_brain_get(&ep);
    if (off > 0 && off < (int)buflen) {
        off += snprintf(buf + off, buflen - off,
            ",\"epup\":{\"title\":\"%s\",\"level\":%lu,\"confidence\":%u,\"scans\":%lu,"
            "\"unique\":%lu,\"wifi\":%u,\"ble\":%u,\"new\":%u,\"ema\":%u,\"boots\":%lu,"
            "\"place\":{\"cur\":%d,\"count\":%u,\"sim\":%u,\"known\":%s,\"is_new\":%s,"
            "\"scans\":%lu,\"label\":\"%s\"}}",
            epup_title_label((epup_title_t)ep.title), (unsigned long)ep.level,
            ep.confidence, (unsigned long)ep.total_scans,
            (unsigned long)ep.unique_est, ep.last_wifi, ep.last_ble,
            ep.last_new, ep.ema_total,
            (unsigned long)(ep.boot_now >= ep.born_boot ? ep.boot_now - ep.born_boot + 1 : 1),
            ep.place_cur, ep.place_count, ep.place_sim,
            (ep.place_flags & EPUP_PLACE_KNOWN) ? "true" : "false",
            (ep.place_flags & EPUP_PLACE_NEW) ? "true" : "false",
            (unsigned long)ep.place_scans, ep.place_label);
    }
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    bool s3on = s_s3.online && (now - s_s3.last_ok_us) < 3000000LL;
    off += snprintf(buf + off, buflen - off,
             ",\"sd\":{\"ok\":%s,\"full\":false,\"gb\":0.0,\"free_gb\":0.0,\"recs\":%u,\"kb\":0}",
             s3on ? "true" : "false", (unsigned)s_s3.recs);
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    snprintf(buf + off, buflen - off,
             ",\"health\":{\"up\":%lld,\"heap\":%u,\"merges\":%lu,\"s3push\":%lu,\"s3fail\":%lu,"
             "\"busrst\":%lu,\"s3\":{\"online\":%s,\"up\":%lld,\"recs\":%lu,\"flagged\":%lu,\"windows\":%lu}}}",
             (long long)(now / 1000000), (unsigned)esp_get_free_heap_size(),
             (unsigned long)s_merge_count, (unsigned long)s_s3_pushes, (unsigned long)s_s3_fail,
             (unsigned long)s_bus_resets, s3on ? "true" : "false",
             (long long)(s3on ? (now - s_s3.last_ok_us) / 1000000 : -1),
             (unsigned long)s_s3.recs, (unsigned long)s_s3.flagged, (unsigned long)s_s3.windows);
}

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
            .scl_speed_hz    = BRAIN_I2C_HZ,
        };
        ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &dc, &s_dev[i]));
    }
    i2c_device_config_t s3c = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = CL_S3_ADDR,
        .scl_speed_hz    = BRAIN_I2C_HZ,
    };
    ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &s3c, &s_s3_dev));
    ESP_LOGI(TAG, "I2C master up: SDA=%d SCL=%d @%luHz arms 0x%02x/0x%02x S3 0x%02x",
             CL_I2C_SDA_GPIO, CL_I2C_SCL_GPIO, (unsigned long)BRAIN_I2C_HZ,
             CL_ARM1_ADDR, CL_ARM2_ADDR, CL_S3_ADDR);
}

static void push_merge_to_s3(void)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = s_merge_len;
    bool ok = true;

    for (;;) {
        memset(&ch, 0, sizeof(ch));
        ch.type      = CL_PUT_S3MERGE;
        ch.scan_seq  = s_merge_count;
        ch.total_len = total;
        ch.offset    = off;
        uint16_t len = 0;
        if (s_merge_buf && off < total) {
            uint32_t rem = total - off;
            len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
            memcpy(ch.payload, s_merge_buf + off, len);
        }
        ch.len = len;
        cl_chunk_seal(&ch);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&ch, sizeof(ch), 100) != ESP_OK) {
            ok = false; break;
        }
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        off += len;
        if (len == 0) break;
    }
    if (ok) s_s3_pushes++; else s_s3_fail++;
}

static void arm_broadcast(cl_cmd_t cmd, uint8_t arg)
{
    cl_cmd_frame_t f; cl_cmd_build(&f, cmd, arg);
    for (int i = 0; i < N_ARMS; i++)
        i2c_master_transmit(s_dev[i], (const uint8_t *)&f, sizeof(f), 100);
}

static bool send_plan(int i)
{
    cl_plan_t p = {
        .n_arms       = N_ARMS,
        .arm_slot     = (uint8_t)i,
        .dwell_ms     = BRAIN_PLAN_DWELL_LITE,
        .dwell_adv_ms = BRAIN_PLAN_DWELL_ADV,
        .ble_every_n  = BRAIN_PLAN_BLE_EVERY_N,
        .flags        = CL_PLAN_FLAG_DFS,
    };
    cl_plan_seal(&p);
    bool ok = i2c_master_transmit(s_dev[i], (const uint8_t *)&p, sizeof(p), 100) == ESP_OK;
    ESP_LOGI(TAG, "SET_PLAN -> arm%d: slot %d/%d dwell %d/%d ble_n=%d %s",
             ARMS[i].index, i, N_ARMS, BRAIN_PLAN_DWELL_LITE, BRAIN_PLAN_DWELL_ADV,
             BRAIN_PLAN_BLE_EVERY_N, ok ? "ok" : "FAIL");
    return ok;
}

static bool ingest_arm(int i, uint32_t seq)
{
    static cl_chunk_t ch;
    arm_slot_t *a = &s_arm[i];
    uint32_t off = 0, total = 0;
    int64_t t0 = esp_timer_get_time();

    do {
        cl_getreq_t g; cl_getreq_build(&g, off);
        if (i2c_master_transmit(s_dev[i], (const uint8_t *)&g, sizeof(g), 100) != ESP_OK)
            return false;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        if (i2c_master_receive(s_dev[i], (uint8_t *)&ch, sizeof(ch), 200) != ESP_OK)
            return false;
        if (!cl_chunk_valid(&ch) || ch.scan_seq != seq || ch.offset != off)
            return false;
        total = ch.total_len;
        if (ch.len && a->buf && (uint32_t)off + ch.len <= BRAIN_ARM_CAP)
            memcpy(a->buf + off, ch.payload, ch.len);
        off += ch.len;
        if (ch.len == 0) break;
    } while (off < total);

    uint32_t recs = 0;
    for (uint32_t k = 0; k < off; k++) if (a->buf[k] == '\n') recs++;
    a->len  = off;
    a->recs = recs;
    a->have = true;

    ring_feed_scanset(a->buf, off);
    ESP_LOGI(TAG, "ingest arm%d seq=%lu: %lu bytes, %lu recs, %lldms",
             ARMS[i].index, (unsigned long)seq, (unsigned long)off,
             (unsigned long)recs, (long long)(esp_timer_get_time() - t0) / 1000);
    return true;
}

static void merge_window(void)
{
    do_merge();
    ESP_LOGI(TAG, "MERGE #%lu: %lu uniq, %lu dup, %lu bytes (arm1=%lu arm2=%lu recs)",
             (unsigned long)s_merge_count, (unsigned long)s_merge_uniq,
             (unsigned long)s_merge_dup, (unsigned long)s_merge_len,
             (unsigned long)s_arm[0].recs, (unsigned long)s_arm[1].recs);
    epup_brain_observe((const char *)s_merge_buf, s_merge_len);

    push_merge_to_s3();

    epup_summary_t ep; epup_brain_get(&ep);
    char st[24];
    snprintf(st, sizeof(st), "%s L%lu %lu%%",
             epup_title_label((epup_title_t)ep.title),
             (unsigned long)ep.level, (unsigned long)ep.confidence);
    render_screen(st);

    s_arm[0].have = s_arm[1].have = false;
}

static void poll_arm(int i)
{
    arm_link_t *L = &s_link[i];
    cl_status_t st;
    int64_t now = esp_timer_get_time();

    if (L->planned && L->ok && (now - L->last_ok_us) > 3000000LL) L->planned = false;
    L->polls++;
    if (i2c_master_receive(s_dev[i], (uint8_t *)&st, sizeof(st), 100) == ESP_OK
        && cl_status_valid(&st)) {
        L->last = st; L->ok++; L->last_ok_us = esp_timer_get_time();
        if (!L->planned && send_plan(i)) L->planned = true;
        if (st.scanset_ready && st.scanset_len > 0 && st.scan_seq != L->last_ingest_seq) {
            if (ingest_arm(i, st.scan_seq)) L->last_ingest_seq = st.scan_seq;
        }
    }
}

static inline bool bus_line_stuck(void)
{
    return gpio_get_level(CL_I2C_SDA_GPIO) == 0 || gpio_get_level(CL_I2C_SCL_GPIO) == 0;
}

static void bus_health_check(void)
{
    if (!bus_line_stuck()) return;
    esp_rom_delay_us(50);
    if (!bus_line_stuck()) return;
    int sda = gpio_get_level(CL_I2C_SDA_GPIO), scl = gpio_get_level(CL_I2C_SCL_GPIO);
    esp_err_t e = i2c_master_bus_reset(s_bus);
    s_bus_resets++;
    ESP_LOGW(TAG, "I2C bus wedged (SDA=%d SCL=%d) -> bus_reset #%lu: %s",
             sda, scl, (unsigned long)s_bus_resets, esp_err_to_name(e));
}

static void bus_task(void *arg)
{
    (void)arg;
    bool arm_was_online[N_ARMS] = { false };
    bool scan_inflight = false;
    int  scr = 0;
    bool joined_prev = false;

    for (;;) {
        bus_health_check();

        for (int i = 0; i < N_ARMS; i++) poll_arm(i);
        poll_s3();

        if (s_cfg_req) {
            s_cfg_req = false;
            push_sentcfg_to_s3(s_cfg_pending, s_cfg_pending_len);
            refresh_s3_blobs();
        }
        if (s_clock_req) { s_clock_req = false; push_clock_to_s3(s_clock_pending); }
        {
            static int64_t last_blob_us;
            int64_t bnow = esp_timer_get_time();
            if (bnow - last_blob_us >= 1000000LL) { last_blob_us = bnow; refresh_s3_blobs(); }
        }

        if (s_reset_req) {
            s_reset_req = false;
            ESP_LOGW(TAG, "HARD RESET (WebAP): wiping model + place memory, restarting");
            epup_brain_reset();
            vTaskDelay(pdMS_TO_TICKS(150));
            esp_restart();
        }

        req_t req = s_req; s_req = REQ_NONE;
        if      (req == REQ_WALK)     s_walking = true;
        else if (req == REQ_STOPWALK) s_walking = false;
        else if (req == REQ_SCAN)     s_rescan_once = true;

        int64_t now = esp_timer_get_time();

        int online = 0;
        for (int i = 0; i < N_ARMS; i++) {
            bool on = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
            if (on) online++;
            if (on != arm_was_online[i]) {
                ESP_LOGI(TAG, "arm %u %s", ARMS[i].index, on ? "online" : "went offline");
                arm_was_online[i] = on;
            }
        }

        if (s_arm[0].have && s_arm[1].have) {
            merge_window();
            scan_inflight = false;
            if (!s_walking) s_rescan_once = false;
        }

        bool want_scan = !s_boot_scanned || s_walking || s_rescan_once;
        if (want_scan && online == N_ARMS && !scan_inflight &&
            !(s_arm[0].have || s_arm[1].have)) {
            const char *why = !s_boot_scanned ? "boot" : s_walking ? "walk" : "rescan";
            ESP_LOGI(TAG, "LINK %d/%d -> broadcast SCAN (adv) [%s]", online, N_ARMS, why);
            arm_broadcast(CL_CMD_SCAN, CL_SCAN_ADV);
            scan_inflight = true;
            s_boot_scanned = true;
        }

        if (!download_mode_is_active()) {
            if (scr != 1) {
                display_clear(COLOR_NEARBLACK);
                display_draw_string(2, 34, "Starting AP...", COLOR_AMBER, COLOR_NEARBLACK, 1);
                scr = 1;
            }
        } else {
            bool joined = download_mode_get_client_count() > 0;
            if (scr != 2 || joined != joined_prev) {
                draw_join_screen(joined);
                joined_prev = joined;
                scr = 2;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

#define QR_BOX_PX 72
#define QR_X0     4
#define QR_Y0     4
#define QR_RCOL   80
static uint16_t s_qrbuf[QR_BOX_PX * QR_BOX_PX];
static char     s_stat[26];

static void qr_draw_cb(esp_qrcode_handle_t qr)
{
    int size = esp_qrcode_get_size(qr);
    int border = 2, total = size + 2 * border;
    int scale = QR_BOX_PX / total; if (scale < 1) scale = 1;
    int px = total * scale; if (px > QR_BOX_PX) px = QR_BOX_PX;
    for (int i = 0; i < px * px; i++) s_qrbuf[i] = COLOR_WHITE;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (esp_qrcode_get_module(qr, x, y)) {
                int bx = (border + x) * scale, by = (border + y) * scale;
                for (int dy = 0; dy < scale && by + dy < px; dy++)
                    for (int dx = 0; dx < scale && bx + dx < px; dx++)
                        s_qrbuf[(by + dy) * px + (bx + dx)] = COLOR_BLACK;
            }
    display_draw_image(QR_X0, QR_Y0, px, px, s_qrbuf);
}

static void draw_status_line(void)
{
    display_fill_rect(0, 70, DISPLAY_W, 10, COLOR_NEARBLACK);
    display_draw_string(2, 70, s_stat, COLOR_AMBER, COLOR_NEARBLACK, 1);
}

static void draw_join_screen(bool joined)
{
    display_clear(COLOR_NEARBLACK);
    const char *ssid = download_mode_get_ssid();
    const char *pass = download_mode_get_passphrase();
    char payload[80];
    if (joined) snprintf(payload, sizeof(payload), "http://192.168.4.1/");
    else        snprintf(payload, sizeof(payload), "WIFI:T:WPA2;S:%s;P:%s;;", ssid, pass);
    esp_qrcode_config_t qcfg = ESP_QRCODE_CONFIG_DEFAULT();
    qcfg.display_func       = qr_draw_cb;
    qcfg.max_qrcode_version = 4;
    qcfg.qrcode_ecc_level   = ESP_QRCODE_ECC_LOW;
    if (esp_qrcode_generate(&qcfg, payload) != ESP_OK)
        display_draw_string(QR_X0, 34, "QR err", COLOR_RED, COLOR_NEARBLACK, 1);

    display_draw_string(QR_RCOL, 4, "BRAIN AP", COLOR_HEADER, COLOR_NEARBLACK, 1);
    if (joined) {
        display_draw_string(QR_RCOL, 16, "scan to open", COLOR_WHITE, COLOR_NEARBLACK, 1);
        display_draw_string(QR_RCOL, 27, "192.168.4.1", COLOR_AMBER, COLOR_NEARBLACK, 1);
    } else {
        display_draw_string(QR_RCOL, 16, ssid, COLOR_WHITE, COLOR_NEARBLACK, 1);
        display_draw_string(QR_RCOL, 27, pass, COLOR_AMBER, COLOR_NEARBLACK, 1);
    }
    display_draw_string(QR_RCOL, 42, FW_CKPT, COLOR_GREEN, COLOR_NEARBLACK, 1);
    draw_status_line();
}

static void render_screen(const char *state_txt)
{
    (void)state_txt;
    int online = 0;
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < N_ARMS; i++)
        if (s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL) online++;
    snprintf(s_stat, sizeof(s_stat), "LINK%d/%d m#%lu SD%lu", online, N_ARMS,
             (unsigned long)s_merge_count, (unsigned long)s_s3.recs);
    draw_status_line();
}

static void log_task(void *arg)
{
    (void)arg;
    int64_t last_log = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_log >= 2000000LL) {
            last_log = now;
            int online = 0;
            for (int i = 0; i < N_ARMS; i++)
                if (s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL) online++;
            epup_summary_t ep; epup_brain_get(&ep);
            ESP_LOGI(TAG, "BRAIN-MASTER [%s] up=%llds LINK %d/%d (a1=%s a2=%s) merge#%lu(%luuq %ludp) S3push=%lu/%lu busrst=%lu ePup:%s L%lu %lu%% scans=%lu uniq~%lu",
                     FW_CKPT, (long long)(now / 1000000), online, N_ARMS,
                     s_link[0].ok && (now-s_link[0].last_ok_us)<1500000LL ? "OK":"--",
                     s_link[1].ok && (now-s_link[1].last_ok_us)<1500000LL ? "OK":"--",
                     (unsigned long)s_merge_count, (unsigned long)s_merge_uniq,
                     (unsigned long)s_merge_dup,
                     (unsigned long)s_s3_pushes, (unsigned long)s_s3_fail,
                     (unsigned long)s_bus_resets,
                     epup_title_label((epup_title_t)ep.title), (unsigned long)ep.level,
                     (unsigned long)ep.confidence, (unsigned long)ep.total_scans,
                     (unsigned long)ep.unique_est);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

static void web_task(void *arg)
{
    (void)arg;
    bool up = false;
    for (;;) {
        if (!download_mode_is_active()) download_mode_request_enable();
        if (!up) {
            httpd_handle_t sv = download_http_server();
            if (sv && cluster_web_start(sv) == ESP_OK) {
                up = true;
                alog("WebAP up at 192.168.4.1");
                ESP_LOGI(TAG, "WebAP up — dashboard at http://192.168.4.1/");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " SniffCheck Cluster BRAIN (T-Dongle-C5)  [%s]", FW_CKPT);
    ESP_LOGI(TAG, " I2C MASTER + WebAP host");
    ESP_LOGI(TAG, "==================================================");

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

    for (int f = 0; f < 10; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(160)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(1200));

    uint32_t caps = MALLOC_CAP_SPIRAM;
    s_arm[0].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
    s_arm[1].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
    s_merge_buf  = heap_caps_malloc(BRAIN_MERGE_CAP, caps);
    if (!s_arm[0].buf || !s_arm[1].buf || !s_merge_buf) {
        caps = MALLOC_CAP_8BIT;
        if (!s_arm[0].buf) s_arm[0].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
        if (!s_arm[1].buf) s_arm[1].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
        if (!s_merge_buf)  s_merge_buf  = heap_caps_malloc(BRAIN_MERGE_CAP, caps);
    }
    ESP_LOGI(TAG, "buffers: 2x%uKB arm + %uKB merge (%s)",
             BRAIN_ARM_CAP / 1024, BRAIN_MERGE_CAP / 1024,
             caps == MALLOC_CAP_SPIRAM ? "PSRAM" : "internal RAM");

    s_s3_mux = xSemaphoreCreateMutex();
    uint32_t jcaps = (caps == MALLOC_CAP_SPIRAM) ? MALLOC_CAP_SPIRAM : MALLOC_CAP_8BIT;
    s_sent_json = heap_caps_malloc(6144, jcaps);
    s_hits_json = heap_caps_malloc(6144, jcaps);
    if (s_sent_json) s_sent_json[0] = '\0';
    if (s_hits_json) s_hits_json[0] = '\0';

    epup_brain_init(0);

    ESP_ERROR_CHECK(capture_ring_init(2 * 1024 * 1024, 128 * 1024));
    master_shim_set_session("cluster-brain-0001", FW_CKPT);
    virtual_pup_init(1);
    virtual_pup_walk_init();
    pup_trophy_init();
    const char *seed = "{\"type\":\"info\",\"src\":\"cluster-brain\",\"msg\":\"brain WebAP online\"}";
    capture_ring_write(seed, strlen(seed));

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_country_t country = { .cc = "US", .schan = 1, .nchan = 11,
                               .policy = WIFI_COUNTRY_POLICY_MANUAL };
    esp_wifi_set_country(&country);
    download_mode_init();

    i2c_master_setup();
    render_screen("mastering");

    xTaskCreate(bus_task, "brain_bus", 6144, NULL, 6, NULL);
    xTaskCreate(log_task, "brain_log", 3072, NULL, 4, NULL);
    xTaskCreate(web_task, "brain_web", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "app_main done — I2C MASTER + WebAP host (arms 0x%02x/0x%02x, S3 0x%02x)",
             CL_ARM1_ADDR, CL_ARM2_ADDR, CL_S3_ADDR);
}
