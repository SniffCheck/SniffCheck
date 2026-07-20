#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/util/util.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_slave.h"

#include "head_pins.h"
#include "cluster_pins.h"
#include "cluster_proto.h"
#include "led.h"
#include "node_display.h"
#include "head_sd.h"
#include "sentinel.h"
#include "sentinel_registry.h"

#define FW_CKPT "s3node-1.0"

static const char *TAG = "sc-s3node";

static i2c_slave_dev_handle_t s_slave;
static QueueHandle_t s_txq;
static QueueHandle_t s_rxq;
static volatile uint32_t s_reads, s_pings;

static volatile uint8_t  s_sel_cmd = CL_CMD_STATUS_SEL;
static volatile uint32_t s_sel_off;

static char    s_blob[6144];
static int     s_blob_len;
static uint8_t s_blob_which;

static uint32_t s_window;
static uint32_t s_win_recs;
static char     s_line[3600];
static size_t   s_linelen;

#define BYOI_MAX     24
#define BYOI_NAME    20
#define BYOI_ICON    12
typedef struct {
    uint8_t mac[6];
    uint8_t pref_len;
    uint8_t enabled;
    char    name[BYOI_NAME];
    char    icon[BYOI_ICON];
} byoi_t;

static uint8_t  s_sent_armed = 1;
static uint16_t s_cat_mask = SENTINEL_MASK_ALL;
static byoi_t   s_byoi[BYOI_MAX];
static uint8_t  s_byoi_n;
static uint32_t s_cat_hits[SENTINEL_CAT_COUNT];
static uint8_t  s_cat_conf[SENTINEL_CAT_COUNT];
static uint32_t s_byoi_hits[BYOI_MAX];
static uint32_t s_sent_total, s_sent_recent, s_sent_seq;
static char     s_sent_last[40];
static uint8_t  s_sent_last_mac[6];
static uint8_t  s_sent_last_conf;
static portMUX_TYPE s_sent_mux = portMUX_INITIALIZER_UNLOCKED;

#define SENT_HIT_N  32
typedef struct { int64_t us; char name[40]; uint8_t mac[6]; uint8_t kind; uint8_t conf; } sent_hit_t;
static sent_hit_t   s_hit[SENT_HIT_N];
static uint32_t     s_hit_head, s_hit_count;
static volatile uint32_t s_epoch_base;

static void sent_log_hit(const char *name, const uint8_t mac[6], uint8_t kind, uint8_t conf)
{
    uint32_t i = s_hit_head;
    s_hit[i].us   = esp_timer_get_time();
    s_hit[i].kind = kind;
    s_hit[i].conf = conf;
    memcpy(s_hit[i].mac, mac, 6);
    strlcpy(s_hit[i].name, name && name[0] ? name : "flagged", sizeof s_hit[i].name);
    s_hit_head = (i + 1) % SENT_HIT_N;
    if (s_hit_count < SENT_HIT_N) s_hit_count++;
}

#define SENT_RECENT_N   64
#define SENT_RECENT_US  15000000LL
static struct { uint8_t mac[6]; uint16_t key; int64_t us; } s_recent[SENT_RECENT_N];
static int s_recent_head;
static bool sentinel_recent_seen(const uint8_t mac[6], uint16_t key)
{
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < SENT_RECENT_N; i++) {
        if (s_recent[i].us && s_recent[i].key == key && memcmp(s_recent[i].mac, mac, 6) == 0) {
            bool recent = (now - s_recent[i].us) < SENT_RECENT_US;
            s_recent[i].us = now;
            return recent;
        }
    }
    int idx = s_recent_head; s_recent_head = (s_recent_head + 1) % SENT_RECENT_N;
    memcpy(s_recent[idx].mac, mac, 6); s_recent[idx].key = key; s_recent[idx].us = now;
    return false;
}

typedef struct { uint8_t idbyte; uint8_t conf; char name[40]; } sent_event_t;

static int  json_field(const char *b, int n, const char *pat, char *out, int outsz);
static void mac_str(const uint8_t m[6], char *out);

static void sentinel_account(uint32_t cats, const uint8_t conf[SENTINEL_CAT_COUNT],
                             const uint8_t mac[6], bool have_id, const char *dname,
                             const char *rec_json, int rec_len)
{
    sent_event_t ev[SENTINEL_CAT_COUNT + BYOI_MAX];
    int ne = 0;

    portENTER_CRITICAL(&s_sent_mux);
    for (int c = 0; c < SENTINEL_CAT_COUNT; c++) {
        if (!(cats & (1u << c))) continue;
        bool rep = sentinel_recent_seen(mac, (uint16_t)c);
        if (!rep) s_cat_hits[c]++;
        if (conf[c] > s_cat_conf[c]) s_cat_conf[c] = conf[c];
        if (s_cat_mask & (1u << c)) {
            const sentinel_cat_meta_t *mt = sentinel_cat_meta(c);
            strlcpy(s_sent_last, mt ? mt->label : "?", sizeof s_sent_last);
            memcpy(s_sent_last_mac, mac, 6);
            s_sent_last_conf = conf[c];
            if (!rep) {
                s_sent_total++; s_sent_seq++;
                sent_log_hit(mt ? mt->label : "?", mac, 0, conf[c]);
                ev[ne].idbyte = (uint8_t)c; ev[ne].conf = conf[c];
                strlcpy(ev[ne].name, dname ? dname : "", sizeof ev[ne].name); ne++;
            }
        }
    }
    if (have_id) for (int i = 0; i < s_byoi_n; i++) {
        if (!s_byoi[i].enabled) continue;
        if (sentinel_mac_prefix(mac, s_byoi[i].mac, s_byoi[i].pref_len)) {
            bool rep = sentinel_recent_seen(mac, (uint16_t)(100 + i));
            if (!rep) s_byoi_hits[i]++;
            strlcpy(s_sent_last, s_byoi[i].name, sizeof s_sent_last);
            memcpy(s_sent_last_mac, mac, 6);
            s_sent_last_conf = SENTINEL_CONF_HIGH;
            if (!rep) {
                s_sent_total++; s_sent_seq++;
                sent_log_hit(s_byoi[i].name, mac, 1, SENTINEL_CONF_HIGH);
                ev[ne].idbyte = (uint8_t)(0x80 | i); ev[ne].conf = SENTINEL_CONF_HIGH;
                strlcpy(ev[ne].name, s_byoi[i].name, sizeof ev[ne].name); ne++;
            }
        }
    }
    portEXIT_CRITICAL(&s_sent_mux);

    for (int i = 0; i < ne; i++) {
        uint8_t key[24];
        int kl = sentinel_registry_key(ev[i].idbyte, mac, ev[i].name, key, sizeof key);
        if (kl > 0) sentinel_registry_note(key, kl, rec_json, rec_len);
        else        sentinel_registry_note_untracked();
    }
}

static void sentinel_check_record(const char *line, int n)
{
    if (!s_sent_armed) return;
    uint8_t conf[SENTINEL_CAT_COUNT];
    uint32_t cats = sentinel_match_categories_conf(line, n, conf);
    uint8_t mac[6];
    bool have_id = sentinel_line_identifier(line, n, mac);
    if (!have_id) memset(mac, 0, 6);

    char dname[40] = {0};
    if (!json_field(line, n, "\"name\":\"", dname, sizeof dname))
        json_field(line, n, "\"ssid\":\"", dname, sizeof dname);

    sentinel_account(cats, conf, mac, have_id, dname, line, n);
}

static void s3_sentinel_flag_live(const char *name, const uint8_t m[6], const char *src)
{
    if (!s_sent_armed) return;
    uint8_t conf[SENTINEL_CAT_COUNT];
    uint32_t cats = sentinel_match_fields_conf(name, NULL, NULL, false, conf);
    uint8_t mac[6]; bool have_id = false;
    if (m) { memcpy(mac, m, 6); for (int i = 0; i < 6; i++) if (m[i]) have_id = true; }
    else memset(mac, 0, 6);
    if (!cats && !have_id) return;

    char macs[20]; mac_str(mac, macs);
    char rec[192];
    int rl = snprintf(rec, sizeof rec,
        "{\"type\":\"%s\",\"name\":\"%s\",\"mac\":\"%s\",\"src\":\"s3-%s\"}",
        (src && strcmp(src, "ble") == 0) ? "ble" : "wifi_ap",
        name ? name : "", macs, src ? src : "scan");
    sentinel_account(cats, conf, mac, have_id, name, rec, rl);
}

static void sentinel_persist_load(void)
{
    nvs_handle_t h;
    if (nvs_open("sentinel", NVS_READONLY, &h) != ESP_OK) return;
    uint8_t a; if (nvs_get_u8(h, "armed", &a) == ESP_OK) s_sent_armed = a ? 1 : 0;
    uint16_t m; if (nvs_get_u16(h, "mask", &m) == ESP_OK) s_cat_mask = m & SENTINEL_MASK_ALL;
    size_t sz = sizeof(s_byoi);
    if (nvs_get_blob(h, "byoi", s_byoi, &sz) == ESP_OK) {
        s_byoi_n = (uint8_t)(sz / sizeof(byoi_t));
        if (s_byoi_n > BYOI_MAX) s_byoi_n = BYOI_MAX;
    }
    uint8_t cnt; if (nvs_get_u8(h, "byoi_n", &cnt) == ESP_OK && cnt <= BYOI_MAX) s_byoi_n = cnt;
    nvs_close(h);
}
static void sentinel_persist_save(void)
{
    nvs_handle_t h;
    if (nvs_open("sentinel", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u8(h, "armed", s_sent_armed);
    nvs_set_u16(h, "mask", s_cat_mask);
    nvs_set_u8(h, "byoi_n", s_byoi_n);
    nvs_set_blob(h, "byoi", s_byoi, (size_t)s_byoi_n * sizeof(byoi_t));
    nvs_commit(h);
    nvs_close(h);
}

static bool byoi_parse_mac(const char *s, uint8_t mac[6])
{
    int b = 0; unsigned v = 0, nib = 0;
    for (const char *p = s; *p && b < 6; p++) {
        int d = (*p >= '0' && *p <= '9') ? *p - '0'
              : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10
              : (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
        if (d < 0) continue;
        v = (v << 4) | (unsigned)d;
        if (++nib == 2) { mac[b++] = (uint8_t)v; v = 0; nib = 0; }
    }
    return b >= 1;
}
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

static void sentinel_apply_cfg(const char *body, int n)
{
    bool changed = false;
    if (strstr(body, "\"armed\":")) {
        long a = json_int(body, n, "armed", s_sent_armed);
        portENTER_CRITICAL(&s_sent_mux); s_sent_armed = a ? 1 : 0; portEXIT_CRITICAL(&s_sent_mux);
        changed = true;
    }
    if (strstr(body, "\"mask\":")) {
        long m = json_int(body, n, "mask", s_cat_mask);
        portENTER_CRITICAL(&s_sent_mux); s_cat_mask = (uint16_t)m & SENTINEL_MASK_ALL; portEXIT_CRITICAL(&s_sent_mux);
        changed = true;
    }
    if (strstr(body, "\"byoi_en\":")) {
        long i = json_int(body, n, "i", -1), on = json_int(body, n, "on", 1);
        portENTER_CRITICAL(&s_sent_mux);
        if (i >= 0 && i < s_byoi_n) { s_byoi[i].enabled = on ? 1 : 0; changed = true; }
        portEXIT_CRITICAL(&s_sent_mux);
    }
    if (strstr(body, "\"byoi_del\":")) {
        long i = json_int(body, n, "byoi_del", -1);
        portENTER_CRITICAL(&s_sent_mux);
        if (i >= 0 && i < s_byoi_n) {
            for (int k = i; k + 1 < s_byoi_n; k++) { s_byoi[k] = s_byoi[k + 1]; s_byoi_hits[k] = s_byoi_hits[k + 1]; }
            s_byoi_n--; changed = true;
        }
        portEXIT_CRITICAL(&s_sent_mux);
    }
    if (strstr(body, "\"byoi_add\":")) {
        char mac[32] = {0}, name[BYOI_NAME] = {0}, icon[BYOI_ICON] = {0};
        json_field(body, n, "\"mac\":\"",  mac,  sizeof mac);
        json_field(body, n, "\"name\":\"", name, sizeof name);
        json_field(body, n, "\"icon\":\"", icon, sizeof icon);
        long pref = json_int(body, n, "pref_len", 6);
        byoi_t e; memset(&e, 0, sizeof e);
        if (byoi_parse_mac(mac, e.mac) && s_byoi_n < BYOI_MAX) {
            e.pref_len = (uint8_t)(pref < 1 ? 1 : pref > 6 ? 6 : pref);
            e.enabled  = 1;
            strlcpy(e.name, name[0] ? name : "flagged", sizeof e.name);
            strlcpy(e.icon, icon[0] ? icon : "ic-alert", sizeof e.icon);
            portENTER_CRITICAL(&s_sent_mux);
            s_byoi_hits[s_byoi_n] = 0;
            s_byoi[s_byoi_n++] = e;
            portEXIT_CRITICAL(&s_sent_mux);
            changed = true;
        }
    }
    if (changed) { sentinel_persist_save(); ESP_LOGI(TAG, "sentinel cfg applied (armed=%u mask=0x%x byoi=%u)",
                                                     s_sent_armed, s_cat_mask, s_byoi_n); }
}

static void mac_str(const uint8_t m[6], char *out)
{
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}
static int build_sentinel_json(char *buf, size_t buflen)
{
    char mac[20];
    sentinel_reg_stats_t rg; sentinel_registry_stats(&rg);
    int off = snprintf(buf, buflen, "{\"armed\":%s,\"mask\":%u,\"total\":%lu,\"recent\":%lu,\"seq\":%lu,"
                       "\"life\":%lu,\"life_uniq\":%lu,\"returning\":%lu,\"sess_uniq\":%lu,\"cats\":[",
                       s_sent_armed ? "true" : "false", s_cat_mask, (unsigned long)s_sent_total,
                       (unsigned long)s_sent_recent, (unsigned long)s_sent_seq,
                       (unsigned long)rg.lifetime_detections, (unsigned long)rg.lifetime_unique,
                       (unsigned long)rg.returning, (unsigned long)rg.session_unique);
    for (int i = 0; i < SENTINEL_CAT_COUNT && off > 0 && off < (int)buflen; i++) {
        const sentinel_cat_meta_t *mt = sentinel_cat_meta(i);
        off += snprintf(buf + off, buflen - off,
            "%s{\"id\":%d,\"key\":\"%s\",\"label\":\"%s\",\"icon\":\"%s\",\"hits\":%lu,\"conf\":%u,\"alert\":%s}",
            i ? "," : "", i, mt ? mt->key : "?", mt ? mt->label : "?", mt ? mt->icon : "ic-alert",
            (unsigned long)s_cat_hits[i], s_cat_conf[i], (s_cat_mask & (1u << i)) ? "true" : "false");
    }
    if (off > 0 && off < (int)buflen) off += snprintf(buf + off, buflen - off, "],\"byoi\":[");
    for (int i = 0; i < s_byoi_n && off > 0 && off < (int)buflen; i++) {
        mac_str(s_byoi[i].mac, mac);
        off += snprintf(buf + off, buflen - off,
            "%s{\"i\":%d,\"mac\":\"%s\",\"pref_len\":%u,\"name\":\"%s\",\"icon\":\"%s\",\"enabled\":%s,\"hits\":%lu}",
            i ? "," : "", i, mac, s_byoi[i].pref_len, s_byoi[i].name, s_byoi[i].icon,
            s_byoi[i].enabled ? "true" : "false", (unsigned long)s_byoi_hits[i]);
    }
    mac_str(s_sent_last_mac, mac);
    if (off > 0 && off < (int)buflen)
        off += snprintf(buf + off, buflen - off, "],\"last\":{\"label\":\"%s\",\"mac\":\"%s\",\"conf\":%u}}",
                        s_sent_last[0] ? s_sent_last : "", mac, s_sent_last_conf);
    return (off > 0 && off < (int)buflen) ? off : (int)buflen - 1;
}
static int build_hits_json(char *buf, size_t buflen)
{
    portENTER_CRITICAL(&s_sent_mux);
    uint32_t n = s_hit_count, head = s_hit_head;
    portEXIT_CRITICAL(&s_sent_mux);
    uint32_t base = s_epoch_base;
    int off = snprintf(buf, buflen, "{\"base\":%lu,\"hits\":[", (unsigned long)base);
    char mac[20];
    for (uint32_t k = 0; k < n && off > 0 && off < (int)buflen; k++) {
        uint32_t idx = (head + SENT_HIT_N - 1 - k) % SENT_HIT_N;
        uint32_t up = (uint32_t)(s_hit[idx].us / 1000000);
        mac_str(s_hit[idx].mac, mac);
        off += snprintf(buf + off, buflen - off,
            "%s{\"name\":\"%s\",\"mac\":\"%s\",\"kind\":%u,\"conf\":%u,\"up\":%lu,\"ts\":%lu,\"lat\":null,\"lon\":null}",
            k ? "," : "", s_hit[idx].name, mac, s_hit[idx].kind, s_hit[idx].conf, (unsigned long)up,
            (unsigned long)(base ? base + up : 0));
    }
    if (off > 0 && off < (int)buflen) off += snprintf(buf + off, buflen - off, "]}");
    return (off > 0 && off < (int)buflen) ? off : (int)buflen - 1;
}

static void feed_payload(const uint8_t *p, uint16_t n)
{
    for (uint16_t k = 0; k < n; k++) {
        uint8_t b = p[k];
        if (b == '\n') {
            if (s_linelen > 0) {
                s_line[s_linelen] = '\0';
                head_sd_append(s_line, s_linelen);
                sentinel_check_record(s_line, (int)s_linelen);
                s_win_recs++;
            }
            s_linelen = 0;
        } else if (s_linelen < sizeof(s_line) - 1) {
            s_line[s_linelen++] = b;
        } else {
            s_linelen = 0;
        }
    }
}

static bool IRAM_ATTR on_receive_cb(i2c_slave_dev_handle_t dev,
                                    const i2c_slave_rx_done_event_data_t *evt, void *arg)
{
    (void)dev; (void)arg;
    if (!evt || !evt->buffer) return false;

    if (evt->length >= sizeof(cl_chunk_t)) {
        const cl_chunk_t *c = (const cl_chunk_t *)evt->buffer;
        if (!cl_chunk_valid(c) || (c->type != CL_PUT_S3MERGE && c->type != CL_PUT_SENTCFG))
            return false;
        BaseType_t woken = pdFALSE;
        xQueueSendFromISR(s_rxq, c, &woken);
        return woken == pdTRUE;
    }

    if (evt->length >= sizeof(cl_getreq_t)) {
        const cl_getreq_t *g = (const cl_getreq_t *)evt->buffer;
        if (cl_getreq_valid_cmd(g, CL_CMD_GET_SENT) || cl_getreq_valid_cmd(g, CL_CMD_GET_HITS) ||
            cl_getreq_valid_cmd(g, CL_CMD_STATUS_SEL)) {
            s_sel_cmd = g->cmd; s_sel_off = g->offset;
        } else if (cl_getreq_valid_cmd(g, CL_CMD_SET_CLOCK)) {
            uint32_t epoch = g->offset;
            if (epoch >= 1700000000UL) s_epoch_base = epoch - (uint32_t)(esp_timer_get_time() / 1000000);
        }
        return false;
    }

    if (evt->length >= sizeof(cl_cmd_frame_t)) {
        const cl_cmd_frame_t *f = (const cl_cmd_frame_t *)evt->buffer;
        if (cl_cmd_valid(f) && f->cmd == CL_CMD_PING) s_pings++;
        return false;
    }
    return false;
}

static bool IRAM_ATTR on_request_cb(i2c_slave_dev_handle_t dev,
                                    const i2c_slave_request_event_data_t *evt, void *arg)
{
    (void)dev; (void)evt; (void)arg;
    s_reads++;
    BaseType_t woken = pdFALSE;
    uint8_t ev = 1;
    xQueueSendFromISR(s_txq, &ev, &woken);
    return woken == pdTRUE;
}

static void serve_status(void)
{
    head_sd_stats_t sd; head_sd_get_stats(&sd);
    cl_status_t st;
    memset(&st, 0, sizeof st);
    st.arm_index     = CL_S3_ADDR;
    st.band          = 0;
    st.state         = sd.mounted ? 1 : 0;
    st.scanset_ready = sd.mounted ? 1 : 0;
    st.wifi_seen     = (uint16_t)s_sent_total;
    st.ble_seen      = 0;
    st.scan_seq      = s_window;
    st.scanset_len   = sd.records;
    cl_status_seal(&st);
    uint32_t written = 0;
    i2c_slave_write(s_slave, (const uint8_t *)&st, sizeof(st), &written, 100);
}
static void serve_blob(uint8_t cmd, uint32_t off)
{
    if (off == 0) {
        s_blob_len   = (cmd == CL_CMD_GET_HITS) ? build_hits_json(s_blob, sizeof s_blob)
                                                : build_sentinel_json(s_blob, sizeof s_blob);
        s_blob_which = cmd;
    }
    cl_chunk_t ch; memset(&ch, 0, sizeof ch);
    ch.type      = CL_RESP_CHUNK;
    ch.scan_seq  = 0;
    ch.total_len = (uint32_t)s_blob_len;
    ch.offset    = off;
    if (s_blob_which == cmd && (int)off < s_blob_len) {
        uint32_t rem = (uint32_t)s_blob_len - off;
        ch.len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
        memcpy(ch.payload, s_blob + off, ch.len);
    } else {
        ch.len = 0;
    }
    cl_chunk_seal(&ch);
    uint32_t written = 0;
    i2c_slave_write(s_slave, (const uint8_t *)&ch, sizeof(ch), &written, 100);
}
static void s3_tx_task(void *arg)
{
    (void)arg;
    uint8_t ev;
    for (;;) {
        if (xQueueReceive(s_txq, &ev, portMAX_DELAY) != pdTRUE) continue;
        uint8_t  cmd = s_sel_cmd;
        uint32_t off = s_sel_off;
        if (cmd == CL_CMD_GET_SENT || cmd == CL_CMD_GET_HITS) serve_blob(cmd, off);
        else                                                  serve_status();
    }
}

static void render_screen(const char *state_txt);

static char     s_cfgbuf[512];
static uint32_t s_cfglen;
static void ingest_task(void *arg)
{
    (void)arg;
    static cl_chunk_t ch;
    uint32_t cur_seq = 0, exp_off = 0;
    for (;;) {
        if (xQueueReceive(s_rxq, &ch, portMAX_DELAY) != pdTRUE) continue;

        if (ch.type == CL_PUT_SENTCFG) {
            if (ch.offset == 0) s_cfglen = 0;
            if (ch.len && s_cfglen + ch.len < sizeof(s_cfgbuf))
                { memcpy(s_cfgbuf + s_cfglen, ch.payload, ch.len); s_cfglen += ch.len; }
            if (ch.len == 0 && s_cfglen > 0) {
                s_cfgbuf[s_cfglen] = '\0';
                sentinel_apply_cfg(s_cfgbuf, (int)s_cfglen);
                s_cfglen = 0;
            }
            continue;
        }

        if (ch.offset == 0) {
            cur_seq = ch.scan_seq;
            exp_off = 0;
            s_linelen = 0;
            s_win_recs = 0;
        }
        if (ch.scan_seq != cur_seq) continue;
        if (ch.offset != exp_off) { s_linelen = 0; exp_off = ch.offset; }

        if (ch.len) feed_payload(ch.payload, ch.len);
        exp_off = ch.offset + ch.len;

        if (ch.len == 0) {
            if (s_linelen > 0) {
                s_line[s_linelen] = '\0';
                head_sd_append(s_line, s_linelen);
                sentinel_check_record(s_line, (int)s_linelen);
                s_win_recs++;
                s_linelen = 0;
            }
            head_sd_flush();
            s_window++;
            head_sd_stats_t sd; head_sd_get_stats(&sd);
            ESP_LOGI(TAG, "window #%lu: %lu recs -> SD=%s(%urec) sentinel total=%lu last=%s",
                     (unsigned long)s_window, (unsigned long)s_win_recs,
                     sd.mounted ? "ok" : "--", (unsigned)sd.records,
                     (unsigned long)s_sent_total, s_sent_last[0] ? s_sent_last : "-");
            char l[24];
            snprintf(l, sizeof(l), "w%lu %urec", (unsigned long)s_window, (unsigned)sd.records);
            render_screen(l);
        }
    }
}

static void i2c_slave_setup(void)
{
    s_txq = xQueueCreate(8, sizeof(uint8_t));
    s_rxq = xQueueCreate(16, sizeof(cl_chunk_t));
    i2c_slave_config_t cfg = {
        .i2c_port          = HEAD_I2C_PORT,
        .sda_io_num        = HEAD_I2C_SDA_GPIO,
        .scl_io_num        = HEAD_I2C_SCL_GPIO,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .send_buf_depth    = 512,
        .receive_buf_depth = 512,
        .slave_addr        = CL_S3_ADDR,
        .addr_bit_len      = I2C_ADDR_BIT_LEN_7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_slave_device(&cfg, &s_slave));
    i2c_slave_event_callbacks_t cbs = { .on_request = on_request_cb, .on_receive = on_receive_cb };
    ESP_ERROR_CHECK(i2c_slave_register_event_callbacks(s_slave, &cbs, NULL));
    xTaskCreate(s3_tx_task,  "s3_tx",  4096, NULL, 7, NULL);
    xTaskCreate(ingest_task, "s3_ingest", 6144, NULL, 6, NULL);
    ESP_LOGI(TAG, "I2C slave up: addr 0x%02x SDA=%d SCL=%d",
             CL_S3_ADDR, HEAD_I2C_SDA_GPIO, HEAD_I2C_SCL_GPIO);
}

static void led_bus_init(void)
{
    spi_bus_config_t bus = {
        .mosi_io_num     = HEAD_LED_DIN_GPIO,
        .sclk_io_num     = HEAD_LED_CLK_GPIO,
        .miso_io_num     = -1,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = 64,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(HEAD_LED_SPI_HOST, &bus, SPI_DMA_DISABLED));
    ESP_ERROR_CHECK(led_init(HEAD_LED_SPI_HOST));
}

static void lcd_bus_init(void)
{
    spi_bus_config_t bus = {
        .mosi_io_num   = HEAD_LCD_MOSI_GPIO, .miso_io_num = -1, .sclk_io_num = HEAD_LCD_CLK_GPIO,
        .quadwp_io_num = -1, .quadhd_io_num = -1,
        .max_transfer_sz = DISPLAY_W * DISPLAY_H * (int)sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(HEAD_LCD_SPI_HOST, &bus, SPI_DMA_CH_AUTO));
    ESP_ERROR_CHECK(display_init(HEAD_LCD_SPI_HOST));
}

static void render_screen(const char *state_txt)
{
    char l[24];
    display_clear(COLOR_NEARBLACK);
    const char *title = "S3 NODE";
    display_draw_string(2, 4, title, COLOR_HEADER, COLOR_NEARBLACK, 2);
    snprintf(l, sizeof(l), "slave 0x%02X  SD+Sentinel", CL_S3_ADDR);
    display_draw_string(2, 24, l, COLOR_GREEN, COLOR_NEARBLACK, 1);
    display_draw_string(2, 40, state_txt, COLOR_AMBER, COLOR_NEARBLACK, 1);
    snprintf(l, sizeof(l), "flagged: %lu", (unsigned long)s_sent_total);
    display_draw_string(2, 54, l, COLOR_WHITE, COLOR_NEARBLACK, 1);
    snprintf(l, sizeof(l), "%s", FW_CKPT);
    display_draw_string(DISPLAY_W - (int)strlen(l) * 6 - 2, 70, l, COLOR_WHITE,
                        COLOR_NEARBLACK, 1);
}

static void status_task(void *arg)
{
    (void)arg;
    int64_t last_log = 0, last_flush = 0;
    int phase = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();

        if (!head_sd_ok()) led_set(255, 40, 0, 12);
        else { uint8_t b = (phase < 16) ? phase : (31 - phase); led_set(0, 255, 80, b); }
        phase = (phase + 1) & 31;

        if (now - last_flush >= 2000000LL) { last_flush = now; head_sd_flush(); sentinel_registry_sync(); }

        if (now - last_log >= 2000000LL) {
            last_log = now;
            head_sd_stats_t sd; head_sd_get_stats(&sd);
            ESP_LOGI(TAG, "alive [%s] up=%llds SLAVE 0x%02x windows=%lu reads=%lu pings=%lu SD=%s(%urec %.1fGB) flagged=%lu",
                     FW_CKPT, (long long)(now / 1000000), CL_S3_ADDR,
                     (unsigned long)s_window, (unsigned long)s_reads, (unsigned long)s_pings,
                     sd.mounted ? "ok" : "--", (unsigned)sd.records,
                     (double)sd.card_bytes / 1e9, (unsigned long)s_sent_total);
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

static void wifi_scan_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_country_t c = { .cc = "US", .schan = 1, .nchan = 11, .policy = WIFI_COUNTRY_POLICY_MANUAL };
    esp_wifi_set_country(&c);
    ESP_LOGI(TAG, "own-radio sentinel scan: WiFi 2.4 GHz STA up (gated by sentinel arm)");
}

static volatile bool s_ble_synced;
static volatile bool s_ble_scanning;
static uint8_t        s_ble_addr_type;

static int ble_disc_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type != BLE_GAP_EVENT_EXT_DISC) return 0;
    const struct ble_gap_ext_disc_desc *d = &event->ext_disc;
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, d->data, d->length_data) != 0) return 0;
    if (!fields.name || fields.name_len == 0) return 0;
    char name[33];
    int l = fields.name_len < 32 ? fields.name_len : 32;
    memcpy(name, fields.name, l); name[l] = '\0';
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = d->addr.val[5 - i];
    s3_sentinel_flag_live(name, mac, "ble");
    return 0;
}

static void ble_on_sync(void)
{
    if (ble_hs_id_infer_auto(0, &s_ble_addr_type) != 0) { ESP_LOGW(TAG, "BLE: addr infer failed"); return; }
    s_ble_synced = true;
    ESP_LOGI(TAG, "own-radio sentinel scan: BLE observer ready (gated by sentinel arm)");
}
static void ble_on_reset(int reason) { ESP_LOGW(TAG, "BLE reset (%d)", reason); s_ble_scanning = false; }
static void ble_host_task(void *arg) { (void)arg; nimble_port_run(); nimble_port_freertos_deinit(); }

static void ble_scan_init(void)
{
    if (nimble_port_init() != ESP_OK) { ESP_LOGW(TAG, "NimBLE init failed — WiFi-only sentinel"); return; }
    ble_hs_cfg.sync_cb  = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;
    nimble_port_freertos_init(ble_host_task);
}

static void ble_scan_set(bool on)
{
    if (!s_ble_synced || on == s_ble_scanning) return;
    if (on) {
        struct ble_gap_ext_disc_params un = { .itvl = 0, .window = 0, .passive = 1 };
        int rc = ble_gap_ext_disc(s_ble_addr_type, 0 , 0, 0 ,
                                  0, 0, &un, NULL, ble_disc_cb, NULL);
        if (rc == 0) s_ble_scanning = true;
        else ESP_LOGW(TAG, "ble_gap_ext_disc: %d", rc);
    } else {
        ble_gap_disc_cancel();
        s_ble_scanning = false;
    }
}

static void sniff_task(void *arg)
{
    (void)arg;
    static wifi_ap_record_t aps[32];
    uint32_t sweeps = 0, flagged_seen = 0;
    for (;;) {
        if (!s_sent_armed) {
            ble_scan_set(false);
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        ble_scan_set(true);
        wifi_scan_config_t sc = { .show_hidden = true, .scan_type = WIFI_SCAN_TYPE_ACTIVE };
        if (esp_wifi_scan_start(&sc, true) == ESP_OK) {
            uint16_t n = sizeof(aps) / sizeof(aps[0]);
            if (esp_wifi_scan_get_ap_records(&n, aps) == ESP_OK) {
                uint32_t before = 0; { sentinel_reg_stats_t s; sentinel_registry_stats(&s); before = s.session_detections; }
                for (int i = 0; i < n; i++) {
                    char ssid[33];
                    memcpy(ssid, aps[i].ssid, 32); ssid[32] = '\0';
                    s3_sentinel_flag_live(ssid, aps[i].bssid, "wifi");
                }
                sentinel_reg_stats_t s; sentinel_registry_stats(&s);
                flagged_seen += (s.session_detections - before);
            }
            sweeps++;
            if ((sweeps & 0x0F) == 0)
                ESP_LOGI(TAG, "own-scan: %lu sweeps, %lu flagged (session), ble=%d",
                         (unsigned long)sweeps, (unsigned long)flagged_seen, s_ble_scanning);
        }
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " SniffCheck Cluster S3 SERVICE NODE (T-Dongle-S3)  [%s]", FW_CKPT);
    ESP_LOGI(TAG, " I2C slave 0x%02x — SD store + sentinel", CL_S3_ADDR);
    ESP_LOGI(TAG, "==================================================");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    led_bus_init();
    led_set(255, 160, 0, 10);

    lcd_bus_init();
    for (int f = 0; f < 10; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(120)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(900));

#if HEAD_SD_ENABLE
    if (head_sd_mount() != ESP_OK)
        ESP_LOGW(TAG, "no SD store — sentinel-only (insert a FAT32 card)");
#else
    ESP_LOGW(TAG, "SD disabled (HEAD_SD_ENABLE=0) — sentinel-only");
#endif

    sentinel_persist_load();
    sentinel_registry_init();
    i2c_slave_setup();
    render_screen("waiting for brain");

    wifi_scan_init();
    ble_scan_init();
    xTaskCreate(sniff_task,  "s3_sniff",  4096, NULL, 5, NULL);
    xTaskCreate(status_task, "s3_status", 4096, NULL, 4, NULL);
    ESP_LOGI(TAG, "S3 node app_main done — I2C slave 0x%02x listening for merged scansets",
             CL_S3_ADDR);
}
