#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "dp_espnow.h"
#include "dogpark_protocol.h"
#include "dp_sniffer.h"
#include "dp_ble.h"
#include "node_display.h"
#include "led.h"

static const char *TAG = "sniffcheck-node";

#define CONTROL_CHANNEL    1
#define HEARTBEAT_US       (2 * 1000000LL)
#define SERVICE_MS         200
#define DEFAULT_DWELL_MS   250
#define MAX_RECORDS_PER_CYCLE 8

#define SPI_HOST        SPI2_HOST
#define PIN_MOSI        2
#define PIN_MISO        7
#define PIN_SCK         6
#define PIN_BOOT        28
#define BTN_DEBOUNCE_MS 40

static struct {
    bool     admitted;
    uint16_t node_id;
    uint32_t session_id;
    uint8_t  orch_mac[6];
    uint8_t  mode;
    bool     scanning;
    bool     ble_on;
    uint16_t seq;
    uint32_t record_id;

    uint8_t  channels[DP_MAX_CHANNELS_PER_NODE];
    uint8_t  chan_count;
    uint16_t dwell_ms;

    uint16_t guard_baseline_s;
    int8_t   guard_radius_rssi;
    int64_t  guard_baseline_until;
    uint32_t guard_baseline_count;
    uint32_t guard_barks;
} N;

#define DEFAULT_GUARD_BASELINE_S  30
#define DEFAULT_GUARD_RADIUS_RSSI (-75)
#define GUARD_BARK_MS             1500
#define GUARD_BARK_BRIGHT         12

#define GUARD_RESEND_MS  2000
#define GUARD_LEAVE_MS   45000
#define GUARD_SNAP_MAX   24
static int64_t s_last_resend;

#define NODE_PEERS   12
#define PEER_FRESH_MS 12000
static struct { uint16_t id; int8_t rssi; int64_t ts; bool used; } s_peers[NODE_PEERS];

static void peer_note(uint16_t id, int8_t rssi)
{
    if (id == DP_NODE_UNASSIGNED) return;
    int64_t now = esp_timer_get_time();
    int slot = -1;
    for (int i = 0; i < NODE_PEERS; i++) {
        if (s_peers[i].used && s_peers[i].id == id) {
            s_peers[i].rssi = rssi; s_peers[i].ts = now; return;
        }
        if (!s_peers[i].used && slot < 0) slot = i;
    }
    if (slot < 0) return;
    s_peers[slot] = (typeof(s_peers[0])){ .id = id, .rssi = rssi, .ts = now, .used = true };
}

static volatile bool s_active;
static uint8_t       s_self_mac[6];

static const uint8_t DEFAULT_CHANNELS[] = { 1, 6, 11 };

static uint16_t next_seq(void) { return N.seq++; }

static volatile int64_t s_bark_until_us;

static void led_post_blit_guard(void)
{
    if (esp_timer_get_time() < s_bark_until_us) led_set(255, 0, 0, GUARD_BARK_BRIGHT);
    else                                        led_off();
}

static void node_bark(void)
{
    s_bark_until_us = esp_timer_get_time() + (int64_t)GUARD_BARK_MS * 1000;
    led_set(255, 0, 0, GUARD_BARK_BRIGHT);
    N.guard_barks++;
}

static void radios_for_mode(uint8_t mode)
{
    bool wifi = (mode == DP_MODE_WALK);
    bool ble  = (mode == DP_MODE_GUARD);

    if (wifi && !N.scanning) { dp_sniffer_reset_seen(); dp_sniffer_start(); }
    else if (!wifi && N.scanning) dp_sniffer_stop();
    N.scanning = wifi;

    if (ble && !N.ble_on) { dp_ble_reset_seen(); dp_ble_start(); }
    else if (!ble && N.ble_on) dp_ble_stop();
    N.ble_on = ble;
}

static void apply_mode(uint8_t mode)
{
    N.mode = mode;
    radios_for_mode(mode);

    if (mode == DP_MODE_GUARD) {

        uint16_t bs = N.guard_baseline_s ? N.guard_baseline_s : DEFAULT_GUARD_BASELINE_S;
        N.guard_baseline_until = esp_timer_get_time() + (int64_t)bs * 1000000;
        N.guard_baseline_count = 0;
        N.guard_barks = 0;
        ESP_LOGI(TAG, "GUARD (BLE) baseline %us, radius %ddBm", bs,
                 N.guard_radius_rssi ? N.guard_radius_rssi : DEFAULT_GUARD_RADIUS_RSSI);
    }
}

static void send_join_request(void)
{
    dp_join_request_t jr = {0};
    dp_espnow_self_mac(jr.mac);
    jr.caps = DP_CAP_WIFI_2G | DP_CAP_BLE;
    jr.fw_major = 1;
    jr.fw_minor = 0;
    strncpy(jr.name, "sniffnode", sizeof(jr.name) - 1);
    dp_espnow_send(NULL, DP_MSG_JOIN_REQUEST, 0,
                   DP_SESSION_NONE, DP_NODE_UNASSIGNED, next_seq(),
                   &jr, sizeof(jr));
    ESP_LOGI(TAG, "broadcast JOIN_REQUEST (awaiting approval on the X4)");
}

static void send_heartbeat(void)
{
    uint32_t wu = dp_sniffer_unique_count();
    uint32_t bu = dp_ble_unique_count();
    dp_heartbeat_t hb = {
        .mode = N.mode,
        .battery_pct = 0xFF,
        .wifi_seen = wu > 0xFFFF ? 0xFFFF : (uint16_t)wu,
        .ble_seen  = bu > 0xFFFF ? 0xFFFF : (uint16_t)bu,
    };
    dp_espnow_send(N.orch_mac, DP_MSG_HEARTBEAT, 0,
                   N.session_id, N.node_id, next_seq(), &hb, sizeof(hb));
}

static void send_record(const dp_obs_t *o, bool guard)
{
    uint8_t buf[sizeof(dp_record_hdr_t) + sizeof(dp_scan_record_t)];
    dp_record_hdr_t *rh  = (dp_record_hdr_t *)buf;
    dp_scan_record_t *rec = (dp_scan_record_t *)(buf + sizeof(*rh));

    memset(rec, 0, sizeof(*rec));
    memcpy(rec->bssid, o->mac, 6);
    rec->rssi     = o->rssi;
    rec->channel  = o->channel;
    rec->freq_mhz = dp_channel_to_freq(o->channel);
    rec->auth     = DP_AUTH_UNKNOWN;
    rec->ssid_len = o->ssid_len > sizeof(rec->ssid) ? sizeof(rec->ssid) : o->ssid_len;
    if (rec->ssid_len) memcpy(rec->ssid, o->ssid, rec->ssid_len);
    rec->geo.fix  = DP_FIX_NONE;

    rh->record_id = ++N.record_id;
    rh->kind      = o->kind;
    rh->body_len  = (uint8_t)sizeof(*rec);

    dp_espnow_send(N.orch_mac, guard ? DP_MSG_GUARD_EVENT : DP_MSG_SCAN_RECORD, 0,
                   N.session_id, N.node_id, next_seq(),
                   buf, sizeof(*rh) + sizeof(*rec));
}

static void send_node_ping(void)
{
    dp_espnow_send(NULL, DP_MSG_NODE_PING, DP_FLAG_BROADCAST,
                   N.session_id, N.node_id, next_seq(), NULL, 0);
}

static void send_peer_report(void)
{
    dp_peer_report_t pr = {0};
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < NODE_PEERS && pr.count < DP_MAX_PEER_RSSI; i++) {
        if (!s_peers[i].used) continue;
        if (now - s_peers[i].ts > (int64_t)PEER_FRESH_MS * 1000) { s_peers[i].used = false; continue; }
        pr.peers[pr.count].peer_id = s_peers[i].id;
        pr.peers[pr.count].rssi    = s_peers[i].rssi;
        pr.count++;
    }
    if (pr.count == 0) return;

    dp_espnow_send(NULL, DP_MSG_PEER_REPORT, DP_FLAG_BROADCAST,
                   N.session_id, N.node_id, next_seq(), &pr, sizeof(pr));
}

static void send_ack(const dp_rx_frame_t *f)
{
    if (!(f->hdr.flags & DP_FLAG_ACK_REQ)) return;
    dp_ack_t a = { .acked_type = f->hdr.type, .status = 0,
                   .acked_sequence = f->hdr.sequence };
    dp_espnow_send(f->src_mac, DP_MSG_ACK, 0,
                   N.session_id, N.node_id, next_seq(), &a, sizeof(a));
}

static void flush_records(void)
{
    if (N.mode == DP_MODE_WALK) {
        dp_obs_t o;
        for (int i = 0; i < MAX_RECORDS_PER_CYCLE && dp_sniffer_next(&o, 0); i++)
            send_record(&o, false);
        return;
    }
    if (N.mode != DP_MODE_GUARD) return;

    bool baselining = esp_timer_get_time() < N.guard_baseline_until;
    int8_t radius = N.guard_radius_rssi ? N.guard_radius_rssi : DEFAULT_GUARD_RADIUS_RSSI;
    dp_obs_t o;
    for (int i = 0; i < MAX_RECORDS_PER_CYCLE && dp_ble_next(&o, 0); i++) {
        if (baselining) { N.guard_baseline_count++; continue; }
        if (o.rssi < radius) continue;
        node_bark();
        send_record(&o, true);
    }
}

static void guard_resend(void)
{
    int64_t now = esp_timer_get_time();
    if (now - s_last_resend < (int64_t)GUARD_RESEND_MS * 1000) return;
    s_last_resend = now;

    int8_t radius = N.guard_radius_rssi ? N.guard_radius_rssi : DEFAULT_GUARD_RADIUS_RSSI;
    dp_obs_t snap[GUARD_SNAP_MAX];
    int n = dp_ble_live_snapshot(snap, GUARD_SNAP_MAX, GUARD_LEAVE_MS);
    for (int i = 0; i < n; i++) {
        if (snap[i].rssi < radius) continue;
        send_record(&snap[i], true);
    }
}

static const char *mode_name(uint8_t m)
{
    return m == DP_MODE_WALK ? "Walk" : m == DP_MODE_GUARD ? "Guard Dog" : "Idle";
}

static void on_join_accept(const dp_rx_frame_t *f)
{
    if (f->payload_len < sizeof(dp_join_accept_t)) return;
    const dp_join_accept_t *acc = (const dp_join_accept_t *)f->payload;

    if (memcmp(acc->node_mac, s_self_mac, 6) != 0) return;

    N.admitted   = true;
    N.node_id    = acc->assigned_id;
    N.session_id = acc->session_id;
    memcpy(N.orch_mac, acc->orch_mac, 6);
    dp_espnow_add_peer(N.orch_mac);
    apply_mode(acc->mode);
    send_ack(f);
    ESP_LOGI(TAG, "ADMITTED as node %u, session 0x%08lx", N.node_id,
             (unsigned long)N.session_id);
}

static void on_mode_set(const dp_rx_frame_t *f)
{
    if (f->payload_len < sizeof(dp_mode_set_t)) return;
    const dp_mode_set_t *ms = (const dp_mode_set_t *)f->payload;
    apply_mode(ms->mode);
    send_ack(f);
    ESP_LOGI(TAG, "MODE_SET -> %s (wifi=%d ble=%d)", mode_name(N.mode),
             ms->scan_wifi, ms->scan_ble);
}

static void on_channel_assign(const dp_rx_frame_t *f)
{
    if (f->payload_len < sizeof(dp_channel_assign_t)) return;
    const dp_channel_assign_t *ca = (const dp_channel_assign_t *)f->payload;
    int c = ca->count > DP_MAX_CHANNELS_PER_NODE ? DP_MAX_CHANNELS_PER_NODE : ca->count;
    memcpy(N.channels, ca->channels, c);
    N.chan_count = c;
    N.dwell_ms = ca->dwell_ms ? ca->dwell_ms : DEFAULT_DWELL_MS;
    send_ack(f);

    char list[64]; int o = 0;
    for (int i = 0; i < c; i++) o += snprintf(list + o, sizeof(list) - o, "%d ", N.channels[i]);
    ESP_LOGI(TAG, "CHANNEL_ASSIGN dwell=%ums [ %s]", N.dwell_ms, list);
}

static void on_guard_config(const dp_rx_frame_t *f)
{
    if (f->payload_len < sizeof(dp_guard_config_t)) return;
    const dp_guard_config_t *gc = (const dp_guard_config_t *)f->payload;
    N.guard_baseline_s  = gc->baseline_s;
    N.guard_radius_rssi = gc->radius_rssi;
    send_ack(f);
    ESP_LOGI(TAG, "GUARD_CONFIG baseline=%us duration=%us radius=%ddBm",
             gc->baseline_s, gc->duration_s, gc->radius_rssi);
}

static void handle(const dp_rx_frame_t *f)
{
    peer_note(f->hdr.node_id, f->rssi);
    switch (f->hdr.type) {
        case DP_MSG_JOIN_ACCEPT:    on_join_accept(f);   break;
        case DP_MSG_JOIN_REJECT:    ESP_LOGW(TAG, "JOIN_REJECT"); break;
        case DP_MSG_MODE_SET:       on_mode_set(f);      break;
        case DP_MSG_CHANNEL_ASSIGN: on_channel_assign(f); break;
        case DP_MSG_GUARD_CONFIG:   on_guard_config(f);  break;
        case DP_MSG_NODE_PING:      break;
        case DP_MSG_LEAVE:
            ESP_LOGW(TAG, "removed by orchestrator; re-advertising");
            N.admitted = false; N.node_id = DP_NODE_UNASSIGNED;
            N.session_id = DP_SESSION_NONE; apply_mode(DP_MODE_IDLE);
            break;
        default:
            ESP_LOGD(TAG, "ignoring type 0x%02x", f->hdr.type);
            break;
    }
}

static void node_deactivate(void)
{
    if (N.admitted)
        dp_espnow_send(N.orch_mac, DP_MSG_LEAVE, 0,
                       N.session_id, N.node_id, next_seq(), NULL, 0);
    apply_mode(DP_MODE_IDLE);
    N.admitted   = false;
    N.node_id    = DP_NODE_UNASSIGNED;
    N.session_id = DP_SESSION_NONE;
    ESP_LOGI(TAG, "node mode STOPPED");
}

static void service_control(uint32_t ms)
{
    dp_sniffer_set_channel(CONTROL_CHANNEL);
    int64_t end = esp_timer_get_time() + (int64_t)ms * 1000;
    dp_rx_frame_t f;
    do {
        if (dp_espnow_rx(&f, 20)) handle(&f);
    } while (esp_timer_get_time() < end);
}

static void scan_assigned(void)
{
    const uint8_t *chans = N.chan_count ? N.channels : DEFAULT_CHANNELS;
    int count = N.chan_count ? N.chan_count : (int)sizeof(DEFAULT_CHANNELS);
    uint16_t dwell = N.dwell_ms ? N.dwell_ms : DEFAULT_DWELL_MS;
    for (int i = 0; i < count; i++) {
        dp_sniffer_set_channel(chans[i]);
        vTaskDelay(pdMS_TO_TICKS(dwell));
    }
}

static void node_task(void *arg)
{
    (void)arg;
    int64_t last_beat = 0, last_mesh = 0;

    for (;;) {

        if (!s_active) {
            if (N.admitted || N.scanning) node_deactivate();
            vTaskDelay(pdMS_TO_TICKS(120));
            continue;
        }

        service_control(SERVICE_MS);

        int64_t now = esp_timer_get_time();
        if (!N.admitted) {
            if (now - last_beat >= HEARTBEAT_US) { last_beat = now; send_join_request(); }
            continue;
        }

        flush_records();
        if (N.mode == DP_MODE_GUARD) {
            guard_resend();
            if (now - last_mesh >= 1500000LL) {
                last_mesh = now; send_node_ping(); send_peer_report();
            }
        }
        if (now - last_beat >= HEARTBEAT_US) { last_beat = now; send_heartbeat(); }

        if (N.scanning && N.mode == DP_MODE_WALK) scan_assigned();
    }
}

static void button_task(void *arg)
{
    (void)arg;
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << PIN_BOOT,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&io);

    bool prev_down = false;
    for (;;) {
        bool down = gpio_get_level(PIN_BOOT) == 0;
        if (down && !prev_down) {
            vTaskDelay(pdMS_TO_TICKS(BTN_DEBOUNCE_MS));
            if (gpio_get_level(PIN_BOOT) == 0) {
                s_active = !s_active;
                ESP_LOGI(TAG, "button: node mode %s", s_active ? "START" : "STOP");
                while (gpio_get_level(PIN_BOOT) == 0)
                    vTaskDelay(pdMS_TO_TICKS(20));
            }
        }
        prev_down = down;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void draw_centered(int y, const char *s, uint16_t fg, uint8_t scale)
{
    int cw = scale < 2 ? 6 : 12;
    int x = (DISPLAY_W - (int)strlen(s) * cw) / 2;
    if (x < 0) x = 0;
    display_draw_string(x, y, s, fg, COLOR_NEARBLACK, scale);
}

static void render_idle(void)
{
    char mac[20];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X", s_self_mac[3], s_self_mac[4], s_self_mac[5]);
    display_clear(COLOR_NEARBLACK);
    display_blit_sitting(2);
    draw_centered(40, "SNIFFCHECK", COLOR_HEADER, 1);
    draw_centered(50, "NODE", COLOR_WHITE, 1);
    draw_centered(62, mac, rgb565be(160, 160, 160), 1);
    draw_centered(72, "[btn] start", rgb565be(0x00, 0xFF, 0x00), 1);
}

static void render_active_status(char *last, size_t lastsz)
{
    char l1[28], l2[28], line[56];
    if (N.admitted) snprintf(l1, sizeof(l1), "node %u %s", N.node_id, mode_name(N.mode));
    else            snprintf(l1, sizeof(l1), "joining...");
    snprintf(l2, sizeof(l2), "seen %lu", (unsigned long)dp_sniffer_unique_count());
    snprintf(line, sizeof(line), "%s|%s", l1, l2);
    if (strncmp(line, last, lastsz) == 0) return;
    strlcpy(last, line, lastsz);

    const int y = 44;
    display_fill_rect(0, y, DISPLAY_W, DISPLAY_H - y, COLOR_NEARBLACK);
    draw_centered(y,      l1, N.admitted ? rgb565be(0x00, 0xFF, 0x00) : COLOR_WHITE, 1);
    draw_centered(y + 12, l2, COLOR_HEADER, 1);
    draw_centered(y + 26, "[btn] stop", rgb565be(160, 160, 160), 1);
}

static void ui_task(void *arg)
{
    (void)arg;

    for (int f = 0; f < 20; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(80)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(1400));

    int  prev_state = -1;
    bool drawn = false;
    int  x = display_scan_walk_x_min(), xmax = display_scan_walk_x_max();
    int  dir = 1, frame = 0;
    char last[56] = "";

    for (;;) {

        int state = !s_active ? 0 : ((N.scanning || N.ble_on) ? 2 : 1);
        if (state != prev_state) { drawn = false; prev_state = state; last[0] = '\0'; }

        if (state == 0) {
            if (!drawn) { render_idle(); drawn = true; }
            vTaskDelay(pdMS_TO_TICKS(150));
            continue;
        }

        if (state == 1) {
            if (!drawn) {
                display_clear(COLOR_NEARBLACK);
                display_blit_sitting_scaled(2, 2);
                drawn = true;
            }
            render_active_status(last, sizeof(last));
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (!drawn) { display_clear(COLOR_NEARBLACK); drawn = true; }
        display_scan_walk_frame(x, dir < 0, frame);
        frame ^= 1;
        x += dir * 8;
        if (x >= xmax) { x = xmax; dir = -1; }
        if (x <= 0)    { x = 0;    dir =  1; }

        render_active_status(last, sizeof(last));
        vTaskDelay(pdMS_TO_TICKS(160));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "SniffCheck Node — boot");

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
    ESP_ERROR_CHECK(led_init(SPI_HOST));
    ESP_ERROR_CHECK(display_init(SPI_HOST));
    display_set_post_blit_cb(led_post_blit_guard);
    led_off();

    N.node_id    = DP_NODE_UNASSIGNED;
    N.session_id = DP_SESSION_NONE;
    N.mode       = DP_MODE_IDLE;

    s_active = true;

    ESP_ERROR_CHECK(dp_espnow_init());
    dp_sniffer_init();
    if (dp_ble_init() != ESP_OK)
        ESP_LOGW(TAG, "BLE init failed - Guard detection unavailable");
    dp_espnow_self_mac(s_self_mac);
    ESP_LOGI(TAG, "node MAC %02x:%02x:%02x:%02x:%02x:%02x — auto-started (button = stop/start)",
             s_self_mac[0], s_self_mac[1], s_self_mac[2],
             s_self_mac[3], s_self_mac[4], s_self_mac[5]);

    xTaskCreate(node_task,   "sniff_node", 4096, NULL, 5, NULL);
    xTaskCreate(button_task, "dp_button",  2048, NULL, 4, NULL);
    xTaskCreate(ui_task,     "dp_ui",      4096, NULL, 4, NULL);
}
