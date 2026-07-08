

#include "pcap_capture.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_heap_caps.h"

static const char *TAG = "pcap";

#define PCAP_BUF_PREFERRED   (1024 * 1024)
#define PCAP_BUF_FALLBACK    (512  * 1024)
#define PCAP_SNAP_LEN        2048

#define DLT_IEEE802_11_RADIOTAP   127

#define PCAP_SETTLE_MS       20

static uint8_t        *s_buf;
static size_t          s_cap;
static volatile size_t s_len;
static volatile bool   s_active;
static volatile uint8_t  s_req_channel;
static volatile uint32_t s_hop_ms;
static pcap_meta_t     s_meta;

static void put_u16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static void write_global_header(void)
{
    uint8_t h[24];
    put_u32(h + 0,  0xa1b2c3d4);
    put_u16(h + 4,  2);
    put_u16(h + 6,  4);
    put_u32(h + 8,  0);
    put_u32(h + 12, 0);
    put_u32(h + 16, PCAP_SNAP_LEN);
    put_u32(h + 20, DLT_IEEE802_11_RADIOTAP);
    memcpy(s_buf, h, sizeof(h));
    s_len = sizeof(h);
}

#define RT_PRESENT  ((1u << 1) | (1u << 3) | (1u << 5))
#define RT_LEN      15
#define RT_F_FCS    0x10 

static uint16_t chan_to_freq(uint8_t ch, bool band5)
{
    if (band5)     return 5000 + ch * 5;
    if (ch == 14)  return 2484;
    return 2407 + ch * 5;
}

static void build_radiotap(uint8_t *out, uint8_t channel, int8_t rssi)
{
    bool     band5  = channel > 14;
    uint16_t freq   = chan_to_freq(channel, band5);
    uint16_t cflags = band5 ? 0x0140
                            : 0x00A0;
    out[0] = 0; out[1] = 0;
    put_u16(out + 2, RT_LEN);
    put_u32(out + 4, RT_PRESENT);
    out[8]  = RT_F_FCS;
    out[9]  = 0;
    put_u16(out + 10, freq);
    put_u16(out + 12, cflags);
    out[14] = (uint8_t)rssi;
}

static void append_frame(const uint8_t *frame, uint16_t orig_len,
                         uint8_t channel, int8_t rssi, int64_t ts_us)
{
    uint16_t snap  = orig_len;
    bool     trunc = false;
    if (snap > PCAP_SNAP_LEN) { snap = PCAP_SNAP_LEN; trunc = true; }

    size_t need = 16 + RT_LEN + snap;
    if (s_len + need > s_cap) {
        s_meta.dropped++;
        s_active = false;
        return;
    }

    uint8_t *p = s_buf + s_len;
    uint32_t ts_sec  = (uint32_t)(ts_us / 1000000);
    uint32_t ts_usec = (uint32_t)(ts_us % 1000000);
    put_u32(p + 0,  ts_sec);
    put_u32(p + 4,  ts_usec);
    put_u32(p + 8,  RT_LEN + snap);
    put_u32(p + 12, RT_LEN + orig_len);
    build_radiotap(p + 16, channel, rssi);
    memcpy(p + 16 + RT_LEN, frame, snap);

    s_len += need;
    s_meta.packets++;
    if (trunc) s_meta.truncated++;
}

static void cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    if (!s_active || !buf) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    if (now - s_hop_ms < PCAP_SETTLE_MS) return;
    if (s_req_channel && pkt->rx_ctrl.channel != s_req_channel) return;

    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 4) return;
    append_frame(pkt->payload, len, pkt->rx_ctrl.channel,
                 pkt->rx_ctrl.rssi, esp_timer_get_time());
}

esp_err_t pcap_capture_init(void)
{
    s_buf = heap_caps_malloc(PCAP_BUF_PREFERRED, MALLOC_CAP_SPIRAM);
    if (s_buf) {
        s_cap = PCAP_BUF_PREFERRED;
    } else {
        s_buf = heap_caps_malloc(PCAP_BUF_FALLBACK, MALLOC_CAP_SPIRAM);
        if (s_buf) {
            s_cap = PCAP_BUF_FALLBACK;
            ESP_LOGW(TAG, "pcap buffer fell back to %u bytes", (unsigned)s_cap);
        }
    }
    if (!s_buf) {
        ESP_LOGE(TAG, "PSRAM pcap buffer alloc failed");
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "pcap buffer: %u bytes PSRAM", (unsigned)s_cap);
    return ESP_OK;
}

esp_err_t pcap_capture_run(const uint8_t *channels, uint8_t n,
                           uint16_t secs, uint32_t scan_id)
{
    memset(&s_meta, 0, sizeof(s_meta));
    s_meta.ran     = true;
    s_meta.scan_id = scan_id;

    if (!s_buf)               { s_meta.status = PCAP_FAILED; return ESP_ERR_NO_MEM; }
    if (!channels || n == 0)  { s_meta.status = PCAP_FAILED; return ESP_ERR_INVALID_ARG; }
    if (n > PCAP_MAX_CHANNELS) n = PCAP_MAX_CHANNELS;

    s_meta.status              = PCAP_RUNNING;
    s_meta.seconds_per_channel = secs;
    s_meta.channel_count       = n;
    memcpy(s_meta.channels, channels, n);

    write_global_header();

    wifi_promiscuous_filter_t filt = { .filter_mask =
        WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA |
        WIFI_PROMIS_FILTER_MASK_CTRL };
    esp_wifi_set_promiscuous_filter(&filt);
    wifi_promiscuous_filter_t cfilt = { .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_ctrl_filter(&cfilt);
    esp_wifi_set_promiscuous_rx_cb(cb);

    s_active = true;
    esp_wifi_set_promiscuous(true);

    int64_t t0 = esp_timer_get_time();
    for (uint8_t i = 0; i < n && s_active; i++) {

        s_hop_ms      = (uint32_t)(esp_timer_get_time() / 1000);
        s_req_channel = channels[i];
        esp_wifi_set_channel(channels[i], WIFI_SECOND_CHAN_NONE);

        for (uint16_t e = 0; e < (uint16_t)(secs * 10) && s_active; e++)
            vTaskDelay(pdMS_TO_TICKS(100));
    }

    bool cap_hit  = !s_active;
    s_req_channel = 0;
    s_active      = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    s_meta.duration_s = (uint32_t)((esp_timer_get_time() - t0) / 1000000);
    s_meta.bytes      = (uint32_t)s_len;
    s_meta.status     = cap_hit ? PCAP_PARTIAL : PCAP_READY;

    ESP_LOGI(TAG, "pcap done: %u ch, %lu pkts, %lu bytes, %lu dropped, %lu trunc, %s",
             (unsigned)n, (unsigned long)s_meta.packets,
             (unsigned long)s_meta.bytes, (unsigned long)s_meta.dropped,
             (unsigned long)s_meta.truncated, cap_hit ? "PARTIAL" : "READY");
    return ESP_OK;
}

const pcap_meta_t *pcap_capture_meta(void) { return &s_meta; }

const uint8_t *pcap_capture_data(size_t *len_out)
{
    if (len_out) *len_out = (s_meta.ran && s_len > 24) ? s_len : 0;
    return s_buf;
}
