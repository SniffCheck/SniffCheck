#include "dp_espnow.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_netif.h"

static const char *TAG = "dp_espnow";

#define DP_CONTROL_CHANNEL  1

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static QueueHandle_t s_rx_queue;

uint16_t dp_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

static void rx_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (!info || !data) return;
    if (len < (int)(DP_HEADER_LEN + DP_CRC_LEN) || len > DP_FRAME_MAX) return;

    if (data[0] != DP_MAGIC_0 || data[1] != DP_MAGIC_1 ||
        data[2] != DP_MAGIC_2 || data[3] != DP_MAGIC_3) return;
    if (data[4] != DP_PROTO_VERSION) return;

    size_t crc_off = (size_t)len - DP_CRC_LEN;
    uint16_t want = (uint16_t)data[crc_off] | ((uint16_t)data[crc_off + 1] << 8);
    if (dp_crc16(data, crc_off) != want) return;

    dp_rx_frame_t f;
    memcpy(f.src_mac, info->src_addr, 6);
    f.rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0;
    memcpy(&f.hdr, data, DP_HEADER_LEN);
    f.payload_len = (uint8_t)(crc_off - DP_HEADER_LEN);
    if (f.payload_len) memcpy(f.payload, data + DP_HEADER_LEN, f.payload_len);

    if (xQueueSend(s_rx_queue, &f, 0) != pdTRUE)
        ESP_LOGW(TAG, "rx queue full, dropping type 0x%02x", f.hdr.type);
}

static void tx_cb(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    if (status != ESP_NOW_SEND_SUCCESS && info && info->des_addr) {
        const uint8_t *m = info->des_addr;
        ESP_LOGD(TAG, "tx to %02x:%02x:%02x:%02x:%02x:%02x failed (MAC layer)",
                 m[0], m[1], m[2], m[3], m[4], m[5]);
    }
}

static esp_err_t espnow_bringup(void)
{
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_channel(DP_CONTROL_CHANNEL, WIFI_SECOND_CHAN_NONE));

    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(rx_cb));
    ESP_ERROR_CHECK(esp_now_register_send_cb(tx_cb));

    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = DP_CONTROL_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = false;
    ESP_ERROR_CHECK(esp_now_add_peer(&peer));
    return ESP_OK;
}

esp_err_t dp_espnow_init(void)
{
    s_rx_queue = xQueueCreate(16, sizeof(dp_rx_frame_t));
    if (!s_rx_queue) return ESP_ERR_NO_MEM;

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(espnow_bringup());

    uint8_t mac[6];
    dp_espnow_self_mac(mac);
    ESP_LOGI(TAG, "ESP-NOW up on ch%d, self %02x:%02x:%02x:%02x:%02x:%02x",
             DP_CONTROL_CHANNEL, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ESP_OK;
}

void dp_espnow_suspend(void)
{
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    esp_now_deinit();
    ESP_LOGI(TAG, "ESP-NOW suspended (radio handed to service mode)");
}

esp_err_t dp_espnow_resume(void)
{
    esp_err_t err = espnow_bringup();
    ESP_LOGI(TAG, "ESP-NOW resumed on ch%d (%s)", DP_CONTROL_CHANNEL, esp_err_to_name(err));
    return err;
}

void dp_espnow_self_mac(uint8_t mac_out[6])
{
    esp_wifi_get_mac(WIFI_IF_STA, mac_out);
}

bool dp_espnow_rx(dp_rx_frame_t *out, uint32_t timeout_ms)
{
    if (!out) return false;
    return xQueueReceive(s_rx_queue, out, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

esp_err_t dp_espnow_add_peer(const uint8_t mac[6])
{
    if (esp_now_is_peer_exist(mac)) return ESP_OK;
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = DP_CONTROL_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = false;
    return esp_now_add_peer(&peer);
}

esp_err_t dp_espnow_del_peer(const uint8_t mac[6])
{
    if (!esp_now_is_peer_exist(mac)) return ESP_OK;
    return esp_now_del_peer(mac);
}

esp_err_t dp_espnow_send(const uint8_t *dst_mac,
                         dp_msg_type_t type,
                         uint8_t extra_flags,
                         uint32_t session_id,
                         uint16_t node_id,
                         uint16_t seq,
                         const void *payload,
                         uint8_t payload_len)
{
    if (payload_len > DP_PAYLOAD_MAX) return ESP_ERR_INVALID_SIZE;

    uint8_t frame[DP_FRAME_MAX];
    dp_header_t *h = (dp_header_t *)frame;
    h->magic[0] = DP_MAGIC_0; h->magic[1] = DP_MAGIC_1;
    h->magic[2] = DP_MAGIC_2; h->magic[3] = DP_MAGIC_3;
    h->version    = DP_PROTO_VERSION;
    h->type       = (uint8_t)type;
    h->flags      = extra_flags | (dst_mac ? 0 : DP_FLAG_BROADCAST);
    h->reserved   = 0;
    h->session_id = session_id;
    h->node_id    = node_id;
    h->sequence   = seq;

    if (payload_len && payload)
        memcpy(frame + DP_HEADER_LEN, payload, payload_len);

    size_t crc_off = DP_HEADER_LEN + payload_len;
    uint16_t crc = dp_crc16(frame, crc_off);
    frame[crc_off]     = (uint8_t)(crc & 0xFF);
    frame[crc_off + 1] = (uint8_t)(crc >> 8);

    const uint8_t *dst = dst_mac ? dst_mac : BROADCAST_MAC;
    return esp_now_send(dst, frame, crc_off + DP_CRC_LEN);
}
