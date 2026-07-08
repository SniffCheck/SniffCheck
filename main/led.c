#include "led.h"
#include "driver/spi_master.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include <string.h>

#define LED_CLK_HZ  (10 * 1000 * 1000)
#define LED_COUNT   1
#define FRAME_BYTES (4 + LED_COUNT * 4 + 4)

static const char *TAG = "sc_led";
static spi_device_handle_t s_dev;

esp_err_t led_init(spi_host_device_t host)
{
    spi_device_interface_config_t cfg = {
        .clock_speed_hz = LED_CLK_HZ,
        .mode           = 0,
        .spics_io_num   = -1,
        .queue_size     = 1,
    };
    esp_err_t err = spi_bus_add_device(host, &cfg, &s_dev);
    if (err == ESP_OK) {

        led_off();
        ESP_LOGI(TAG, "APA102 ready");
    }
    return err;
}

void led_set(uint8_t r, uint8_t g, uint8_t b, uint8_t brightness)
{
    uint8_t *buf = heap_caps_malloc(FRAME_BYTES, MALLOC_CAP_DMA);
    if (!buf) {
        ESP_LOGE(TAG, "alloc failed");
        return;
    }
    memset(buf, 0, FRAME_BYTES);
    buf[4] = 0xE0 | (brightness & 0x1F);
    buf[5] = b;
    buf[6] = g;
    buf[7] = r;
    spi_transaction_t t = {
        .length    = FRAME_BYTES * 8,
        .tx_buffer = buf,
    };
    spi_device_transmit(s_dev, &t);
    heap_caps_free(buf);
}

void led_off(void)
{
    led_set(0, 0, 0, 0);
}
