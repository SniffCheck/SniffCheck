#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "driver/spi_master.h"
#include "driver/i2c_slave.h"

#include "cluster_pins.h"
#include "cluster_proto.h"
#include "node_display.h"
#include "led.h"
#include "arm_scan.h"

#ifndef ARM_INDEX
#error "build with -DARM_INDEX=1 or -DARM_INDEX=2 (both sweep half of 2.4+5 GHz + BLE)"
#endif

#define ARM_BAND   ((ARM_INDEX) == 1 ? CL_BAND_24_BLE : CL_BAND_5_BLE)
#define ARM_ADDR   CL_ARM_ADDR(ARM_INDEX)
#define BAND_LABEL ((ARM_INDEX) == 1 ? "2.4+5 A/BLE" : "2.4+5 B/BLE")

static const char *TAG = "cluster-arm";

static cl_status_t   s_status;
static uint32_t      s_scan_seq;

static volatile bool s_req_scan, s_req_scan_adv, s_req_walk, s_req_walk_stop;

static volatile bool s_have_plan;
static cl_plan_t     s_pending_plan;

static volatile bool     s_serve_chunk;
static const uint8_t    *s_snap_ptr;
static volatile uint32_t s_snap_total, s_snap_seq, s_chunk_off;

static i2c_slave_dev_handle_t s_slave;
static QueueHandle_t s_txq;
static volatile uint32_t s_reads;

static void led_blank_cb(void) { led_off(); }

static void status_publish(uint8_t state, uint16_t wifi_seen, uint16_t ble_seen)
{
    s_status.arm_index     = ARM_INDEX;
    s_status.band          = ARM_BAND;
    s_status.state         = state;
    s_status.wifi_seen     = wifi_seen;
    s_status.ble_seen      = ble_seen;
    s_status.scan_seq      = s_scan_seq;
    s_status.scanset_len   = arm_scanset_len();
    s_status.scanset_ready = (arm_scanset_len() > 0) ? 1 : 0;
    cl_status_seal(&s_status);
}

static bool IRAM_ATTR on_receive_cb(i2c_slave_dev_handle_t dev,
                                    const i2c_slave_rx_done_event_data_t *evt, void *arg)
{
    (void)dev; (void)arg;
    if (!evt || !evt->buffer || evt->length < sizeof(cl_cmd_frame_t)) return false;

    if (evt->buffer[1] == (uint8_t)CL_CMD_GET_SCANSET) {
        if (evt->length < sizeof(cl_getreq_t)) return false;
        const cl_getreq_t *g = (const cl_getreq_t *)evt->buffer;
        if (!cl_getreq_valid(g)) return false;
        if (g->offset == 0) {
            s_snap_ptr   = arm_scanset_ptr();
            s_snap_total = arm_scanset_len();
            s_snap_seq   = s_scan_seq;
        }
        s_chunk_off   = g->offset;
        s_serve_chunk = true;
        return false;
    }

    if (evt->buffer[1] == (uint8_t)CL_CMD_SET_PLAN) {
        if (evt->length < sizeof(cl_plan_t)) return false;
        const cl_plan_t *p = (const cl_plan_t *)evt->buffer;
        if (!cl_plan_valid(p)) return false;
        s_pending_plan = *p;
        s_have_plan    = true;
        return false;
    }

    const cl_cmd_frame_t *f = (const cl_cmd_frame_t *)evt->buffer;
    if (!cl_cmd_valid(f)) return false;
    switch (f->cmd) {
    case CL_CMD_SCAN:
        s_req_scan = true; s_req_scan_adv = (f->arg == CL_SCAN_ADV);
        break;
    case CL_CMD_WALK:
        if (f->arg) s_req_walk = true; else s_req_walk_stop = true;
        break;
    default: break;
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

static void arm_tx_task(void *arg)
{
    (void)arg;
    static cl_chunk_t chunk;
    uint8_t ev;
    for (;;) {
        if (xQueueReceive(s_txq, &ev, portMAX_DELAY) != pdTRUE) continue;
        uint32_t written = 0;

        if (s_serve_chunk) {
            memset(&chunk, 0, sizeof(chunk));
            chunk.type      = CL_RESP_CHUNK;
            chunk.scan_seq  = s_snap_seq;
            chunk.total_len = s_snap_total;
            chunk.offset    = s_chunk_off;
            uint16_t len = 0;
            if (s_snap_ptr && s_chunk_off < s_snap_total) {
                uint32_t rem = s_snap_total - s_chunk_off;
                len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
                memcpy(chunk.payload, s_snap_ptr + s_chunk_off, len);
            }
            chunk.len = len;
            cl_chunk_seal(&chunk);
            s_serve_chunk = false;
            i2c_slave_write(s_slave, (const uint8_t *)&chunk, sizeof(chunk), &written, 100);
        } else {
            cl_status_t snap = s_status;
            i2c_slave_write(s_slave, (const uint8_t *)&snap, sizeof(snap), &written, 100);
        }
    }
}

static void i2c_slave_setup(void)
{
    s_txq = xQueueCreate(8, sizeof(uint8_t));
    i2c_slave_config_t cfg = {
        .i2c_port          = CL_I2C_PORT,
        .sda_io_num        = CL_I2C_SDA_GPIO,
        .scl_io_num        = CL_I2C_SCL_GPIO,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .send_buf_depth    = 512,
        .receive_buf_depth = 128,
        .slave_addr        = ARM_ADDR,
        .addr_bit_len      = I2C_ADDR_BIT_LEN_7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_slave_device(&cfg, &s_slave));
    i2c_slave_event_callbacks_t cbs = { .on_request = on_request_cb, .on_receive = on_receive_cb };
    ESP_ERROR_CHECK(i2c_slave_register_event_callbacks(s_slave, &cbs, NULL));
    xTaskCreate(arm_tx_task, "arm_tx", 4096, NULL, 7, NULL);
    ESP_LOGI(TAG, "I2C slave up: addr 0x%02x band %s SDA=%d SCL=%d",
             ARM_ADDR, BAND_LABEL, CL_I2C_SDA_GPIO, CL_I2C_SCL_GPIO);
}

static void render_screen(const char *state_txt, uint16_t wifi, uint16_t ble)
{
    char l[24];
    display_clear(COLOR_NEARBLACK);
    display_blit_sitting_scaled(2, 2);
    snprintf(l, sizeof(l), "ARM %d", ARM_INDEX);
    int x = (DISPLAY_W - (int)strlen(l) * 12) / 2;
    display_draw_string(x < 0 ? 0 : x, 40, l, COLOR_HEADER, COLOR_NEARBLACK, 2);
    int bx = (DISPLAY_W - (int)strlen(BAND_LABEL) * 6) / 2;
    display_draw_string(bx < 0 ? 0 : bx, 58, BAND_LABEL, COLOR_GREEN, COLOR_NEARBLACK, 1);
    display_draw_string(2, 70, state_txt, COLOR_AMBER, COLOR_NEARBLACK, 1);
    snprintf(l, sizeof(l), "W%u B%u", (unsigned)wifi, (unsigned)ble);
    display_draw_string(DISPLAY_W - (int)strlen(l) * 6 - 2, 70, l, COLOR_WHITE,
                        COLOR_NEARBLACK, 1);
}

static void scan_task(void *arg)
{
    (void)arg;

    for (int f = 0; f < 10; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(160)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(1200));

    arm_scan_init(ARM_INDEX);

    uint16_t wifi = 0, ble = 0;

    ESP_LOGI(TAG, "boot adv scan…");
    status_publish(CL_STATE_SCANNING, 0, 0);
    render_screen("boot scan", 0, 0);
    arm_scan_run(true, &wifi, &ble);
    s_scan_seq++;
    status_publish(CL_STATE_IDLE, wifi, ble);
    render_screen("ready", wifi, ble);

    for (;;) {
        if (s_have_plan) {
            s_have_plan = false;
            arm_scan_set_plan(&s_pending_plan);
        }
        if (s_req_walk) {
            s_req_walk = false; s_req_walk_stop = false;
            ESP_LOGI(TAG, "walk start");
            arm_walk_start();
            uint16_t wu = 0, bu = 0; uint32_t dur = 0;
            while (!s_req_walk_stop) {
                arm_walk_sweep(&wu, &bu, &dur);
                status_publish(CL_STATE_WALKING, wu, bu);
                render_screen("walk", wu, bu);
                if (dur >= (30 * 60)) break;
            }
            bool capped = false;
            arm_walk_finish(&capped, &wifi, &ble);
            s_scan_seq++;
            status_publish(CL_STATE_IDLE, wifi, ble);
            render_screen(capped ? "walk capped" : "walk done", wifi, ble);
        } else if (s_req_scan) {
            bool adv = s_req_scan_adv;
            s_req_scan = false;
            ESP_LOGI(TAG, "%s rescan…", adv ? "adv" : "regular");
            status_publish(CL_STATE_SCANNING, wifi, ble);
            render_screen(adv ? "adv scan" : "scan", wifi, ble);
            arm_scan_run(adv, &wifi, &ble);
            s_scan_seq++;
            status_publish(CL_STATE_IDLE, wifi, ble);
            render_screen("ready", wifi, ble);
        } else {
            status_publish(CL_STATE_IDLE, wifi, ble);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }
}

static void log_task(void *arg)
{
    (void)arg;
    int64_t last_log = 0;
    uint32_t last_reads = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_log >= 2000000LL) {
            last_log = now;
            uint32_t r = s_reads;
            ESP_LOGI(TAG, "ARM%d 0x%02x %s st=%u seq=%lu ss=%luB reads=%lu(+%lu)",
                     ARM_INDEX, ARM_ADDR, BAND_LABEL, s_status.state,
                     (unsigned long)s_scan_seq, (unsigned long)arm_scanset_len(),
                     (unsigned long)r, (unsigned long)(r - last_reads));
            last_reads = r;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "SniffCheck Cluster ARM %d (%s) boot", ARM_INDEX, BAND_LABEL);

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

    memset(&s_status, 0, sizeof(s_status));
    status_publish(CL_STATE_IDLE, 0, 0);
    i2c_slave_setup();
    xTaskCreate(log_task,  "arm_log",  3072, NULL, 4, NULL);
    xTaskCreate(scan_task, "arm_scan", 8192, NULL, 6, NULL);
}
