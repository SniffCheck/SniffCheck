#include "usb_console.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const char *TAG = "sc_usb";

static usb_cmd_cb_t s_cmd_cb = NULL;

esp_err_t usb_console_init(void)
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    ESP_LOGI(TAG, "USB console ready — commands: connect <ssid> [pass] | disconnect | status");
    return ESP_OK;
}

void usb_console_set_cmd_cb(usb_cmd_cb_t cb)
{
    s_cmd_cb = cb;
}

static void dispatch_line(char *line)
{

    while (*line && isspace((unsigned char)*line)) line++;
    if (!*line) return;

    char *cmd = line;
    char *args = line;
    while (*args && !isspace((unsigned char)*args)) args++;
    if (*args) {
        *args = '\0';
        args++;
        while (*args && isspace((unsigned char)*args)) args++;
    }

    if (s_cmd_cb)
        s_cmd_cb(cmd, args);
    else
        ESP_LOGI(TAG, "rx: %s %s", cmd, args);
}

void usb_console_task(void *arg)
{
    static char line[128];
    int pos = 0;

    for (;;) {
        int c = fgetc(stdin);
        if (c == EOF) {
            vTaskDelay(1);
            continue;
        }

        if (c == '\r' || c == '\n') {
            if (pos > 0) {
                line[pos] = '\0';
                dispatch_line(line);
                pos = 0;
            }
        } else if (c == 0x08 || c == 0x7F) {
            if (pos > 0) pos--;
        } else {
            if (pos < (int)sizeof(line) - 1)
                line[pos++] = (char)c;
        }
    }
}
