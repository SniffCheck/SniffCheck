#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void app_settings_get_json(char *buf, size_t buflen);

bool app_settings_set_mode(bool adv);
bool app_settings_set_brightness_pct(int pct);
bool app_settings_set_led(bool enabled);

void app_request_scan_after_download(void);

/* Rough upper-bound seconds a WebAP-triggered full rescan will take, so the
 * browser can show a reconnect countdown while the AP is down. */
int app_scan_eta_seconds(void);

void app_request_walk_after_download(void);

void app_request_sta_capture_after_download(uint8_t channel, uint16_t seconds);
void app_request_csi_after_download(uint8_t channel, uint16_t seconds);

void app_request_pcap_after_download(const uint8_t *channels, uint8_t n);

void app_scan_channels_json(char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif
