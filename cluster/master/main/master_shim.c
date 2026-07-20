#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "capture_writer.h"
#include "sta_tracker.h"
#include "wifi_csi_probe.h"
#include "pcap_capture.h"
#include "app_settings.h"
#include "master_shim.h"

static const char *TAG = "master-shim";

#define CL_SCHEMA_VERSION "1.30.0"
static char     s_session_id[24] = "cluster-0000";
static char     s_fw_version[24]  = "cluster-0.2";
static uint16_t s_last_scan;

void master_shim_set_session(const char *id, const char *fw)
{
    if (id) strlcpy(s_session_id, id, sizeof(s_session_id));
    if (fw) strlcpy(s_fw_version, fw, sizeof(s_fw_version));
}
void master_shim_set_last_scan(uint16_t s) { s_last_scan = s; }

const char *capture_writer_session_id(void)     { return s_session_id; }
const char *capture_writer_fw_version(void)      { return s_fw_version; }
const char *capture_writer_schema_version(void)  { return CL_SCHEMA_VERSION; }
uint16_t    capture_writer_last_scan(void)       { return s_last_scan; }

void capture_emit_header(void) {}
void capture_emit_codebook(void) {}
void capture_emit_footer(capture_end_reason_t reason, uint32_t a, uint32_t b,
                         uint32_t c, uint32_t d, uint32_t e, uint32_t f)
{ (void)reason;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f; }
void capture_emit_byos_mac(const uint8_t mac[6], uint16_t si, uint32_t iid,
                           uint16_t iidx, const capture_byos_sight_t *s, uint8_t n)
{ (void)mac;(void)si;(void)iid;(void)iidx;(void)s;(void)n; }
void capture_emit_byos_wifi(const uint8_t b[6], uint16_t si, uint32_t iid, uint16_t iidx,
                            const char *ssid, uint8_t ch, const char *auth,
                            const capture_byos_sight_t *s, uint8_t n)
{ (void)b;(void)si;(void)iid;(void)iidx;(void)ssid;(void)ch;(void)auth;(void)s;(void)n; }
void capture_emit_byos_ble(const uint8_t a[6], uint16_t si, uint32_t iid, uint16_t iidx,
                           const char *name, const capture_byos_sight_t *s, uint8_t n)
{ (void)a;(void)si;(void)iid;(void)iidx;(void)name;(void)s;(void)n; }

uint16_t sta_tracker_entry_count(void)  { return 0; }
uint16_t sta_tracker_camera_count(void) { return 0; }
const sta_entry_t *sta_tracker_at(uint16_t idx) { (void)idx; return NULL; }
const wifi_csi_result_t *wifi_csi_probe_last(void) { return NULL; }
const pcap_meta_t *pcap_capture_meta(void) { return NULL; }
const uint8_t *pcap_capture_data(size_t *len_out) { if (len_out) *len_out = 0; return NULL; }

static bool s_adv_mode = true;

void app_settings_get_json(char *buf, size_t buflen)
{
    snprintf(buf, buflen,
        "{\"mode\":\"%s\",\"brightness\":100,\"led\":true,\"cluster\":true}",
        s_adv_mode ? "adv" : "regular");
}
bool app_settings_set_mode(bool adv)          { s_adv_mode = adv; return true; }
bool app_settings_set_brightness_pct(int pct) { (void)pct; return true; }
bool app_settings_set_led(bool en)            { (void)en; return true; }

void app_request_scan_after_download(void)    { master_on_rescan_request(); }
int  app_scan_eta_seconds(void)               { return 40; }
void app_request_walk_after_download(void)    { master_on_walk_request(true); }
void app_request_sta_capture_after_download(uint8_t ch, uint16_t s) { (void)ch;(void)s; }
void app_request_csi_after_download(uint8_t ch, uint16_t s)         { (void)ch;(void)s; }
void app_request_pcap_after_download(const uint8_t *ch, uint8_t n)  { (void)ch;(void)n; }
void app_scan_channels_json(char *buf, size_t buflen) { snprintf(buf, buflen, "[]"); }
