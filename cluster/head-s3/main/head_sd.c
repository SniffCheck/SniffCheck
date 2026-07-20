#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"

#include "head_sd.h"
#include "head_pins.h"

static const char *TAG = "head-sd";

#define SD_MOUNT   "/sdcard"
#define SD_DIR     "/sdcard/sniffcheck"

#define SD_RESERVE_BYTES   (8ULL * 1024 * 1024)
#define SD_FREE_CHECK_US   (10LL * 1000 * 1000)

static sdmmc_card_t *s_card;
static FILE         *s_fp;
static head_sd_stats_t s_st;
static int64_t       s_last_flush_us;
static int64_t       s_last_free_us;
static uint32_t      s_unflushed;

bool head_sd_ok(void) { return s_st.mounted && s_fp && !s_st.full; }

static void head_sd_refresh_free(void)
{
    uint64_t total = 0, freeb = 0;
    if (esp_vfs_fat_info(SD_MOUNT, &total, &freeb) != ESP_OK) return;
    s_st.free_bytes = freeb;
    bool was_full = s_st.full;
    s_st.full = s_st.free_bytes < SD_RESERVE_BYTES;
    if (s_st.full && !was_full)
        ESP_LOGW(TAG, "card near full (%.1f MB free < %llu MB reserve) — store paused, "
                 "ring-only until space frees", (double)s_st.free_bytes / 1e6,
                 (unsigned long long)(SD_RESERVE_BYTES / (1024 * 1024)));
    else if (!s_st.full && was_full)
        ESP_LOGI(TAG, "card space recovered (%.1f MB free) — store resumed",
                 (double)s_st.free_bytes / 1e6);
    s_last_free_us = esp_timer_get_time();
}

esp_err_t head_sd_mount(void)
{
    memset(&s_st, 0, sizeof(s_st));

    esp_vfs_fat_sdmmc_mount_config_t mcfg = {
        .format_if_mount_failed = false,
        .max_files              = 4,
        .allocation_unit_size   = 16 * 1024,
    };

    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = 4;
    slot.clk = HEAD_SD_CLK_GPIO;
    slot.cmd = HEAD_SD_CMD_GPIO;
    slot.d0  = HEAD_SD_D0_GPIO;
    slot.d1  = HEAD_SD_D1_GPIO;
    slot.d2  = HEAD_SD_D2_GPIO;
    slot.d3  = HEAD_SD_D3_GPIO;
    slot.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

    esp_err_t err = esp_vfs_fat_sdmmc_mount(SD_MOUNT, &host, &slot, &mcfg, &s_card);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mount failed: %s (card FAT32-formatted & seated?)",
                 esp_err_to_name(err));
        return err;
    }
    s_st.mounted    = true;
    s_st.card_bytes = (uint64_t)s_card->csd.capacity * s_card->csd.sector_size;
    ESP_LOGI(TAG, "SD mounted: %s %.1f GB", s_card->cid.name,
             (double)s_st.card_bytes / 1e9);

    mkdir(SD_DIR, 0777);

    snprintf(s_st.path, sizeof(s_st.path), SD_DIR "/cap_%08llx.jsonl",
             (unsigned long long)(esp_timer_get_time() / 1000));
    s_fp = fopen(s_st.path, "a");
    if (!s_fp) {
        ESP_LOGE(TAG, "cannot open %s", s_st.path);
        s_st.mounted = false;
        esp_vfs_fat_sdcard_unmount(SD_MOUNT, s_card);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "capture file: %s", s_st.path);
    head_sd_refresh_free();
    ESP_LOGI(TAG, "SD free: %.1f GB of %.1f GB", (double)s_st.free_bytes / 1e9,
             (double)s_st.card_bytes / 1e9);
    head_sd_append("{\"type\":\"info\",\"src\":\"head-sd\",\"msg\":\"store opened\"}", 55);
    head_sd_flush();
    return ESP_OK;
}

void head_sd_append(const char *line, size_t len)
{
    if (!s_fp || !line || len == 0) return;
    if (s_st.full) return;
    size_t w = fwrite(line, 1, len, s_fp);
    if (w != len) { s_st.write_errors++; return; }
    fputc('\n', s_fp);
    s_st.written_bytes += len + 1;
    s_st.records++;
    if (++s_unflushed >= 32) head_sd_flush();
}

void head_sd_flush(void)
{
    if (!s_fp) return;
    int64_t now = esp_timer_get_time();

    if (now - s_last_free_us >= SD_FREE_CHECK_US) head_sd_refresh_free();
    if (s_unflushed == 0) return;
    fflush(s_fp);
    fsync(fileno(s_fp));
    s_unflushed = 0;
    s_last_flush_us = now;
}

void head_sd_get_stats(head_sd_stats_t *out)
{
    if (out) *out = s_st;
}

#define SD_CKPT     SD_DIR "/epup_ckpt.bin"
#define SD_CKPT_TMP SD_DIR "/epup_ckpt.tmp"

FILE *head_sd_ckpt_open(bool write)
{
    if (!s_st.mounted) return NULL;
    if (write) {
        if (s_st.full) return NULL;
        return fopen(SD_CKPT_TMP, "wb");
    }
    return fopen(SD_CKPT, "rb");
}

bool head_sd_ckpt_commit(void)
{
    if (!s_st.mounted) return false;
    unlink(SD_CKPT);
    return rename(SD_CKPT_TMP, SD_CKPT) == 0;
}

struct head_sd_reader { FILE *fp; };

head_sd_reader_t *head_sd_report_open(size_t window_bytes)
{
    if (!s_st.mounted || !s_fp || s_st.path[0] == '\0') return NULL;
    head_sd_flush();

    FILE *fp = fopen(s_st.path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); return NULL; }

    long start = (window_bytes && (long)window_bytes < size) ? size - (long)window_bytes : 0;
    if (fseek(fp, start, SEEK_SET) != 0) { fclose(fp); return NULL; }
    if (start > 0) {
        int c;
        while ((c = fgetc(fp)) != EOF && c != '\n') { }
    }

    head_sd_reader_t *r = calloc(1, sizeof(*r));
    if (!r) { fclose(fp); return NULL; }
    r->fp = fp;
    return r;
}

size_t head_sd_report_next(head_sd_reader_t *r, char *buf, size_t bufsz)
{
    if (!r || !r->fp || !buf || bufsz == 0) return 0;
    size_t n = 0;
    int c;
    while ((c = fgetc(r->fp)) != EOF) {
        if (c == '\n') { if (n > 0) return n; else continue; }
        if (n < bufsz - 1) buf[n++] = (char)c;
    }
    return n;
}

void head_sd_report_close(head_sd_reader_t *r)
{
    if (!r) return;
    if (r->fp) fclose(r->fp);
    free(r);
}
