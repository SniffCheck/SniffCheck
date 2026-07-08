#include "capture_ring.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>

static const char *TAG = "sc_capring";

#define HDR_LEN  4 

static uint8_t            *s_buf;
static size_t              s_cap;
static size_t              s_head;
static size_t              s_tail;
static size_t              s_used;
static uint32_t            s_recs_total;
static uint32_t            s_recs_current;
static uint32_t            s_recs_dropped;
static uint64_t            s_bytes_total;
static SemaphoreHandle_t   s_mtx;
static uint64_t            s_evict_seq;

static inline uint32_t read_u32_le(size_t off)
{
    return (uint32_t)s_buf[off] |
           ((uint32_t)s_buf[(off + 1) % s_cap] << 8) |
           ((uint32_t)s_buf[(off + 2) % s_cap] << 16) |
           ((uint32_t)s_buf[(off + 3) % s_cap] << 24);
}

static inline void write_u32_le(size_t off, uint32_t v)
{
    s_buf[off]                 = (uint8_t)(v & 0xFF);
    s_buf[(off + 1) % s_cap]   = (uint8_t)((v >> 8) & 0xFF);
    s_buf[(off + 2) % s_cap]   = (uint8_t)((v >> 16) & 0xFF);
    s_buf[(off + 3) % s_cap]   = (uint8_t)((v >> 24) & 0xFF);
}

static void copy_in(size_t off, const void *src, size_t n)
{
    size_t first = (off + n <= s_cap) ? n : (s_cap - off);
    memcpy(&s_buf[off], src, first);
    if (first < n) {
        memcpy(&s_buf[0], (const uint8_t *)src + first, n - first);
    }
}

static void copy_out(size_t off, void *dst, size_t n)
{
    size_t first = (off + n <= s_cap) ? n : (s_cap - off);
    memcpy(dst, &s_buf[off], first);
    if (first < n) {
        memcpy((uint8_t *)dst + first, &s_buf[0], n - first);
    }
}

static void drop_oldest(void)
{
    if (s_used == 0) return;
    uint32_t old_len = read_u32_le(s_tail);
    size_t frame = HDR_LEN + old_len;
    s_tail = (s_tail + frame) % s_cap;
    s_used -= frame;
    s_recs_current--;
    s_recs_dropped++;
    s_evict_seq++;
}

esp_err_t capture_ring_init(size_t preferred_bytes, size_t fallback_bytes)
{
    s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx) return ESP_ERR_NO_MEM;

    s_buf = heap_caps_malloc(preferred_bytes, MALLOC_CAP_SPIRAM);
    if (s_buf) {
        s_cap = preferred_bytes;
    } else if (fallback_bytes) {
        s_buf = heap_caps_malloc(fallback_bytes, MALLOC_CAP_SPIRAM);
        if (s_buf) {
            s_cap = fallback_bytes;
            ESP_LOGW(TAG, "PSRAM ring fell back to %u bytes (preferred %u failed)",
                     (unsigned)fallback_bytes, (unsigned)preferred_bytes);
        }
    }

    if (!s_buf) {
        ESP_LOGE(TAG, "PSRAM ring alloc failed (preferred=%u fallback=%u)",
                 (unsigned)preferred_bytes, (unsigned)fallback_bytes);
        return ESP_ERR_NO_MEM;
    }

    s_head = s_tail = s_used = 0;
    s_recs_total = s_recs_current = s_recs_dropped = 0;
    s_bytes_total = 0;
    s_evict_seq = 0;
    ESP_LOGI(TAG, "PSRAM ring ready: %u bytes", (unsigned)s_cap);
    return ESP_OK;
}

size_t capture_ring_write(const char *line, size_t len)
{
    if (!s_buf || !line || len == 0) return 0;
    size_t frame = HDR_LEN + len;
    if (frame > s_cap) return 0;

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    while (s_used + frame > s_cap) {
        drop_oldest();
    }
    write_u32_le(s_head, (uint32_t)len);
    copy_in((s_head + HDR_LEN) % s_cap, line, len);
    s_head = (s_head + frame) % s_cap;
    s_used += frame;
    s_recs_total++;
    s_recs_current++;
    s_bytes_total += frame;
    xSemaphoreGive(s_mtx);
    return frame;
}

void capture_ring_reader_open(capture_ring_reader_t *r)
{
    if (!r) return;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    r->pos = s_tail;
    r->end = s_head;
    r->wrapped = false;
    r->valid = (s_used > 0);
    xSemaphoreGive(s_mtx);
}

size_t capture_ring_reader_next(capture_ring_reader_t *r, char *out, size_t out_sz)
{
    if (!r || !r->valid || !out || out_sz == 0) return 0;

    size_t copied = 0;
    xSemaphoreTake(s_mtx, portMAX_DELAY);

    if (s_used == 0) { r->valid = false; goto done; }

    size_t live_lo = s_tail;
    size_t live_hi = (s_tail + s_used) % s_cap;
    bool in_range;
    if (live_lo < live_hi) {
        in_range = (r->pos >= live_lo && r->pos < live_hi);
    } else {
        in_range = (r->pos >= live_lo || r->pos < live_hi);
    }
    if (!in_range) {

        r->valid = false;
        goto done;
    }

    if (r->pos == r->end && !r->wrapped) goto done;

    uint32_t rec_len = read_u32_le(r->pos);
    if (rec_len == 0 || rec_len > s_cap) { r->valid = false; goto done; }
    if (rec_len + 1 > out_sz) goto done;

    copy_out((r->pos + HDR_LEN) % s_cap, out, rec_len);
    out[rec_len] = '\0';
    copied = rec_len;
    r->pos = (r->pos + HDR_LEN + rec_len) % s_cap;
    if (r->pos == r->end) r->wrapped = true;

done:
    xSemaphoreGive(s_mtx);
    return copied;
}

void capture_ring_get_stats(capture_ring_stats_t *out)
{
    if (!out) return;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    out->capacity         = s_cap;
    out->bytes_used       = s_used;
    out->records_total    = s_recs_total;
    out->records_current  = s_recs_current;
    out->records_dropped  = s_recs_dropped;
    out->bytes_total      = s_bytes_total;
    xSemaphoreGive(s_mtx);
}

void capture_ring_clear_volatile(void)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_head = s_tail = s_used = 0;
    s_recs_current = 0;
    s_evict_seq++;
    xSemaphoreGive(s_mtx);
}
