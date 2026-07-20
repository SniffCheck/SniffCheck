#include "sentinel_registry.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "nvs.h"
#include "head_sd.h"

static const char *TAG = "sc-sreg";

#define REG_DIR         "/sdcard/sniffcheck"
#define REG_SEG_FMT     REG_DIR "/sentinel_reg_%04lu.jsonl"
#define REG_BLOOM_PATH  REG_DIR "/sentinel_bloom.bin"

#define BLOOM_BYTES     (48 * 1024)
#define BLOOM_BITS      (BLOOM_BYTES * 8)
#define BLOOM_K         4
#define SEG_MAX_BYTES   (4 * 1024 * 1024)

static uint8_t  s_bloom[BLOOM_BYTES];
static uint32_t s_life_det, s_life_uniq;
static uint32_t s_sess_det, s_sess_uniq, s_sess_ret;
static uint32_t s_seg_idx;
static uint32_t s_seg_bytes;
static bool     s_dirty;
static bool     s_bloom_dirty;

static uint32_t fnv1a(const uint8_t *p, int n, uint32_t seed)
{
    uint32_t h = seed;
    for (int i = 0; i < n; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h;
}

static void bloom_bits(const uint8_t *key, int n, uint32_t idx[BLOOM_K])
{
    uint32_t h1 = fnv1a(key, n, 0x811c9dc5u);
    uint32_t h2 = fnv1a(key, n, 0x7ee3623bu) | 1u;
    for (int k = 0; k < BLOOM_K; k++) idx[k] = (h1 + (uint32_t)k * h2) % BLOOM_BITS;
}
static bool bloom_test(const uint32_t idx[BLOOM_K])
{
    for (int k = 0; k < BLOOM_K; k++)
        if (!(s_bloom[idx[k] >> 3] & (1u << (idx[k] & 7)))) return false;
    return true;
}
static void bloom_set(const uint32_t idx[BLOOM_K])
{
    for (int k = 0; k < BLOOM_K; k++) s_bloom[idx[k] >> 3] |= (1u << (idx[k] & 7));
}

static void nvs_load(void)
{
    nvs_handle_t h;
    if (nvs_open("sentreg", NVS_READONLY, &h) != ESP_OK) return;
    nvs_get_u32(h, "det",  &s_life_det);
    nvs_get_u32(h, "uniq", &s_life_uniq);
    nvs_get_u32(h, "seg",  &s_seg_idx);
    nvs_close(h);
}
static void nvs_store(void)
{
    nvs_handle_t h;
    if (nvs_open("sentreg", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u32(h, "det",  s_life_det);
    nvs_set_u32(h, "uniq", s_life_uniq);
    nvs_set_u32(h, "seg",  s_seg_idx);
    nvs_commit(h);
    nvs_close(h);
}

static void bloom_load(void)
{
    if (!head_sd_ok()) return;
    FILE *f = fopen(REG_BLOOM_PATH, "rb");
    if (!f) return;
    size_t rd = fread(s_bloom, 1, BLOOM_BYTES, f);
    fclose(f);
    ESP_LOGI(TAG, "bloom snapshot loaded (%u/%u bytes)", (unsigned)rd, (unsigned)BLOOM_BYTES);
}
static void bloom_save(void)
{
    if (!head_sd_ok() || !s_bloom_dirty) return;
    FILE *f = fopen(REG_BLOOM_PATH ".tmp", "wb");
    if (!f) return;
    size_t wr = fwrite(s_bloom, 1, BLOOM_BYTES, f);
    fclose(f);
    if (wr == BLOOM_BYTES) { remove(REG_BLOOM_PATH); rename(REG_BLOOM_PATH ".tmp", REG_BLOOM_PATH); s_bloom_dirty = false; }
}

static void seg_measure(void)
{
    if (!head_sd_ok()) { s_seg_bytes = 0; return; }
    char path[80]; snprintf(path, sizeof path, REG_SEG_FMT, (unsigned long)s_seg_idx);
    FILE *f = fopen(path, "rb");
    if (!f) { s_seg_bytes = 0; return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    s_seg_bytes = sz > 0 ? (uint32_t)sz : 0;
}

void sentinel_registry_init(void)
{
    nvs_load();
    bloom_load();
    seg_measure();
    ESP_LOGI(TAG, "registry: lifetime %lu det / %lu uniq, segment #%lu (%lu B)",
             (unsigned long)s_life_det, (unsigned long)s_life_uniq,
             (unsigned long)s_seg_idx, (unsigned long)s_seg_bytes);
}

int sentinel_registry_key(uint8_t cat, const uint8_t mac[6], const char *name, uint8_t *out, int outcap)
{
    bool have_name = name && name[0];

    bool have_mac = false;
    if (mac) { for (int i = 0; i < 6; i++) if (mac[i]) { have_mac = true; break; } }
    bool mac_random = have_mac && (mac[0] & 0x02);
    bool stable_mac = have_mac && !mac_random;
    if (!stable_mac && !have_name) return 0;

    int o = 0;
    if (o < outcap) out[o++] = cat;
    if (stable_mac) { for (int i = 0; i < 6 && o < outcap; i++) out[o++] = mac[i]; }
    if (have_name) {

        for (const char *p = name; *p && o < outcap; p++) {
            char c = *p; if (c >= 'A' && c <= 'Z') c += 32;
            out[o++] = (uint8_t)c;
        }
    }
    return o;
}

bool sentinel_registry_note(const uint8_t *key, int keylen, const char *rec_json, int rec_len)
{
    uint32_t idx[BLOOM_K];
    bloom_bits(key, keylen, idx);
    bool returning = bloom_test(idx);

    s_life_det++; s_sess_det++;
    if (returning) s_sess_ret++;
    else { bloom_set(idx); s_bloom_dirty = true; s_life_uniq++; s_sess_uniq++; }
    s_dirty = true;

    if (head_sd_ok() && rec_json && rec_len > 0) {
        if (s_seg_bytes >= SEG_MAX_BYTES) { s_seg_idx++; s_seg_bytes = 0; nvs_store(); }
        char path[80]; snprintf(path, sizeof path, REG_SEG_FMT, (unsigned long)s_seg_idx);
        FILE *f = fopen(path, "ab");
        if (f) {
            int w = fprintf(f, "%.*s\n", rec_len, rec_json);
            fclose(f);
            if (w > 0) s_seg_bytes += (uint32_t)w;
        }
    }
    return returning;
}

void sentinel_registry_note_untracked(void)
{
    s_life_det++; s_sess_det++; s_dirty = true;
}

void sentinel_registry_stats(sentinel_reg_stats_t *out)
{
    if (!out) return;
    out->lifetime_detections = s_life_det;
    out->lifetime_unique     = s_life_uniq;
    out->session_detections  = s_sess_det;
    out->session_unique      = s_sess_uniq;
    out->returning           = s_sess_ret;
}

void sentinel_registry_sync(void)
{
    if (!s_dirty && !s_bloom_dirty) return;
    bloom_save();
    if (s_dirty) { nvs_store(); s_dirty = false; }
}
