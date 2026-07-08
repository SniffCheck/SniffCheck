#include "virtual_pup.h"

#include <math.h>
#include <string.h>
#include <ctype.h>
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "sc_vpup";

#define VP_NS          "uicfg"
#define VP_K_WIFI      "vp_wifi"
#define VP_K_BLE       "vp_ble"
#define VP_K_XP        "vp_xp"
#define VP_K_BIRTH     "vp_birth"
#define VP_K_AVATAR    "vp_avatar"
#define VP_K_SCANS     "vp_scans"
#define VP_K_PETS      "vp_pets"
#define VP_K_TREATS    "vp_treats"
#define VP_K_NAME      "vp_name"

#define VP_CURVE_BASE    30.0
#define VP_CURVE_GROWTH  1.35

#define VP_LEVEL_GUARD   1000

static uint32_t s_wifi   = 0;
static uint32_t s_ble    = 0;
static uint64_t s_xp     = 0;
static uint32_t s_birth  = 0;
static uint8_t  s_avatar = 0;
static uint32_t s_scans  = 0;
static uint32_t s_pets   = 0;
static uint32_t s_treats = 0;
static char     s_name[VP_NAME_MAX] = "Suz";

static uint32_t  s_last_scan_xp = 0;
static vp_mood_t s_mood         = VP_MOOD_CURIOUS;
static uint32_t  s_cur_boot     = 1;

static uint64_t curve_threshold(uint16_t level)
{
    if (level <= 1) return 0;
    double t = VP_CURVE_BASE * pow(VP_CURVE_GROWTH, (double)level);
    if (t >= 1.8e19) return UINT64_MAX;
    return (uint64_t)t;
}

uint16_t virtual_pup_level_for_xp(uint64_t xp)
{
    uint16_t level = 1;
    while (level < VP_LEVEL_GUARD && xp >= curve_threshold(level + 1)) {
        level++;
    }
    return level;
}

vp_title_t virtual_pup_title_for_level(uint16_t level)
{
    if (level <= 5)  return VP_TITLE_PUPPY;
    if (level <= 15) return VP_TITLE_YOUNG;
    if (level <= 30) return VP_TITLE_ADULT;
    if (level <= 50) return VP_TITLE_VETERAN;
    return VP_TITLE_LEGEND;
}

const char *virtual_pup_title_label(vp_title_t title)
{
    switch (title) {
    case VP_TITLE_PUPPY:   return "Puppy";
    case VP_TITLE_YOUNG:   return "Young dog";
    case VP_TITLE_ADULT:   return "Adult";
    case VP_TITLE_VETERAN: return "Veteran";
    case VP_TITLE_LEGEND:  return "Legend";
    default:               return "?";
    }
}

static void virtual_pup_save(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(VP_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "save open failed: %s", esp_err_to_name(err));
        return;
    }
    nvs_set_u32(h, VP_K_WIFI, s_wifi);
    nvs_set_u32(h, VP_K_BLE, s_ble);
    nvs_set_u64(h, VP_K_XP, s_xp);
    nvs_set_u32(h, VP_K_BIRTH, s_birth);
    nvs_set_u8(h, VP_K_AVATAR, s_avatar);
    nvs_set_u32(h, VP_K_SCANS, s_scans);
    nvs_set_u32(h, VP_K_PETS, s_pets);
    nvs_set_u32(h, VP_K_TREATS, s_treats);
    nvs_set_str(h, VP_K_NAME, s_name);
    nvs_commit(h);
    nvs_close(h);
}

void virtual_pup_init(uint32_t boot_count)
{
    s_cur_boot = (boot_count == 0) ? 1 : boot_count;

    nvs_handle_t h;
    if (nvs_open(VP_NS, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, VP_K_WIFI, &s_wifi);
        nvs_get_u32(h, VP_K_BLE, &s_ble);
        nvs_get_u64(h, VP_K_XP, &s_xp);
        nvs_get_u32(h, VP_K_BIRTH, &s_birth);
        nvs_get_u8(h, VP_K_AVATAR, &s_avatar);
        nvs_get_u32(h, VP_K_SCANS, &s_scans);
        nvs_get_u32(h, VP_K_PETS, &s_pets);
        nvs_get_u32(h, VP_K_TREATS, &s_treats);
        size_t nlen = sizeof(s_name);
        nvs_get_str(h, VP_K_NAME, s_name, &nlen);
        nvs_close(h);
    }

    if (s_birth == 0) {
        s_birth = (boot_count == 0) ? 1 : boot_count;
        virtual_pup_save();
        ESP_LOGI(TAG, "new pup born at boot %u (avatar %u)",
                 (unsigned)s_birth, (unsigned)s_avatar);
    }

    ESP_LOGI(TAG, "pup loaded: L%u xp=%llu wifi=%u ble=%u",
             (unsigned)virtual_pup_level_for_xp(s_xp),
             (unsigned long long)s_xp, (unsigned)s_wifi, (unsigned)s_ble);
}

vp_feed_result_t virtual_pup_feed(uint16_t wifi_n, uint16_t ble_n)
{
    uint16_t old_level = virtual_pup_level_for_xp(s_xp);

    s_wifi += wifi_n;
    s_ble  += ble_n;
    uint32_t gained = (uint32_t)wifi_n + (uint32_t)ble_n;
    s_xp += gained;
    s_scans++;
    s_last_scan_xp = gained;
    s_mood = VP_MOOD_EXCITED;

    uint16_t new_level = virtual_pup_level_for_xp(s_xp);
    virtual_pup_save();

    vp_feed_result_t r = {
        .xp_gained  = gained,
        .leveled_up = (new_level > old_level),
        .new_level  = new_level,
    };
    if (r.leveled_up) {
        ESP_LOGI(TAG, "level up! %u -> %u (%s)", (unsigned)old_level,
                 (unsigned)new_level,
                 virtual_pup_title_label(virtual_pup_title_for_level(new_level)));
    }
    ESP_LOGI(TAG, "fed +%u xp (wifi %u, ble %u) -> L%u xp=%llu",
             (unsigned)gained, (unsigned)wifi_n, (unsigned)ble_n,
             (unsigned)new_level, (unsigned long long)s_xp);
    return r;
}

vp_feed_result_t virtual_pup_grant_xp(uint32_t xp)
{
    uint16_t old_level = virtual_pup_level_for_xp(s_xp);
    s_xp += xp;
    uint16_t new_level = virtual_pup_level_for_xp(s_xp);
    if (xp > 0) virtual_pup_save();

    vp_feed_result_t r = {
        .xp_gained  = xp,
        .leveled_up = (new_level > old_level),
        .new_level  = new_level,
    };
    if (xp > 0) {
        ESP_LOGI(TAG, "bonus +%u xp -> L%u xp=%llu", (unsigned)xp,
                 (unsigned)new_level, (unsigned long long)s_xp);
    }
    return r;
}

void virtual_pup_get(vp_status_t *out)
{
    if (!out) return;
    uint16_t level = virtual_pup_level_for_xp(s_xp);
    uint64_t cur   = curve_threshold(level);
    uint64_t next  = curve_threshold(level + 1);
    if (next == UINT64_MAX) next = cur;

    out->lifetime_wifi = s_wifi;
    out->lifetime_ble  = s_ble;
    out->total_xp      = s_xp;
    out->level         = level;
    out->xp_into_level = (s_xp > cur) ? (s_xp - cur) : 0;
    out->xp_for_level  = (next > cur) ? (next - cur) : 0;
    out->title         = virtual_pup_title_for_level(level);
    out->avatar        = s_avatar;
    out->birth_boot    = s_birth;
    out->lifetime_scans= s_scans;
    out->pets          = s_pets;
    out->treats        = s_treats;
    out->last_scan_xp  = s_last_scan_xp;
    out->mood          = s_mood;
}

const char *virtual_pup_name(void) { return s_name; }

void virtual_pup_set_name(const char *name)
{
    if (!name) return;
    char clean[VP_NAME_MAX];
    size_t j = 0;
    for (size_t i = 0; name[i] && j < sizeof(clean) - 1; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') clean[j++] = (char)c;
    }
    clean[j] = '\0';

    char *p = clean;
    while (*p == ' ') p++;
    size_t len = strlen(p);
    while (len && p[len - 1] == ' ') p[--len] = '\0';
    if (len == 0) return;

    strncpy(s_name, p, sizeof(s_name) - 1);
    s_name[sizeof(s_name) - 1] = '\0';
    virtual_pup_save();
    ESP_LOGI(TAG, "pup renamed -> %s", s_name);
}

void virtual_pup_pet(void)
{
    s_pets++;
    s_mood = VP_MOOD_HAPPY;
    virtual_pup_save();
    ESP_LOGI(TAG, "pet (%u total)", (unsigned)s_pets);
}

void virtual_pup_treat(void)
{
    s_treats++;
    s_mood = VP_MOOD_CONTENT;
    virtual_pup_save();
    ESP_LOGI(TAG, "treat (%u total)", (unsigned)s_treats);
}

const char *virtual_pup_mood_label(void)
{
    switch (s_mood) {
    case VP_MOOD_HAPPY:   return "happy";
    case VP_MOOD_EXCITED: return "excited";
    case VP_MOOD_CONTENT: return "content";
    default:              return "curious";
    }
}

void virtual_pup_reset(void)
{
    s_wifi = 0; s_ble = 0; s_xp = 0;
    s_scans = 0; s_pets = 0; s_treats = 0;
    s_birth = s_cur_boot;
    s_avatar = 0;
    strcpy(s_name, "Suz");
    s_last_scan_xp = 0;
    s_mood = VP_MOOD_CURIOUS;
    virtual_pup_save();
    ESP_LOGW(TAG, "pup reset — fresh pup born at boot %u", (unsigned)s_birth);
}
