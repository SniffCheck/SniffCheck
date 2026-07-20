#include "sentinel.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const sentinel_cat_meta_t META[SENTINEL_CAT_COUNT] = {
    [SENTINEL_CAT_PWNAGOTCHI]     = { "pwnagotchi", "Pwnagotchi",      "ic-tracker" },
    [SENTINEL_CAT_MINIGOTCHI]     = { "minigotchi", "Minigotchi",      "ic-tracker" },
    [SENTINEL_CAT_MARAUDER]       = { "marauder",   "ESP32 Marauder",  "ic-tracker" },
    [SENTINEL_CAT_HAK5]           = { "hak5",       "Hak5 gear",       "ic-tracker" },
    [SENTINEL_CAT_FLIPPER]        = { "flipper",    "Flipper Zero",    "ic-tracker" },
    [SENTINEL_CAT_FLOCK]          = { "flock",      "Flock ALPR",      "ic-camera" },
    [SENTINEL_CAT_LAW_ENFORCEMENT]= { "law",        "Law enforcement", "ic-police" },
    [SENTINEL_CAT_DEAUTHER]       = { "deauther",   "WiFi Deauther",   "ic-tracker" },
    [SENTINEL_CAT_OMG]            = { "omg",        "O.MG cable",      "ic-tracker" },
    [SENTINEL_CAT_UBERTOOTH]      = { "ubertooth",  "Ubertooth",       "ic-ble" },
    [SENTINEL_CAT_WARDRIVER]      = { "wardriver",  "Wardriver",       "ic-wifi" },
    [SENTINEL_CAT_BETTERCAP]      = { "bettercap",  "Bettercap",       "ic-router" },
    [SENTINEL_CAT_SNIFFCHECK]     = { "sniffcheck", "SniffCheck unit", "ic-chip" },
    [SENTINEL_CAT_RAGNAR]         = { "ragnar",     "Ragnar / Bjorn",  "ic-tracker" },
};

const sentinel_cat_meta_t *sentinel_cat_meta(int i)
{
    if (i < 0 || i >= SENTINEL_CAT_COUNT) return NULL;
    return &META[i];
}

static int json_str(const char *s, int n, const char *pat, char *out, int outsz)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) {
        if (memcmp(s + i, pat, pl) == 0) {
            int k = i + pl, o = 0;
            while (k < n && s[k] != '"' && o < outsz - 1) out[o++] = s[k++];
            out[o] = '\0';
            return o;
        }
    }
    return 0;
}

int sentinel_line_type(const char *line, int n, char *out, int outsz)
{
    return json_str(line, n, "\"type\":\"", out, outsz);
}

static bool ci_has(const char *hay, const char *needle_lc)
{
    if (!hay || !*hay) return false;
    size_t nl = strlen(needle_lc);
    for (const char *p = hay; *p; p++) {
        size_t k = 0;
        while (k < nl && p[k] && (char)tolower((unsigned char)p[k]) == needle_lc[k]) k++;
        if (k == nl) return true;
    }
    return false;
}

static uint32_t match_haystack(const char *hay)
{
    uint32_t m = 0;
    if (!hay || !*hay) return 0;
    if (ci_has(hay, "pwnagotchi") || ci_has(hay, "pwngrid")) m |= (1u << SENTINEL_CAT_PWNAGOTCHI);
    if (ci_has(hay, "minigotchi"))                           m |= (1u << SENTINEL_CAT_MINIGOTCHI);
    if (ci_has(hay, "marauder"))                             m |= (1u << SENTINEL_CAT_MARAUDER);
    if (ci_has(hay, "flipper"))                              m |= (1u << SENTINEL_CAT_FLIPPER);

    if (ci_has(hay, "hak5") || ci_has(hay, "wifi pineapple") || ci_has(hay, "wifipineapple") ||
        ci_has(hay, "pineapple_") || ci_has(hay, "bash bunny") || ci_has(hay, "bashbunny") ||
        ci_has(hay, "lan turtle") || ci_has(hay, "shark jack"))
        m |= (1u << SENTINEL_CAT_HAK5);
    if (ci_has(hay, "flock safety") || ci_has(hay, "flocksafety"))
        m |= (1u << SENTINEL_CAT_FLOCK);
    if (ci_has(hay, "deauth") || ci_has(hay, "spacehuhn"))   m |= (1u << SENTINEL_CAT_DEAUTHER);
    if (ci_has(hay, "o.mg") || ci_has(hay, "omg cable") ||
        ci_has(hay, "ductnut"))                              m |= (1u << SENTINEL_CAT_OMG);
    if (ci_has(hay, "ubertooth"))                            m |= (1u << SENTINEL_CAT_UBERTOOTH);

    if (ci_has(hay, "wigle") || ci_has(hay, "wardriv"))     m |= (1u << SENTINEL_CAT_WARDRIVER);
    if (ci_has(hay, "bettercap"))                            m |= (1u << SENTINEL_CAT_BETTERCAP);
    if (ci_has(hay, "sniffcheck"))                           m |= (1u << SENTINEL_CAT_SNIFFCHECK);

    if (ci_has(hay, "ragnar") || ci_has(hay, "bjorn"))       m |= (1u << SENTINEL_CAT_RAGNAR);
    return m;
}

uint32_t sentinel_match_fields_conf(const char *name, const char *vendor,
                                    const char *name_rule, bool is_le, uint8_t *conf)
{
    if (conf) memset(conf, SENTINEL_CONF_NONE, SENTINEL_CAT_COUNT);
    if (is_le) {
        if (conf) conf[SENTINEL_CAT_LAW_ENFORCEMENT] = SENTINEL_CONF_HIGH;
        return (1u << SENTINEL_CAT_LAW_ENFORCEMENT);
    }

    uint32_t high = match_haystack(vendor);
    char lowhay[96];
    snprintf(lowhay, sizeof lowhay, "%s %s", name ? name : "", name_rule ? name_rule : "");
    uint32_t low = match_haystack(lowhay);
    uint32_t m = high | low;
    if (conf) for (int c = 0; c < SENTINEL_CAT_COUNT; c++) {
        if (high & (1u << c))      conf[c] = SENTINEL_CONF_HIGH;
        else if (low & (1u << c))  conf[c] = SENTINEL_CONF_LOW;
    }
    return m;
}

uint32_t sentinel_match_fields(const char *name, const char *vendor,
                               const char *name_rule, bool is_le)
{
    return sentinel_match_fields_conf(name, vendor, name_rule, is_le, NULL);
}

uint32_t sentinel_match_categories_conf(const char *line, int n, uint8_t *conf)
{
    if (conf) memset(conf, SENTINEL_CONF_NONE, SENTINEL_CAT_COUNT);
    char type[28];
    if (!sentinel_line_type(line, n, type, sizeof type)) return 0;

    if (strcmp(type, "law_enforcement_presence") == 0) {
        char pres[24] = {0};
        json_str(line, n, "\"presence\":\"", pres, sizeof pres);
        if (strcmp(pres, "likely") == 0 || strcmp(pres, "confirmed_identifier") == 0)
            return sentinel_match_fields_conf(NULL, NULL, NULL, true, conf);
        return 0;
    }

    char name[40] = {0}, vendor[40] = {0}, nrule[40] = {0};
    json_str(line, n, "\"name\":\"",           name,   sizeof name);
    json_str(line, n, "\"vendor\":\"",         vendor, sizeof vendor);
    json_str(line, n, "\"name_rule_name\":\"", nrule,  sizeof nrule);
    return sentinel_match_fields_conf(name, vendor, nrule, false, conf);
}

uint32_t sentinel_match_categories(const char *line, int n)
{
    return sentinel_match_categories_conf(line, n, NULL);
}

bool sentinel_line_identifier(const char *line, int n, uint8_t mac[6])
{
    char id[40];

    if (!json_str(line, n, "\"bssid\":\"",  id, sizeof id) &&
        !json_str(line, n, "\"addr\":\"",   id, sizeof id) &&
        !json_str(line, n, "\"target\":\"", id, sizeof id)) return false;
    memset(mac, 0, 6);
    int b = 0; unsigned v = 0, nib = 0;
    for (const char *p = id; *p && b < 6; p++) {
        char c = *p;
        int d = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (d < 0) continue;
        v = (v << 4) | (unsigned)d;
        if (++nib == 2) { mac[b++] = (uint8_t)v; v = 0; nib = 0; }
    }
    return b == 6;
}

bool sentinel_mac_prefix(const uint8_t mac[6], const uint8_t *pref, int pref_len)
{
    if (pref_len < 1 || pref_len > 6) return false;
    return memcmp(mac, pref, (size_t)pref_len) == 0;
}
