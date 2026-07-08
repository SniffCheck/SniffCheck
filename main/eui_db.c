#include "eui_db.h"

#include <string.h>
#include <ctype.h>
#include "esp_partition.h"
#include "esp_log.h"
#include "spi_flash_mmap.h"

static const char *TAG = "sc_eui";

typedef struct __attribute__((packed)) {
    uint8_t  magic[8];
    uint32_t version;
    uint64_t built;
    uint32_t section_count;
    uint8_t  reserved[8];
} eui_preamble_t;

typedef struct __attribute__((packed)) {
    uint32_t kind;
    uint32_t offset;
    uint32_t entry_count;
    uint32_t entry_stride;
} eui_section_desc_t;

typedef struct {
    const uint8_t *base;
    uint32_t       count;
    uint8_t        stride;
} section_view_t;

static const uint8_t      *s_base = NULL;
static const char         *s_names = NULL;
static section_view_t      s_sections[EUI_DB_MAX_SECTIONS];
static spi_flash_mmap_handle_t s_mmap_handle;

static const uint8_t EXPECTED_MAGIC[8] = "SCEUIDB\x00";

esp_err_t eui_db_init(void)
{
    memset(s_sections, 0, sizeof(s_sections));

    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "euidb");
    if (!part) {
        ESP_LOGE(TAG, "euidb partition not found");
        return ESP_ERR_NOT_FOUND;
    }

    const void *ptr;
    esp_err_t err = esp_partition_mmap(part, 0, part->size,
                                        ESP_PARTITION_MMAP_DATA,
                                        &ptr, &s_mmap_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mmap failed: %s", esp_err_to_name(err));
        return err;
    }
    s_base = (const uint8_t *)ptr;

    const eui_preamble_t *pre = (const eui_preamble_t *)s_base;
    if (memcmp(pre->magic, EXPECTED_MAGIC, 8) != 0) {
        ESP_LOGE(TAG, "euidb bad magic — partition blank or corrupt");
        return ESP_ERR_INVALID_STATE;
    }
    if (pre->version != EUI_DB_VERSION) {
        ESP_LOGE(TAG, "euidb v%u unsupported (this firmware needs v%u)",
                 (unsigned)pre->version, EUI_DB_VERSION);
        return ESP_ERR_INVALID_VERSION;
    }
    if (pre->section_count == 0 || pre->section_count > EUI_DB_MAX_SECTIONS) {
        ESP_LOGE(TAG, "euidb section_count %u out of range",
                 (unsigned)pre->section_count);
        return ESP_ERR_INVALID_STATE;
    }

    const eui_section_desc_t *secs = (const eui_section_desc_t *)(s_base + sizeof(eui_preamble_t));
    const uint8_t *trailer = (const uint8_t *)(secs + pre->section_count);
    uint32_t names_off = ((const uint32_t *)trailer)[0];
    uint32_t names_len = ((const uint32_t *)trailer)[1];

    for (uint32_t i = 0; i < pre->section_count; i++) {
        const eui_section_desc_t *d = &secs[i];
        if (d->kind == 0 || d->kind >= EUI_DB_MAX_SECTIONS) continue;
        if (d->entry_stride != 8 && d->entry_stride != 12 &&
            d->entry_stride != 16 && d->entry_stride != 24) {
            ESP_LOGE(TAG, "section kind=%u bad stride %u",
                     (unsigned)d->kind, (unsigned)d->entry_stride);
            return ESP_ERR_INVALID_STATE;
        }
        s_sections[d->kind].base   = s_base + d->offset;
        s_sections[d->kind].count  = d->entry_count;
        s_sections[d->kind].stride = (uint8_t)d->entry_stride;
    }

    s_names = (const char *)(s_base + names_off);

    ESP_LOGI(TAG, "v%u loaded: names=%u B", EUI_DB_VERSION, (unsigned)names_len);
    ESP_LOGI(TAG, "  mac24=%u  mac28=%u  mac36=%u  iab=%u  cid=%u  malicious=%u",
             (unsigned)s_sections[EUI_KIND_MAC24].count,
             (unsigned)s_sections[EUI_KIND_MAC28].count,
             (unsigned)s_sections[EUI_KIND_MAC36].count,
             (unsigned)s_sections[EUI_KIND_IAB].count,
             (unsigned)s_sections[EUI_KIND_CID].count,
             (unsigned)s_sections[EUI_KIND_MALICIOUS].count);
    ESP_LOGI(TAG, "  bt_cid=%u  uuid16=%u  uuid32=%u  uuid128=%u",
             (unsigned)s_sections[EUI_KIND_BT_COMPANY].count,
             (unsigned)s_sections[EUI_KIND_BT_UUID16].count,
             (unsigned)s_sections[EUI_KIND_BT_UUID32].count,
             (unsigned)s_sections[EUI_KIND_BT_UUID128].count);
    ESP_LOGI(TAG, "  mfg_rule=%u  apple_sub=%u  ms_sub=%u  fastpair=%u  name_rule=%u",
             (unsigned)s_sections[EUI_KIND_MFG_RULE].count,
             (unsigned)s_sections[EUI_KIND_APPLE_SUBTYPE].count,
             (unsigned)s_sections[EUI_KIND_MS_SUBTYPE].count,
             (unsigned)s_sections[EUI_KIND_FAST_PAIR].count,
             (unsigned)s_sections[EUI_KIND_NAME_RULE].count);
    ESP_LOGI(TAG, "  vendor_ie=%u  ssid=%u  ie_sig=%u  wps=%u  rsn=%u  country=%u",
             (unsigned)s_sections[EUI_KIND_VENDOR_IE].count,
             (unsigned)s_sections[EUI_KIND_SSID_RULE].count,
             (unsigned)s_sections[EUI_KIND_IE_SIGNATURE].count,
             (unsigned)s_sections[EUI_KIND_WPS_MFG].count,
             (unsigned)s_sections[EUI_KIND_RSN_OUI].count,
             (unsigned)s_sections[EUI_KIND_COUNTRY].count);
    ESP_LOGI(TAG, "  cdp=%u  lldp=%u  dhcp_vc=%u  dhcp_fp=%u  fcc_g=%u  fcc_c=%u",
             (unsigned)s_sections[EUI_KIND_CDP_ORG].count,
             (unsigned)s_sections[EUI_KIND_LLDP_ORG].count,
             (unsigned)s_sections[EUI_KIND_DHCP_VC].count,
             (unsigned)s_sections[EUI_KIND_DHCP_FP].count,
             (unsigned)s_sections[EUI_KIND_FCC_GRANTEE].count,
             (unsigned)s_sections[EUI_KIND_FCC_COVERED].count);
    return ESP_OK;
}

static uint32_t fnv1a32(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t fnv1a32_str_lower(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)tolower((unsigned char)*s);
        h *= 16777619u;
        s++;
    }
    return h;
}

static const void *bsearch_u32(uint8_t kind, uint32_t target)
{
    if (kind >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[kind];
    if (!v.base || v.count == 0) return NULL;
    int32_t lo = 0, hi = (int32_t)v.count - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        const uint8_t *rec = v.base + (size_t)mid * v.stride;
        uint32_t k = *(const uint32_t *)rec;
        if (k == target) return rec;
        if (k < target) lo = mid + 1;
        else            hi = mid - 1;
    }
    return NULL;
}

static const void *bsearch_u16(uint8_t kind, uint16_t target)
{
    if (kind >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[kind];
    if (!v.base || v.count == 0) return NULL;
    int32_t lo = 0, hi = (int32_t)v.count - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        const uint8_t *rec = v.base + (size_t)mid * v.stride;

        uint16_t k = *(const uint16_t *)rec;
        if (k == target) return rec;
        if (k < target) lo = mid + 1;
        else            hi = mid - 1;
    }
    return NULL;
}

static const void *bsearch_u64(uint8_t kind, uint64_t target)
{
    if (kind >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[kind];
    if (!v.base || v.count == 0 || v.stride != 16) return NULL;
    int32_t lo = 0, hi = (int32_t)v.count - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        const uint8_t *rec = v.base + (size_t)mid * v.stride;
        uint64_t k = *(const uint64_t *)rec;
        if (k == target) return rec;
        if (k < target) lo = mid + 1;
        else            hi = mid - 1;
    }
    return NULL;
}

static const void *bsearch_u128(uint8_t kind, const uint8_t target[16])
{
    if (kind >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[kind];

    if (!v.base || v.count == 0 || v.stride != 24) return NULL;
    int32_t lo = 0, hi = (int32_t)v.count - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        const uint8_t *rec = v.base + (size_t)mid * v.stride;
        int cmp = memcmp(rec, target, 16);
        if (cmp == 0) return rec;
        if (cmp < 0)  lo = mid + 1;
        else          hi = mid - 1;
    }
    return NULL;
}

static const char *resolve_std(const void *r,
                               uint16_t *f, uint8_t *c)
{
    if (!r) return NULL;
    const eui_record_std_t *p = (const eui_record_std_t *)r;
    if (f) *f = p->flags;
    if (c) *c = p->class_id;
    return s_names + p->name_off;
}

static const char *resolve_wide(const void *r,
                                uint16_t *f, uint8_t *c)
{
    if (!r) return NULL;
    const eui_record_wide_t *p = (const eui_record_wide_t *)r;
    if (f) *f = p->flags;
    if (c) *c = p->class_id;
    return s_names + p->name_off;
}

static const char *resolve_uuid128(const void *r,
                                   uint16_t *f, uint8_t *c)
{
    if (!r) return NULL;
    const eui_record_uuid128_t *p = (const eui_record_uuid128_t *)r;
    if (f) *f = p->flags;
    if (c) *c = p->class_id;
    return s_names + p->name_off;
}

static const char *resolve_tiny(const void *r,
                                uint16_t *f, uint8_t *c)
{
    if (!r) return NULL;
    const eui_record_tiny_t *p = (const eui_record_tiny_t *)r;
    if (f) *f = p->flags;
    if (c) *c = p->class_id;
    return s_names + p->name_off;
}

const char *eui_lookup_mac(const uint8_t mac[6],
                           uint16_t *flags_out,
                           uint8_t  *class_out,
                           uint8_t  *match_len_out)
{
    if (flags_out) *flags_out = 0;
    if (class_out) *class_out = EUI_CLASS_UNKNOWN;
    if (match_len_out) *match_len_out = 0;

    if (mac_is_multicast(mac)) return NULL;
    if (mac_is_laa(mac)) {
        if (flags_out) *flags_out = EUI_FLAG_PRIVATE_ASSIGN;
        return NULL;
    }

    uint64_t k36 = ((uint64_t)mac[0] << 28) | ((uint64_t)mac[1] << 20) |
                   ((uint64_t)mac[2] << 12) | ((uint64_t)mac[3] <<  4) |
                   ((uint64_t)(mac[4] >> 4));
    const void *r = bsearch_u64(EUI_KIND_MAC36, k36);
    if (r) {
        if (match_len_out) *match_len_out = 36;
        return resolve_wide(r, flags_out, class_out);
    }

    uint32_t k28 = ((uint32_t)mac[0] << 20) | ((uint32_t)mac[1] << 12) |
                   ((uint32_t)mac[2] <<  4) | ((uint32_t)(mac[3] >> 4));
    r = bsearch_u32(EUI_KIND_MAC28, k28);
    if (r) {
        if (match_len_out) *match_len_out = 28;
        return resolve_std(r, flags_out, class_out);
    }

    if (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0xC2) {
        r = bsearch_u64(EUI_KIND_IAB, k36);
        if (r) {
            if (match_len_out) *match_len_out = 36;
            return resolve_wide(r, flags_out, class_out);
        }
    }

    uint32_t k24 = ((uint32_t)mac[0] << 16) |
                   ((uint32_t)mac[1] <<  8) |
                    (uint32_t)mac[2];
    r = bsearch_u32(EUI_KIND_MAC24, k24);
    if (r) {
        if (match_len_out) *match_len_out = 24;
        return resolve_std(r, flags_out, class_out);
    }

    r = bsearch_u32(EUI_KIND_CID, k24);
    if (r) {
        if (match_len_out) *match_len_out = 24;
        return resolve_std(r, flags_out, class_out);
    }

    return NULL;
}

const char *eui_lookup(const uint8_t mac[6], uint16_t *flags_out, uint8_t *class_out)
{
    uint8_t ml = 0;
    return eui_lookup_mac(mac, flags_out, class_out, &ml);
}

const char *eui_lookup_company(uint16_t cid, uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u16(EUI_KIND_BT_COMPANY, cid), f, c);
}

const char *eui_lookup_uuid16(uint16_t uuid, uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u16(EUI_KIND_BT_UUID16, uuid), f, c);
}

const char *eui_lookup_uuid32(uint32_t uuid, uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u32(EUI_KIND_BT_UUID32, uuid), f, c);
}

const char *eui_lookup_uuid128(const uint8_t uuid[16], uint16_t *f, uint8_t *c)
{
    return resolve_uuid128(bsearch_u128(EUI_KIND_BT_UUID128, uuid), f, c);
}

const char *eui_lookup_apple_subtype(uint8_t subtype, uint16_t *f, uint8_t *c)
{
    return resolve_tiny(bsearch_u16(EUI_KIND_APPLE_SUBTYPE, subtype), f, c);
}

const char *eui_lookup_ms_subtype(uint8_t subtype, uint16_t *f, uint8_t *c)
{
    return resolve_tiny(bsearch_u16(EUI_KIND_MS_SUBTYPE, subtype), f, c);
}

const char *eui_lookup_fastpair(uint32_t model_id, uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u32(EUI_KIND_FAST_PAIR, model_id), f, c);
}

const char *eui_match_mfg_data(uint16_t company_id,
                               const uint8_t *payload, size_t len,
                               uint16_t *flags_out,
                               uint8_t  *class_out,
                               uint8_t  *subtype_out)
{
    if (flags_out)   *flags_out   = 0;
    if (class_out)   *class_out   = EUI_CLASS_UNKNOWN;
    if (subtype_out) *subtype_out = 0;

    if (EUI_KIND_MFG_RULE >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[EUI_KIND_MFG_RULE];
    if (!v.base || v.count == 0 || v.stride != 24) return NULL;

    const eui_record_rule_t *best = NULL;
    for (uint32_t i = 0; i < v.count; i++) {
        const eui_record_rule_t *p =
            (const eui_record_rule_t *)(v.base + (size_t)i * v.stride);
        if (p->company_id != company_id) continue;
        if (p->prefix_len > len) continue;
        if (memcmp(p->prefix, payload, p->prefix_len) != 0) continue;
        if (!best || p->prefix_len > best->prefix_len) best = p;
    }
    if (!best) return NULL;
    if (flags_out)   *flags_out   = best->flags;
    if (class_out)   *class_out   = best->class_id;
    if (subtype_out) *subtype_out = best->subtype;
    return s_names + best->name_off;
}

static bool str_contains_ci(const char *hay, const char *needle)
{
    size_t hl = strlen(hay), nl = strlen(needle);
    if (nl == 0 || nl > hl) return false;
    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        while (j < nl &&
               tolower((unsigned char)hay[i + j]) ==
               tolower((unsigned char)needle[j])) j++;
        if (j == nl) return true;
    }
    return false;
}

const char *eui_match_name(const char *name, uint16_t *f, uint8_t *c,
                           uint8_t *kind)
{
    if (f) *f = 0;
    if (c) *c = EUI_CLASS_UNKNOWN;
    if (kind) *kind = EUI_NAME_RULE_GENERIC;
    if (!name || !name[0]) return NULL;

    if (EUI_KIND_NAME_RULE >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[EUI_KIND_NAME_RULE];
    if (!v.base || v.count == 0 || v.stride != 16) return NULL;

    for (uint32_t i = 0; i < v.count; i++) {
        const eui_record_ssid_t *p =
            (const eui_record_ssid_t *)(v.base + (size_t)i * v.stride);
        const char *token = s_names + p->pattern_off;
        if (str_contains_ci(name, token)) {
            if (f) *f = p->flags;
            if (c) *c = p->class_id;
            if (kind) *kind = p->match_type;
            return s_names + p->name_off;
        }
    }
    return NULL;
}

static uint32_t oui_key3(const uint8_t oui[3])
{
    return ((uint32_t)oui[0] << 16) | ((uint32_t)oui[1] << 8) | oui[2];
}

const char *eui_lookup_vendor_ie(const uint8_t oui[3], uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u32(EUI_KIND_VENDOR_IE, oui_key3(oui)), f, c);
}

const char *eui_lookup_wps(const char *manufacturer, uint16_t *f, uint8_t *c)
{
    if (!manufacturer || !manufacturer[0]) return NULL;
    return resolve_std(bsearch_u32(EUI_KIND_WPS_MFG,
                       fnv1a32_str_lower(manufacturer)), f, c);
}

const char *eui_lookup_ie_signature(uint32_t ie_hash, uint16_t *f, uint8_t *c)
{
    if (ie_hash == 0) return NULL;
    return resolve_std(bsearch_u32(EUI_KIND_IE_SIGNATURE, ie_hash), f, c);
}

const char *eui_lookup_rsn_oui(const uint8_t oui[3], uint8_t suite_type,
                               uint16_t *f, uint8_t *c)
{
    uint32_t key = (oui_key3(oui) << 8) | suite_type;
    return resolve_std(bsearch_u32(EUI_KIND_RSN_OUI, key), f, c);
}

const char *eui_lookup_country(const char cc[2], uint16_t *f, uint8_t *c)
{
    if (!cc) return NULL;
    uint16_t k = ((uint16_t)(uint8_t)cc[0] << 8) | (uint8_t)cc[1];
    return resolve_tiny(bsearch_u16(EUI_KIND_COUNTRY, k), f, c);
}

static bool str_starts_with_ci(const char *hay, const char *needle)
{
    while (*needle) {
        if (!*hay) return false;
        if (tolower((unsigned char)*hay) != tolower((unsigned char)*needle))
            return false;
        hay++; needle++;
    }
    return true;
}

static bool str_ends_with_ci(const char *hay, const char *needle)
{
    size_t hl = strlen(hay), nl = strlen(needle);
    if (nl > hl) return false;
    const char *h = hay + (hl - nl);
    for (size_t i = 0; i < nl; i++) {
        if (tolower((unsigned char)h[i]) != tolower((unsigned char)needle[i]))
            return false;
    }
    return true;
}

static bool str_eq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

const char *eui_match_ssid(const char *ssid, uint16_t *f, uint8_t *c)
{
    if (f) *f = 0;
    if (c) *c = EUI_CLASS_UNKNOWN;
    if (!ssid || !ssid[0]) return NULL;

    if (EUI_KIND_SSID_RULE >= EUI_DB_MAX_SECTIONS) return NULL;
    section_view_t v = s_sections[EUI_KIND_SSID_RULE];
    if (!v.base || v.count == 0 || v.stride != 16) return NULL;

    for (uint32_t i = 0; i < v.count; i++) {
        const eui_record_ssid_t *p =
            (const eui_record_ssid_t *)(v.base + (size_t)i * v.stride);
        const char *pat = s_names + p->pattern_off;
        bool hit = false;
        switch (p->match_type) {
        case EUI_SSID_MATCH_EXACT:    hit = str_eq_ci(ssid, pat); break;
        case EUI_SSID_MATCH_PREFIX:   hit = str_starts_with_ci(ssid, pat); break;
        case EUI_SSID_MATCH_SUFFIX:   hit = str_ends_with_ci(ssid, pat); break;
        case EUI_SSID_MATCH_CONTAINS: hit = str_contains_ci(ssid, pat); break;
        case EUI_SSID_MATCH_COMPOUND: {

            const char *suf = pat + strlen(pat) + 1;
            hit = str_starts_with_ci(ssid, pat) && str_ends_with_ci(ssid, suf);
            break;
        }
        default: break;
        }
        if (hit) {
            if (f) *f = p->flags;
            if (c) *c = p->class_id;
            return s_names + p->name_off;
        }
    }
    return NULL;
}

const char *eui_lookup_cdp_org(const uint8_t oui[3], uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u32(EUI_KIND_CDP_ORG, oui_key3(oui)), f, c);
}

const char *eui_lookup_lldp_org(const uint8_t oui[3], uint16_t *f, uint8_t *c)
{
    return resolve_std(bsearch_u32(EUI_KIND_LLDP_ORG, oui_key3(oui)), f, c);
}

const char *eui_lookup_dhcp_vc(const char *vendor_class, uint16_t *f, uint8_t *c)
{
    if (!vendor_class || !vendor_class[0]) return NULL;
    return resolve_std(bsearch_u32(EUI_KIND_DHCP_VC,
                       fnv1a32_str_lower(vendor_class)), f, c);
}

const char *eui_lookup_dhcp_fp(const uint8_t *opt55, size_t n,
                               uint16_t *f, uint8_t *c)
{
    if (!opt55 || n == 0) return NULL;
    return resolve_std(bsearch_u32(EUI_KIND_DHCP_FP, fnv1a32(opt55, n)), f, c);
}

const char *eui_lookup_fcc_grantee(const char grantee[3], uint16_t *f, uint8_t *c)
{
    if (!grantee) return NULL;
    uint32_t k = ((uint32_t)(uint8_t)grantee[0] << 16) |
                 ((uint32_t)(uint8_t)grantee[1] <<  8) |
                  (uint32_t)(uint8_t)grantee[2];
    return resolve_std(bsearch_u32(EUI_KIND_FCC_GRANTEE, k), f, c);
}

const char *eui_lookup_fcc_covered(const char *name, uint16_t *f, uint8_t *c)
{
    if (!name || !name[0]) return NULL;
    return resolve_std(bsearch_u32(EUI_KIND_FCC_COVERED,
                       fnv1a32_str_lower(name)), f, c);
}

const char *eui_lookup_drone_mfr(const char code[4], uint16_t *f, uint8_t *c)
{
    if (!code) return NULL;

    uint32_t k = ((uint32_t)(uint8_t)code[0] << 24) |
                 ((uint32_t)(uint8_t)code[1] << 16) |
                 ((uint32_t)(uint8_t)code[2] <<  8) |
                  (uint32_t)(uint8_t)code[3];
    return resolve_std(bsearch_u32(EUI_KIND_DRONE_MFR, k), f, c);
}

const char *eui_class_label(uint8_t class_id)
{
    switch (class_id) {
    case EUI_CLASS_ENTERPRISE_AP:    return "ENT-AP";
    case EUI_CLASS_CONSUMER_AP:      return "CONSUMER";
    case EUI_CLASS_IOT_HUB:          return "IOT-HUB";
    case EUI_CLASS_IOT_LEAF:         return "IOT";
    case EUI_CLASS_MOBILE:           return "MOBILE";
    case EUI_CLASS_SURVEILLANCE_CAM: return "CAMERA";
    case EUI_CLASS_INVESTIGATION:    return "INVEST";
    case EUI_CLASS_MAKER_BOARD:      return "MAKER";
    case EUI_CLASS_DEV_MODULE:       return "DEV-MOD";
    case EUI_CLASS_BEACON:           return "BEACON";
    case EUI_CLASS_TRACKER:          return "TRACKER";
    case EUI_CLASS_WEARABLE:         return "WEAR";
    case EUI_CLASS_MEDICAL:          return "MEDICAL";
    case EUI_CLASS_AUTOMOTIVE:       return "AUTO";
    case EUI_CLASS_STANDARDS:        return "STDS";
    case EUI_CLASS_ATTACK_SIGNAL:    return "ATTACK";
    case EUI_CLASS_PHONE:            return "PHONE";
    case EUI_CLASS_TABLET:           return "TABLET";
    case EUI_CLASS_LAPTOP:           return "LAPTOP";
    case EUI_CLASS_AUDIO:            return "AUDIO";
    case EUI_CLASS_ACCESS_CONTROL:   return "LOCK";
    case EUI_CLASS_INFRASTRUCTURE:   return "INFRA";
    case EUI_CLASS_POS_PAYMENT:      return "POS";
    case EUI_CLASS_VEHICLE:          return "VEHICLE";
    case EUI_CLASS_DRONE:            return "DRONE";
    case EUI_CLASS_SURVEILLANCE_OUI: return "CAM-OUI?";
    case EUI_CLASS_ROGUE_HW_OUI:     return "ROGUE-HW?";
    default:                         return "";
    }
}
