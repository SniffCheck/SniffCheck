#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#define EUI_DB_VERSION       3

#define EUI_DB_MAX_SECTIONS  64

#define EUI_KIND_MAC24            1
#define EUI_KIND_MAC28            2
#define EUI_KIND_MAC36            3
#define EUI_KIND_IAB              4
#define EUI_KIND_CID              5
#define EUI_KIND_MALICIOUS        6
#define EUI_KIND_BT_COMPANY      10
#define EUI_KIND_BT_UUID16       11
#define EUI_KIND_BT_UUID32       12
#define EUI_KIND_BT_UUID128      13
#define EUI_KIND_MFG_RULE        20
#define EUI_KIND_APPLE_SUBTYPE   21
#define EUI_KIND_MS_SUBTYPE      22
#define EUI_KIND_FAST_PAIR       23
#define EUI_KIND_NAME_RULE       24
#define EUI_KIND_VENDOR_IE       30
#define EUI_KIND_SSID_RULE       31
#define EUI_KIND_IE_SIGNATURE    32
#define EUI_KIND_WPS_MFG         33
#define EUI_KIND_RSN_OUI         34
#define EUI_KIND_COUNTRY         35
#define EUI_KIND_CDP_ORG         40
#define EUI_KIND_LLDP_ORG        41
#define EUI_KIND_DHCP_VC         42
#define EUI_KIND_DHCP_FP         43
#define EUI_KIND_FCC_GRANTEE     50
#define EUI_KIND_FCC_COVERED     51
#define EUI_KIND_DRONE_MFR       60

#define EUI_FLAG_KNOWN_MALICIOUS    0x0001
#define EUI_FLAG_ENTERPRISE_GRADE   0x0002
#define EUI_FLAG_CONSUMER_GRADE     0x0004
#define EUI_FLAG_IOT_DEVICE         0x0008
#define EUI_FLAG_MOBILE_DEVICE      0x0010
#define EUI_FLAG_REGISTRY_OUI28     0x0020
#define EUI_FLAG_REGISTRY_OUI36     0x0040
#define EUI_FLAG_REGISTRY_CID       0x0080
#define EUI_FLAG_SURVEILLANCE       0x0100
#define EUI_FLAG_INVESTIGATION      0x0200
#define EUI_FLAG_MAKER              0x0400
#define EUI_FLAG_DEV_MODULE         0x0800
#define EUI_FLAG_STANDARDS          0x1000
#define EUI_FLAG_PRIVATE_ASSIGN     0x2000
#define EUI_FLAG_FCC_COVERED        0x4000
#define EUI_FLAG_FCC_APPROVED       0x8000

typedef enum {
    EUI_CLASS_UNKNOWN          = 0,
    EUI_CLASS_ENTERPRISE_AP    = 1,
    EUI_CLASS_CONSUMER_AP      = 2,
    EUI_CLASS_IOT_HUB          = 3,
    EUI_CLASS_IOT_LEAF         = 4,
    EUI_CLASS_MOBILE           = 5,
    EUI_CLASS_SURVEILLANCE_CAM = 6,
    EUI_CLASS_INVESTIGATION    = 7,
    EUI_CLASS_MAKER_BOARD      = 8,
    EUI_CLASS_DEV_MODULE       = 9,
    EUI_CLASS_BEACON           = 10,
    EUI_CLASS_TRACKER          = 11,
    EUI_CLASS_WEARABLE         = 12,
    EUI_CLASS_MEDICAL          = 13,
    EUI_CLASS_AUTOMOTIVE       = 14,
    EUI_CLASS_STANDARDS        = 15,
    EUI_CLASS_ATTACK_SIGNAL    = 16,
    EUI_CLASS_PHONE            = 17,
    EUI_CLASS_TABLET           = 18,
    EUI_CLASS_LAPTOP           = 19,
    EUI_CLASS_AUDIO            = 20,
    EUI_CLASS_ACCESS_CONTROL   = 21,
    EUI_CLASS_INFRASTRUCTURE   = 22,
    EUI_CLASS_POS_PAYMENT      = 23,
    EUI_CLASS_VEHICLE          = 24,
    EUI_CLASS_DRONE            = 25,

    EUI_CLASS_SURVEILLANCE_OUI = 26,

    EUI_CLASS_ROGUE_HW_OUI     = 27,
} eui_class_t;

typedef struct __attribute__((packed)) {
    uint32_t key;
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  reserved;
    uint32_t name_off;
} eui_record_std_t;

typedef struct __attribute__((packed)) {
    uint64_t key;
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  reserved;
    uint32_t name_off;
} eui_record_wide_t;

typedef struct __attribute__((packed)) {
    uint8_t  key[16];
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  reserved;
    uint32_t name_off;
} eui_record_uuid128_t;

typedef struct __attribute__((packed)) {
    uint16_t key;
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  reserved;
    uint16_t pad;
    uint32_t name_off;
} eui_record_tiny_t;

typedef struct __attribute__((packed)) {
    uint32_t key_hash;
    uint16_t company_id;
    uint8_t  prefix_len;
    uint8_t  prefix[6];
    uint8_t  reserved[3];
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  subtype;
    uint32_t name_off;
} eui_record_rule_t;

#define EUI_SSID_MATCH_EXACT     0
#define EUI_SSID_MATCH_PREFIX    1
#define EUI_SSID_MATCH_SUFFIX    2
#define EUI_SSID_MATCH_CONTAINS  3
#define EUI_SSID_MATCH_COMPOUND  4

typedef struct __attribute__((packed)) {
    uint32_t pattern_off;
    uint32_t name_off;
    uint16_t flags;
    uint8_t  class_id;
    uint8_t  match_type;
    uint32_t reserved;
} eui_record_ssid_t;

esp_err_t eui_db_init(void);

const char *eui_lookup_mac(const uint8_t mac[6],
                           uint16_t *flags_out,
                           uint8_t  *class_out,
                           uint8_t  *match_len_out);

const char *eui_lookup(const uint8_t mac[6],
                       uint16_t *flags_out,
                       uint8_t  *class_out);

const char *eui_lookup_company(uint16_t cid,
                               uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_uuid16(uint16_t uuid,
                              uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_uuid32(uint32_t uuid,
                              uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_uuid128(const uint8_t uuid[16],
                               uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_apple_subtype(uint8_t subtype,
                                     uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_ms_subtype(uint8_t subtype,
                                  uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_fastpair(uint32_t model_id,
                                uint16_t *flags_out, uint8_t *class_out);

const char *eui_match_mfg_data(uint16_t company_id,
                               const uint8_t *payload, size_t len,
                               uint16_t *flags_out,
                               uint8_t  *class_out,
                               uint8_t  *subtype_out);

#define EUI_NAME_RULE_GENERIC      0
#define EUI_NAME_RULE_PHONE_MODEL  1

const char *eui_match_name(const char *name,
                           uint16_t *flags_out, uint8_t *class_out,
                           uint8_t *kind_out);

const char *eui_lookup_vendor_ie(const uint8_t oui[3],
                                 uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_wps(const char *manufacturer,
                           uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_ie_signature(uint32_t ie_hash,
                                    uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_rsn_oui(const uint8_t oui[3], uint8_t suite_type,
                               uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_country(const char cc[2],
                               uint16_t *flags_out, uint8_t *class_out);

const char *eui_match_ssid(const char *ssid,
                           uint16_t *flags_out, uint8_t *class_out);

const char *eui_lookup_cdp_org(const uint8_t oui[3],
                               uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_lldp_org(const uint8_t oui[3],
                                uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_dhcp_vc(const char *vendor_class,
                               uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_dhcp_fp(const uint8_t *opt55, size_t n,
                               uint16_t *flags_out, uint8_t *class_out);

const char *eui_lookup_fcc_grantee(const char grantee[3],
                                   uint16_t *flags_out, uint8_t *class_out);
const char *eui_lookup_fcc_covered(const char *name,
                                   uint16_t *flags_out, uint8_t *class_out);

const char *eui_lookup_drone_mfr(const char code[4],
                                 uint16_t *flags_out, uint8_t *class_out);

static inline bool mac_is_laa(const uint8_t mac[6]) {
    return (mac[0] & 0x02) != 0;
}

static inline bool mac_is_multicast(const uint8_t mac[6]) {
    return (mac[0] & 0x01) != 0;
}

const char *eui_class_label(uint8_t class_id);
