#include "frame_parser.h"
#include "eui_db.h"
#include "drone_rid.h"
#include <string.h>

#define FC_TYPE_MGMT         0x00
#define FC_SUBTYPE_PROBE_REQ  0x04
#define FC_SUBTYPE_PROBE_RESP 0x05
#define FC_SUBTYPE_BEACON     0x08
#define FC_SUBTYPE_DISASSOC   0x0A
#define FC_SUBTYPE_DEAUTH     0x0C
#define FC_SUBTYPE_ACTION     0x0D

#define ACTION_CATEGORY_PUBLIC  4
#define PUBLIC_ACTION_GAS_INIT_REQ  10

#define PUBLIC_ACTION_VENDOR_SPECIFIC  9

#define IE_SSID       0
#define IE_DS_PARAM   3
#define IE_COUNTRY    7
#define IE_RSN       48
#define IE_VENDOR   221

#define MGMT_HDR    24

#define BCN_FIX     12

#define RSN_MFPR    0x40
#define RSN_MFPC    0x80

static const uint8_t WPS_OUI_TYPE[4] = { 0x00, 0x50, 0xf2, 0x04 };

static const uint8_t MS_OUI[3] = { 0x00, 0x50, 0xf2 };

#define WPS_SUBEL_DEVICE_NAME    0x1011
#define WPS_SUBEL_MANUFACTURER   0x1021
#define WPS_SUBEL_MODEL_NAME     0x1023

static inline uint32_t fnv1a_step(uint32_t h, uint8_t b)
{
    return (h ^ b) * 16777619u;
}

static void copy_wps_string(char *out, const uint8_t *src, uint16_t src_len)
{
    if (src_len > 32) src_len = 32;
    memcpy(out, src, src_len);
    out[src_len] = '\0';
}

static void parse_wps_subelements(const uint8_t *p, uint16_t len, parsed_mgmt_t *out)
{
    uint16_t pos = 0;
    while (pos + 4 <= len) {
        uint16_t type    = ((uint16_t)p[pos]     << 8) | p[pos + 1];
        uint16_t sub_len = ((uint16_t)p[pos + 2] << 8) | p[pos + 3];
        pos += 4;
        if (pos + sub_len > len) break;
        switch (type) {
        case WPS_SUBEL_DEVICE_NAME:
            if (!out->wps_device_name[0])
                copy_wps_string(out->wps_device_name, p + pos, sub_len);
            break;
        case WPS_SUBEL_MANUFACTURER:
            if (!out->wps_manufacturer[0])
                copy_wps_string(out->wps_manufacturer, p + pos, sub_len);
            break;
        case WPS_SUBEL_MODEL_NAME:
            if (!out->wps_model_name[0])
                copy_wps_string(out->wps_model_name, p + pos, sub_len);
            break;
        default: break;
        }
        pos += sub_len;
    }
}

static void parse_ies(const uint8_t *ie, uint16_t ie_len, parsed_mgmt_t *out)
{
    uint16_t pos = 0;
    uint32_t pattern = 2166136261u;

    while (pos + 2 <= ie_len) {
        uint8_t id  = ie[pos];
        uint8_t len = ie[pos + 1];
        pos += 2;
        if (pos + len > ie_len) break;
        const uint8_t *v = &ie[pos];

        pattern = fnv1a_step(pattern, id);

        switch (id) {
        case IE_SSID:
            if (len <= 32) {
                memcpy(out->ssid, v, len);
                out->ssid[len] = '\0';
            }
            break;

        case IE_DS_PARAM:
            if (len == 1) out->ds_channel = v[0];
            break;

        case IE_COUNTRY:
            if (len >= 2) {
                out->country_code[0] = (char)v[0];
                out->country_code[1] = (char)v[1];
                out->country_code[2] = '\0';
            }
            break;

        case IE_RSN: {
            out->has_rsn = true;

            if (len < 8) { out->rsn_malformed = true; break; }
            uint16_t ver = (uint16_t)v[0] | ((uint16_t)v[1] << 8);
            if (ver != 1) { out->rsn_malformed = true; break; }

            memcpy(out->rsn_group_oui, v + 2, 3);
            out->rsn_group_suite = v[5];

            uint16_t off = 6;
            uint16_t pw_cnt = (uint16_t)v[4] | ((uint16_t)v[5] << 8);
            off += (uint16_t)(pw_cnt * 4);
            if (off + 2 > len) break;
            uint16_t akm_cnt = (uint16_t)v[off] | ((uint16_t)v[off + 1] << 8);
            off += 2 + (uint16_t)(akm_cnt * 4);
            if (off + 2 > len) break;

            out->rsn_pmf_required = (v[off] & RSN_MFPR) != 0;
            out->rsn_pmf_capable  = (v[off] & RSN_MFPC) != 0;
            break;
        }

        case IE_VENDOR:
            if (len >= 4 && memcmp(v, WPS_OUI_TYPE, 4) == 0) {
                out->has_wps = true;
                if (len > 4)
                    parse_wps_subelements(v + 4, len - 4, out);
            } else if (!out->has_rid &&
                       drone_rid_decode_wifi_beacon(v, len, &out->rid)) {

                out->has_rid = true;
            } else if (len >= 3 && memcmp(v, MS_OUI, 3) != 0
                       && out->vendor_ie_count < 4) {

                bool dup = false;
                for (uint8_t k = 0; k < out->vendor_ie_count; k++) {
                    if (memcmp(out->vendor_ie_ouis[k], v, 3) == 0) { dup = true; break; }
                }
                if (!dup) {
                    uint8_t idx = out->vendor_ie_count++;
                    memcpy(out->vendor_ie_ouis[idx], v, 3);
                    uint16_t f = 0; uint8_t c = 0;
                    out->vendor_ie_names[idx] = eui_lookup_vendor_ie(v, &f, &c);
                }
            }
            break;

        default:
            break;
        }

        pos += len;
    }
    out->ie_pattern_hash = pattern;
}

bool frame_parse_mgmt(const uint8_t *data, uint16_t len, parsed_mgmt_t *out)
{
    if (!data || !out || len < MGMT_HDR) return false;

    memset(out, 0, sizeof(*out));
    out->type = MGMT_NOT_MGMT;

    uint8_t fc0      = data[0];
    uint8_t fc_type  = (fc0 >> 2) & 0x03;
    uint8_t fc_sub   = (fc0 >> 4) & 0x0F;

    if (fc_type != FC_TYPE_MGMT) return false;

    memcpy(out->bssid, &data[10], 6);

    switch (fc_sub) {
    case FC_SUBTYPE_BEACON:     out->type = MGMT_BEACON;     break;
    case FC_SUBTYPE_PROBE_RESP: out->type = MGMT_PROBE_RESP; break;
    case FC_SUBTYPE_PROBE_REQ:  out->type = MGMT_PROBE_REQ;  break;
    case FC_SUBTYPE_DEAUTH:     out->type = MGMT_DEAUTH;     break;
    case FC_SUBTYPE_DISASSOC:   out->type = MGMT_DISASSOC;   break;
    case FC_SUBTYPE_ACTION:

        if (len >= MGMT_HDR + 2
            && data[MGMT_HDR + 0] == ACTION_CATEGORY_PUBLIC
            && data[MGMT_HDR + 1] == PUBLIC_ACTION_GAS_INIT_REQ) {
            out->type = MGMT_ANQP;
            return true;
        }

        if (len >= MGMT_HDR + 2
            && data[MGMT_HDR + 0] == ACTION_CATEGORY_PUBLIC
            && data[MGMT_HDR + 1] == PUBLIC_ACTION_VENDOR_SPECIFIC
            && drone_rid_decode_wifi_nan(data, len, &out->rid)) {
            out->has_rid = true;
        }
        out->type = MGMT_OTHER;
        return true;
    default:                    out->type = MGMT_OTHER;       return true;
    }

    if (out->type == MGMT_BEACON || out->type == MGMT_PROBE_RESP) {
        if (len < MGMT_HDR + BCN_FIX) return true;
        out->beacon_interval = (uint16_t)data[MGMT_HDR + 8]
                             | ((uint16_t)data[MGMT_HDR + 9] << 8);

        out->privacy = (data[MGMT_HDR + 10] & 0x10) != 0;
        uint16_t ie_off = MGMT_HDR + BCN_FIX;
        parse_ies(&data[ie_off], len - ie_off, out);
    } else if (out->type == MGMT_PROBE_REQ) {

        uint16_t seq_ctrl = (uint16_t)data[22] | ((uint16_t)data[23] << 8);
        out->seq_num = seq_ctrl >> 4;
        parse_ies(&data[MGMT_HDR], len - MGMT_HDR, out);
    }

    return true;
}
