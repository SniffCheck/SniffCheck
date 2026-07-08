

#include "apple_continuity.h"
#include <stdio.h>
#include <string.h>

static uint8_t subtype_priority(uint8_t subtype)
{
    switch (subtype) {
        case APPLE_SUB_AIRTAG:        return 100;
        case APPLE_SUB_FIND_MY_SEP:   return 95;
        case APPLE_SUB_HANDOFF:       return 80;
        case APPLE_SUB_NEARBY_INFO:   return 70;
        case APPLE_SUB_AIRDROP:       return 60;
        case APPLE_SUB_AIRPLAY:       return 50;
        case APPLE_SUB_AIRPODS_PROX:  return 45;
        case APPLE_SUB_HEY_SIRI:      return 40;
        case APPLE_SUB_TETHERING_SRC: return 35;
        case APPLE_SUB_HOMEKIT:       return 30;
        case APPLE_SUB_IBEACON:       return 25;
        case APPLE_SUB_NEARBY_ACTION: return 20;
        case APPLE_SUB_MAGIC_SWITCH:  return 15;
        case APPLE_SUB_TETHERING_TGT: return 10;
        default:                      return 0;
    }
}

const char *apple_subtype_label(uint8_t subtype)
{
    switch (subtype) {
        case APPLE_SUB_IBEACON:        return "iBeacon";
        case APPLE_SUB_AIRDROP:        return "AirDrop";
        case APPLE_SUB_HOMEKIT:        return "HomeKit";
        case APPLE_SUB_AIRPODS_PROX:   return "AirPods";
        case APPLE_SUB_HEY_SIRI:       return "HeySiri";
        case APPLE_SUB_AIRPLAY:        return "AirPlay";
        case APPLE_SUB_MAGIC_SWITCH:   return "MagicSw";
        case APPLE_SUB_HANDOFF:        return "Handoff";
        case APPLE_SUB_TETHERING_TGT:  return "TethTgt";
        case APPLE_SUB_TETHERING_SRC:  return "Hotspot";
        case APPLE_SUB_NEARBY_ACTION:  return "NbyAct";
        case APPLE_SUB_NEARBY_INFO:    return "NbyInfo";
        case APPLE_SUB_AIRTAG:         return "FindMy";
        case APPLE_SUB_FIND_MY_SEP:    return "FindMySep";
        default:                       return "?";
    }
}

const char *apple_nearby_state_label(uint8_t state_nibble)
{
    switch (state_nibble & 0x0F) {
        case 0x00: return "Inactive";
        case 0x01: return "Idle";
        case 0x03: return "Locked";
        case 0x05: return "RingingFM";
        case 0x07: return "Unlocked";
        case 0x09: return "Auth";
        case 0x0A: return "AVPlaying";
        case 0x0B: return "ActiveAudio";
        case 0x0D: return "Calling";
        default:   return "?";
    }
}

const char *apple_airtag_state_label(uint8_t status_byte, uint8_t adv_length)
{
    if (adv_length != 0x19) return "FindMyAcc";
    return (status_byte & 0x20) ? "Maintained" : "Separated";
}

apple_devcat_t apple_hey_siri_devcat(uint16_t device_class)
{
    switch (device_class) {
        case 0x0002: return APPLE_DEVCAT_IPHONE;
        case 0x0003: return APPLE_DEVCAT_IPAD;
        case 0x0007: return APPLE_DEVCAT_HOMEPOD;
        case 0x0009: return APPLE_DEVCAT_MACBOOK;
        case 0x000A: return APPLE_DEVCAT_WATCH;
        default:     return APPLE_DEVCAT_UNKNOWN;
    }
}

const char *apple_devcat_label(apple_devcat_t cat)
{
    switch (cat) {
        case APPLE_DEVCAT_IPHONE:  return "iPhone";
        case APPLE_DEVCAT_IPAD:    return "iPad";
        case APPLE_DEVCAT_MACBOOK: return "MacBook";
        case APPLE_DEVCAT_WATCH:   return "Apple Watch";
        case APPLE_DEVCAT_HOMEPOD: return "HomePod";
        default:                   return NULL;
    }
}

static void evidence_append(char *buf, size_t bufsz, const char *token)
{
    if (!buf || bufsz == 0 || !token || !token[0]) return;
    size_t cur = strnlen(buf, bufsz);
    if (cur >= bufsz - 1) return;
    if (cur > 0 && cur + 2 < bufsz) {
        buf[cur++] = ',';
        buf[cur++] = ' ';
        buf[cur] = '\0';
    }
    size_t room = bufsz - 1 - cur;
    strncat(buf, token, room);
    buf[bufsz - 1] = '\0';
}

void apple_continuity_decode(ble_device_t *d, const uint8_t *payload, size_t len)
{
    if (!d || !payload || len < 2) return;

    d->apple_evidence[0] = '\0';

    uint8_t best_subtype  = d->apple_subtype;
    uint8_t best_priority = subtype_priority(best_subtype);
    uint8_t best_state    = 0;

    size_t i = 0;
    while (i + 2 <= len) {
        uint8_t st  = payload[i];
        uint8_t tlv = payload[i + 1];
        size_t body_off = i + 2;
        size_t body_len = tlv;
        if (body_off + body_len > len) {

            if (body_off >= len) break;
            body_len = len - body_off;
        }
        const uint8_t *body = payload + body_off;

        uint8_t state = 0;
        switch (st) {
            case APPLE_SUB_NEARBY_INFO:

                if (body_len >= 1) state = body[0] & 0x0F;
                break;
            case APPLE_SUB_AIRTAG:

                if (body_len >= 1) state = body[0];
                break;
            case APPLE_SUB_FIND_MY_SEP:

                if (body_len >= 1) state = body[0];
                break;
            case APPLE_SUB_AIRPODS_PROX:

                if (body_len >= 1) state = body[0];
                break;
            case APPLE_SUB_HEY_SIRI:

                if (body_len >= 6) {
                    uint16_t le = (uint16_t)body[4] | ((uint16_t)body[5] << 8);
                    uint16_t be = ((uint16_t)body[4] << 8) | (uint16_t)body[5];
                    apple_devcat_t cat = apple_hey_siri_devcat(le);
                    if (cat == APPLE_DEVCAT_UNKNOWN) cat = apple_hey_siri_devcat(be);
                    if (cat != APPLE_DEVCAT_UNKNOWN) d->apple_devcat = (uint8_t)cat;
                }
                break;
            case APPLE_SUB_IBEACON:

                break;
            default:
                break;
        }

        const char *label = apple_subtype_label(st);
        if (label[0] != '?') {
            evidence_append(d->apple_evidence, sizeof(d->apple_evidence), label);
        }

        uint8_t prio = subtype_priority(st);
        if (st == APPLE_SUB_AIRTAG && tlv != 0x19) {
            prio = 35;
        }
        if (prio > best_priority) {
            best_priority = prio;
            best_subtype  = st;
            best_state    = state;
        }

        if (tlv == 0) {

            i = body_off;
        } else {
            i = body_off + tlv;
        }
    }

    d->apple_subtype = best_subtype;
    d->apple_state   = best_state;
}
