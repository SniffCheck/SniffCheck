#include "public_safety_detect.h"
#include "eui_db.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

static bool ps_icontains(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0]) return false;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl) return true;
    }
    return false;
}

static void mac_to_str(const uint8_t mac[6], char out[18])
{
    if (!mac) { out[0] = 0; return; }
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ps_add_evidence(ps_result_t *r, uint8_t layer, ps_device_type_t dt,
                            uint8_t conf, const char *source, const char *label,
                            const uint8_t mac[6])
{
    if (!r) return;
    r->matches++;
    if (conf >= 70) r->strong_matches++;
    if (dt < PS_DEV_TYPE_COUNT) r->device_counts[dt]++;
    if (conf > r->confidence) r->confidence = conf;

    if (r->evidence_count < PS_MAX_EVIDENCE) {
        ps_evidence_t *e = &r->evidence[r->evidence_count++];
        e->layer = layer;
        e->device_type = (uint8_t)dt;
        e->confidence = conf;
        snprintf(e->source, sizeof(e->source), "%s", source ? source : "");
        snprintf(e->label, sizeof(e->label), "%s", label ? label : "");
        mac_to_str(mac, e->target);
    }
}

static bool ps_subtype_from_name(const char *s, ps_device_type_t *dt, uint8_t *conf)
{
    if (!s || !s[0]) return false;
    if (ps_icontains(s, "taser"))      { *dt = PS_DEV_TASER;         *conf = 80; return true; }
    if (ps_icontains(s, "axon body") ||
        ps_icontains(s, "bodycam")   ||
        ps_icontains(s, "body cam"))   { *dt = PS_DEV_BODY_CAMERA;   *conf = 80; return true; }
    if (ps_icontains(s, "axon fleet")) { *dt = PS_DEV_IN_CAR_CAMERA; *conf = 75; return true; }
    if (ps_icontains(s, "axon dock"))  { *dt = PS_DEV_OTHER;         *conf = 55; return true; }
    return false;
}

static ps_result_t s_last;

void public_safety_begin(ps_result_t *r)
{
    if (r) memset(r, 0, sizeof(*r));
}

void public_safety_eval_wifi(const ap_score_t *ap, ps_result_t *r)
{
    if (!ap || !r) return;

    ps_device_type_t dt; uint8_t conf;

    if (ps_subtype_from_name(ap->ssid, &dt, &conf)) {
        ps_add_evidence(r, 0, dt, conf, "ssid_rule", "ps_device_ssid", ap->bssid);
        return;
    }

    if (ps_icontains(ap->vendor, "axon enterprise")) {
        ps_add_evidence(r, 0, PS_DEV_UNKNOWN, 55, "vendor", "axon_enterprise", ap->bssid);
    }
}

void public_safety_eval_ble(const ble_device_t *d, ps_result_t *r)
{
    if (!d || !r) return;

    ps_device_type_t dt; uint8_t conf;

    if (ps_subtype_from_name(d->name, &dt, &conf)) {
        ps_add_evidence(r, 1, dt, conf, "ble_name", "ps_device_name", d->addr);
        return;
    }

    if (ps_icontains(d->vendor, "axon enterprise") ||
        ps_icontains(d->company_name, "axon enterprise")) {
        ps_add_evidence(r, 1, PS_DEV_UNKNOWN, 60, "vendor", "axon_enterprise", d->addr);
    }
}

void public_safety_finalize(ps_result_t *r)
{
    if (!r) return;

    const uint16_t body   = r->device_counts[PS_DEV_BODY_CAMERA];
    const uint16_t taser  = r->device_counts[PS_DEV_TASER];
    const uint16_t radio  = r->device_counts[PS_DEV_RADIO];
    const uint16_t rugged = r->device_counts[PS_DEV_RUGGED_DEVICE];
    const uint16_t unkn   = r->device_counts[PS_DEV_UNKNOWN];

    const uint16_t base  = body > taser ? body : taser;
    const uint16_t extra = (uint16_t)(radio + rugged + unkn);

    if (base > 0) {
        r->estimated_officers_low  = base;
        r->estimated_officers_high = (uint16_t)(base + extra);
    } else if (extra > 0) {
        r->estimated_officers_low  = 1;
        r->estimated_officers_high = extra;
    } else {
        r->estimated_officers_low  = 0;
        r->estimated_officers_high = 0;
    }

    if (r->matches == 0)            r->presence = PS_PRESENCE_NONE;
    else if (r->confidence >= 80)   r->presence = PS_PRESENCE_CONFIRMED;
    else if (r->confidence >= 60)   r->presence = PS_PRESENCE_LIKELY;
    else                            r->presence = PS_PRESENCE_POSSIBLE;

    s_last = *r;
}

const ps_result_t *public_safety_last(void)
{
    return &s_last;
}

const char *public_safety_presence_label(ps_presence_t p)
{
    switch (p) {
    case PS_PRESENCE_POSSIBLE:  return "possible";
    case PS_PRESENCE_LIKELY:    return "likely";
    case PS_PRESENCE_CONFIRMED: return "confirmed_identifier";
    case PS_PRESENCE_NONE:
    default:                    return "none";
    }
}

const char *public_safety_device_type_label(ps_device_type_t t)
{
    switch (t) {
    case PS_DEV_BODY_CAMERA:    return "body_camera";
    case PS_DEV_TASER:          return "taser";
    case PS_DEV_IN_CAR_CAMERA:  return "in_car_camera";
    case PS_DEV_RADIO:          return "radio";
    case PS_DEV_VEHICLE_GATEWAY:return "vehicle_gateway";
    case PS_DEV_RUGGED_DEVICE:  return "rugged_device";
    case PS_DEV_OTHER:          return "other_public_safety";
    case PS_DEV_UNKNOWN:
    default:                    return "unknown";
    }
}
