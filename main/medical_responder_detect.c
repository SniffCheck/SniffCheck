#include "medical_responder_detect.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

typedef struct {
    const char       *token;
    mr_device_type_t  dt;
    uint8_t           conf;
} mr_rule_t;

static const mr_rule_t MR_RULES[] = {

    { "lifepak",                   MR_DEV_MEDICAL_MONITOR,   55 },
    { "lifenet",                   MR_DEV_MEDICAL_MONITOR,   55 },
    { "propaq",                    MR_DEV_MEDICAL_MONITOR,   55 },
    { "heartstart",                MR_DEV_MEDICAL_MONITOR,   55 },
    { "intellivue",                MR_DEV_MEDICAL_MONITOR,   50 },
    { "corpuls",                   MR_DEV_MEDICAL_MONITOR,   55 },
    { "tempus",                    MR_DEV_MEDICAL_MONITOR,   50 },

    { "american medical response", MR_DEV_AMBULANCE_GATEWAY, 55 },
    { "acadian ambulance",         MR_DEV_AMBULANCE_GATEWAY, 55 },
    { "rural/metro",               MR_DEV_AMBULANCE_GATEWAY, 50 },
    { "air methods",               MR_DEV_AIR_AMBULANCE,     50 },
    { "life flight",               MR_DEV_AIR_AMBULANCE,     50 },

    { "firstnet",                  MR_DEV_UNKNOWN,           50 },

    { "zoll",                      MR_DEV_MEDICAL_MONITOR,   50 },
    { "medtronic",                 MR_DEV_MEDICAL_MONITOR,   50 },
    { "physio-control",            MR_DEV_MEDICAL_MONITOR,   55 },
    { "welch allyn",               MR_DEV_MEDICAL_MONITOR,   50 },
    { "mindray",                   MR_DEV_MEDICAL_MONITOR,   50 },
    { "nihon kohden",              MR_DEV_MEDICAL_MONITOR,   50 },
    { "spacelabs",                 MR_DEV_MEDICAL_MONITOR,   50 },
    { "draeger",                   MR_DEV_MEDICAL_MONITOR,   45 },
    { "masimo",                    MR_DEV_MEDICAL_MONITOR,   45 },

    { "paramedic",                 MR_DEV_OTHER,             45 },
    { "ambulance",                 MR_DEV_AMBULANCE_GATEWAY, 45 },
};
#define MR_RULE_COUNT (sizeof(MR_RULES) / sizeof(MR_RULES[0]))

static bool mr_icontains(const char *hay, const char *needle)
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

static const mr_rule_t *mr_match(const char *s)
{
    if (!s || !s[0]) return NULL;
    for (size_t i = 0; i < MR_RULE_COUNT; i++)
        if (mr_icontains(s, MR_RULES[i].token)) return &MR_RULES[i];
    return NULL;
}

static void mr_add_evidence(mr_result_t *r, uint8_t layer, const mr_rule_t *rule,
                            const char *source, const uint8_t mac[6])
{
    if (!r || !rule) return;
    r->matches++;
    if (rule->conf >= 70) r->strong_matches++;
    if (rule->dt < MR_DEV_TYPE_COUNT) r->device_counts[rule->dt]++;
    if (rule->conf > r->confidence) r->confidence = rule->conf;

    if (r->evidence_count < MR_MAX_EVIDENCE) {
        mr_evidence_t *e = &r->evidence[r->evidence_count++];
        e->layer = layer;
        e->device_type = (uint8_t)rule->dt;
        e->confidence = rule->conf;
        snprintf(e->source, sizeof(e->source), "%s", source ? source : "");
        snprintf(e->label, sizeof(e->label), "%s", rule->token);
        mac_to_str(mac, e->target);
    }
}

static mr_result_t s_last;

void medical_responder_begin(mr_result_t *r)
{
    if (r) memset(r, 0, sizeof(*r));
}

void medical_responder_eval_wifi(const ap_score_t *ap, mr_result_t *r)
{
    if (!ap || !r) return;
    const mr_rule_t *m = mr_match(ap->ssid);
    if (!m) m = mr_match(ap->vendor);
    if (m) mr_add_evidence(r, 0, m, "ssid_rule", ap->bssid);
}

void medical_responder_eval_ble(const ble_device_t *d, mr_result_t *r)
{
    if (!d || !r) return;
    const mr_rule_t *m = mr_match(d->name);
    const char *src = "ble_name";
    if (!m) { m = mr_match(d->vendor); src = "vendor"; }
    if (!m) { m = mr_match(d->company_name); src = "vendor"; }
    if (m) mr_add_evidence(r, 1, m, src, d->addr);
}

void medical_responder_finalize(mr_result_t *r)
{
    if (!r) return;
    r->could_be_first_responder = (r->matches > 0);

    if (r->matches == 0)          r->presence = MR_PRESENCE_NONE;
    else if (r->confidence >= 80) r->presence = MR_PRESENCE_CONFIRMED;
    else if (r->confidence >= 55) r->presence = MR_PRESENCE_LIKELY;
    else                          r->presence = MR_PRESENCE_POSSIBLE;

    s_last = *r;
}

const mr_result_t *medical_responder_last(void)
{
    return &s_last;
}

const char *medical_responder_presence_label(mr_presence_t p)
{
    switch (p) {
    case MR_PRESENCE_POSSIBLE:  return "possible";
    case MR_PRESENCE_LIKELY:    return "likely";
    case MR_PRESENCE_CONFIRMED: return "confirmed_identifier";
    case MR_PRESENCE_NONE:
    default:                    return "none";
    }
}

const char *medical_responder_device_type_label(mr_device_type_t t)
{
    switch (t) {
    case MR_DEV_AMBULANCE_GATEWAY: return "ambulance_gateway";
    case MR_DEV_EMS_TABLET:        return "ems_tablet";
    case MR_DEV_MEDICAL_MONITOR:   return "medical_monitor";
    case MR_DEV_RADIO_ACCESSORY:   return "radio_accessory";
    case MR_DEV_EMS_CAMERA:        return "ems_camera";
    case MR_DEV_AIR_AMBULANCE:     return "air_ambulance";
    case MR_DEV_HOSPITAL_EMS:      return "hospital_ems";
    case MR_DEV_OTHER:             return "other_medical_responder";
    case MR_DEV_UNKNOWN:
    default:                       return "unknown";
    }
}
