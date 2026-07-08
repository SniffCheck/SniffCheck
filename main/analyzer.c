#include "analyzer.h"
#include "eui_db.h"
#include "apple_continuity.h"
#include "wifi_sniffer.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static const char *TAG = "sc_analyze";

#define TIER_MASK  (EUI_FLAG_ENTERPRISE_GRADE | EUI_FLAG_CONSUMER_GRADE | EUI_FLAG_IOT_DEVICE)

static uint8_t v2_crypto_quality(wifi_auth_mode_t auth)
{
    switch (auth) {
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA3_ENTERPRISE:
    case WIFI_AUTH_WPA3_ENT_192:
        return 55;
    case WIFI_AUTH_WPA2_WPA3_PSK:
    case WIFI_AUTH_WPA2_WPA3_ENTERPRISE:
        return 52;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_ENTERPRISE:
        return 48;
    case WIFI_AUTH_OWE:          return 42;
    case WIFI_AUTH_WPA_WPA2_PSK: return 30;
    case WIFI_AUTH_WPA_PSK:      return 22;
    case WIFI_AUTH_WPA_ENTERPRISE: return 22;
    case WIFI_AUTH_WEP:          return 10;
    case WIFI_AUTH_OPEN:         return 35;
    default:                     return 35;
    }
}

static uint8_t v2_vendor_quality(uint16_t flags, bool is_laa, const char *vendor)
{
    if (is_laa && !vendor) return 5;
    if (!vendor)           return 8;
    if (flags & EUI_FLAG_ENTERPRISE_GRADE) return 20;
    if (flags & EUI_FLAG_CONSUMER_GRADE)   return 18;
    if (flags & EUI_FLAG_IOT_DEVICE)       return 12;
    return 14;
}

static uint8_t v2_signal_quality(int8_t rssi)
{
    if (rssi >= -50) return 15;
    if (rssi >= -60) return 14;
    if (rssi >= -70) return 13;
    if (rssi >= -80) return 10;
    if (rssi >= -88) return  6;
    return 2;
}

static uint8_t v2_standards_quality(bool has_rsn, bool rsn_malformed,
                                     uint16_t beacon_interval,
                                     wifi_auth_mode_t auth)
{
    uint8_t q = 0;
    if (has_rsn && !rsn_malformed) {
        q += 6;
    } else if (auth >= WIFI_AUTH_WPA2_PSK && auth != WIFI_AUTH_WAPI_PSK) {
        q += 6;
    }

    if ((beacon_interval >= 50 && beacon_interval <= 200) || beacon_interval == 0)
        q += 4;
    return q;
}

static uint8_t v2_base_quality(const ap_record_t *ap,
                                const sniffer_rec_t *sr,
                                uint16_t flags, bool is_laa,
                                const char *vendor)
{
    bool has_rsn  = sr && sr->has_rsn;
    bool mal_rsn  = sr && sr->rsn_malformed;
    uint16_t bi   = sr ? sr->beacon_interval : 0;
    uint16_t q = (uint16_t)v2_crypto_quality(ap->auth)
               + (uint16_t)v2_vendor_quality(flags, is_laa, vendor)
               + (uint16_t)v2_signal_quality(ap->rssi)
               + (uint16_t)v2_standards_quality(has_rsn, mal_rsn, bi, ap->auth);
    if (q > 100) q = 100;
    return (uint8_t)q;
}

static bool wifi_pmkid_exposed(const ap_record_t *ap);

static uint8_t v2_hygiene(const ap_record_t *ap, const sniffer_rec_t *sr)
{
    uint8_t h = 0;
    bool wps     = sr && sr->has_wps;
    bool has_rsn = sr && sr->has_rsn;
    bool pmf_req = sr && sr->rsn_pmf_required;
    bool pmf_cap = sr && sr->rsn_pmf_capable;

    if (wps) h += 4;

    if (has_rsn
        && ap->auth >= WIFI_AUTH_WPA2_PSK && ap->auth != WIFI_AUTH_WAPI_PSK
        && !pmf_req)
        h += pmf_cap ? 2 : 3;
    if (wifi_pmkid_exposed(ap))
        h += 2;
    return h;
}

const char *analyzer_tier_label(uint8_t tier)
{
    switch (tier) {
    case SCORE_TIER_ENTERPRISE: return "Enterprise";
    case SCORE_TIER_KNOWN:      return "Assumed good";
    case SCORE_TIER_ACCEPTABLE: return "Acceptable";
    case SCORE_TIER_SUSPECT:    return "Suspect";
    case SCORE_TIER_AVOID:      return "Avoid";
    default:                    return "Unknown";
    }
}

const char *analyzer_verdict_label(uint8_t v)
{
    switch (v) {
    case VERDICT_GREEN:  return "SAFE";
    case VERDICT_YELLOW: return "OK";
    case VERDICT_ORANGE: return "CAUTION";
    default:             return "AVOID";
    }
}

const char *analyzer_threat_label(uint8_t lvl)
{
    switch (lvl) {
    case THREAT_NONE:   return "none";
    case THREAT_LOW:    return "low";
    case THREAT_MEDIUM: return "medium";
    default:            return "high";
    }
}

uint8_t analyzer_threat_to_verdict(uint8_t threat_level)
{
    switch (threat_level) {
    case THREAT_NONE:   return VERDICT_GREEN;
    case THREAT_LOW:    return VERDICT_YELLOW;
    case THREAT_MEDIUM: return VERDICT_ORANGE;
    default:            return VERDICT_RED;
    }
}

const char *analyzer_twin_class(const ap_score_t *s)
{
    if (!s)                  return "none";
    if (s->open_clone)       return "high_confidence_clone";
    if (s->twin_detected)    return "possible_clone";
    if (s->vendor_mismatch)  return "caution_second_vendor";
    if (s->same_oui_multiband || s->radio_count > 1) return "ok_roaming_ess";
    return "none";
}

static bool ble_investigation_near(const ble_results_t *ble)
{
    if (!ble) return false;
    for (uint16_t i = 0; i < ble->count; i++) {
        uint16_t f = ble->devices[i].eui_flags
                   | ble->devices[i].bt_company_flags
                   | ble->devices[i].mfg_rule_flags
                   | ble->devices[i].apple_subtype_flags
                   | ble->devices[i].ms_subtype_flags
                   | ble->devices[i].uuid16_flags
                   | ble->devices[i].uuid32_flags
                   | ble->devices[i].uuid128_flags
                   | ble->devices[i].fastpair_flags
                   | ble->devices[i].name_rule_flags;
        if (f & (EUI_FLAG_INVESTIGATION | EUI_FLAG_KNOWN_MALICIOUS)) return true;
    }
    return false;
}

static bool wifi_class_is_endpoint(uint8_t cls)
{
    return cls == EUI_CLASS_MOBILE || cls == EUI_CLASS_PHONE ||
           cls == EUI_CLASS_TABLET || cls == EUI_CLASS_LAPTOP;
}

static bool wifi_class_can_refine(uint8_t cls)
{
    return cls == EUI_CLASS_UNKNOWN || wifi_class_is_endpoint(cls);
}

static uint16_t wifi_flags_for_class(uint8_t cls)
{
    switch (cls) {
    case EUI_CLASS_ENTERPRISE_AP:    return EUI_FLAG_ENTERPRISE_GRADE;
    case EUI_CLASS_CONSUMER_AP:      return EUI_FLAG_CONSUMER_GRADE;
    case EUI_CLASS_IOT_HUB:
    case EUI_CLASS_IOT_LEAF:         return EUI_FLAG_IOT_DEVICE;
    case EUI_CLASS_MOBILE:
    case EUI_CLASS_PHONE:
    case EUI_CLASS_TABLET:
    case EUI_CLASS_LAPTOP:           return EUI_FLAG_MOBILE_DEVICE;
    case EUI_CLASS_SURVEILLANCE_CAM: return EUI_FLAG_SURVEILLANCE;
    case EUI_CLASS_INVESTIGATION:
    case EUI_CLASS_ATTACK_SIGNAL:    return EUI_FLAG_INVESTIGATION;
    case EUI_CLASS_MAKER_BOARD:      return EUI_FLAG_MAKER;
    case EUI_CLASS_DEV_MODULE:       return EUI_FLAG_DEV_MODULE;
    default:                         return 0;
    }
}

static void wifi_refine_ap_identity(ap_score_t *s)
{
    if (!s) return;

    if (s->wps_manufacturer[0]) {
        uint16_t wf = 0;
        uint8_t  wc = EUI_CLASS_UNKNOWN;
        const char *wv = eui_lookup_wps(s->wps_manufacturer, &wf, &wc);
        if (wv) {
            s->eui_flags |= wf | wifi_flags_for_class(wc);
            if (!s->vendor[0]) strlcpy(s->vendor, wv, sizeof(s->vendor));
            if (wc && wifi_class_can_refine(s->device_class)) s->device_class = wc;
        }
    }

    if (s->l2l3_class && wifi_class_can_refine(s->device_class)) {
        s->device_class = s->l2l3_class;
        s->eui_flags |= wifi_flags_for_class(s->l2l3_class);
    }

    if (s->ssid[0] && wifi_class_can_refine(s->device_class)) {
        uint16_t sf = 0;
        uint8_t  sc = EUI_CLASS_UNKNOWN;
        const char *sv = eui_match_ssid(s->ssid, &sf, &sc);
        if (sv && sc) {
            s->device_class = sc;
            s->eui_flags |= sf | wifi_flags_for_class(sc);
            if (!s->vendor[0]) strlcpy(s->vendor, sv, sizeof(s->vendor));
        }
    }

    if (wifi_class_is_endpoint(s->device_class)) {
        s->device_class = EUI_CLASS_CONSUMER_AP;
        s->eui_flags |= EUI_FLAG_CONSUMER_GRADE;
    }
}

static uint8_t wifi_identity_score(const ap_score_t *s)
{
    int32_t v = (int32_t)s->base_quality - (int32_t)s->hygiene;
    if (v < 0)   v = 0;
    if (v > 100) v = 100;
    return (uint8_t)v;
}

static uint8_t wifi_identity_conf(const ap_score_t *s)
{
    if (!s->vendor[0]) return 30;
    if (s->mac_match_len >= 36) return 95;
    if (s->mac_match_len >= 28) return 85;
    if (s->mac_match_len >= 24) return 75;
    return 60;
}

static uint8_t wifi_threat_level(const ap_score_t *s, const ble_results_t *ble)
{
    uint8_t t = THREAT_NONE;
    #define BUMP(lvl) do { if ((lvl) > t) t = (lvl); } while (0)

    if (s->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) BUMP(THREAT_HIGH);
    if (s->open_clone)    BUMP(THREAT_HIGH);
    if (s->karma_suspect) BUMP(THREAT_HIGH);
    if (s->deauth_flood)  BUMP(THREAT_HIGH);
    if (s->pwnagotchi)    BUMP(THREAT_HIGH);
    if (s->eui_flags & EUI_FLAG_INVESTIGATION) BUMP(THREAT_HIGH);

    if (s->twin_detected)   BUMP(THREAT_MEDIUM);

    if (s->vendor_mismatch) BUMP(THREAT_LOW);
    if (s->eui_flags & (EUI_FLAG_FCC_COVERED | EUI_FLAG_SURVEILLANCE))
        BUMP(THREAT_MEDIUM);
    if (ble_investigation_near(ble)) BUMP(THREAT_MEDIUM);

    if (s->has_wps) BUMP(THREAT_LOW);
    if (s->has_rsn && !s->rsn_pmf_required) BUMP(THREAT_LOW);

    #undef BUMP
    return t;
}

static bool wifi_pmkid_exposed(const ap_record_t *ap)
{
    switch (ap->auth) {
        case WIFI_AUTH_WPA_PSK:
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return true;
        default:
            return false;
    }
}

static bool is_pwnagotchi_mac(const uint8_t bssid[6])
{
    static const uint8_t PWNAGOTCHI_MAC[6] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};
    return memcmp(bssid, PWNAGOTCHI_MAC, 6) == 0;
}

static uint32_t bssid_suffix(const uint8_t *bssid)
{
    return ((uint32_t)bssid[3] << 16) | ((uint32_t)bssid[4] << 8) | bssid[5];
}

static bool same_physical_router(const uint8_t a[6], const uint8_t b[6])
{
    if (a[2] != b[2]) return false;
    if (a[3] != b[3]) return false;
    if (a[4] != b[4]) return false;
    int delta = (int)a[5] - (int)b[5];
    if (delta < 0) delta = -delta;
    return delta <= 16;
}

static bool is_chain_ssid(const char *ssid)
{
    if (!ssid || !ssid[0]) return false;
    uint16_t f = 0; uint8_t c = 0;
    return eui_match_ssid(ssid, &f, &c) != NULL;
}

#define VENDOR_FAMILY_MAX 40
static void vendor_family(const char *v, char *out, size_t out_sz)
{
    if (out_sz == 0) return;
    out[0] = '\0';
    if (!v || !v[0]) return;

    char tmp[VENDOR_FAMILY_MAX];
    size_t n = 0;
    bool prev_space = true;
    for (const char *p = v; *p && n + 1 < sizeof(tmp); p++) {
        unsigned char ch = (unsigned char)*p;
        if (isalnum(ch)) {
            tmp[n++] = (char)tolower(ch);
            prev_space = false;
        } else if (!prev_space) {
            tmp[n++] = ' ';
            prev_space = true;
        }
    }
    while (n > 0 && tmp[n - 1] == ' ') n--;
    tmp[n] = '\0';

    static const char *const suffix[] = {
        "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation",
        "co", "company", "gmbh", "ag", "sa", "plc", "bv", "oy", "srl",
    };
    bool stripped;
    do {
        stripped = false;
        char *sp = strrchr(tmp, ' ');
        if (!sp) break;
        const char *last = sp + 1;
        for (size_t s = 0; s < sizeof(suffix) / sizeof(suffix[0]); s++) {
            if (strcmp(last, suffix[s]) == 0) {
                *sp = '\0';
                size_t m = strlen(tmp);
                while (m > 0 && tmp[m - 1] == ' ') tmp[--m] = '\0';
                stripped = true;
                break;
            }
        }
    } while (stripped);

    strlcpy(out, tmp, out_sz);
}

static void twin_peer_family(const uint8_t bssid[6], const char *direct_vendor,
                             char *out, size_t out_sz, bool *recovered)
{
    *recovered = false;
    vendor_family(direct_vendor, out, out_sz);
    if (out[0]) return;
    if (!mac_is_laa(bssid)) return;

    uint8_t rec[6];
    memcpy(rec, bssid, 6);
    rec[0] &= (uint8_t)~0x02;
    uint16_t f = 0; uint8_t c = 0, ml = 0;
    const char *rv = eui_lookup_mac(rec, &f, &c, &ml);
    vendor_family(rv, out, out_sz);
    if (out[0]) *recovered = true;
}

static bool ssid_has_universal_family(const scan_results_t *results,
                                      const char *ssid,
                                      const char * const *vendor_all,
                                      const char *fam)
{
    if (!fam || !fam[0]) return false;
    for (uint16_t k = 0; k < results->count; k++) {
        if (strcmp(results->entries[k].ssid, ssid) != 0) continue;
        if (mac_is_laa(results->entries[k].bssid)) continue;
        const char *v = vendor_all ? vendor_all[k] : NULL;
        char kf[VENDOR_FAMILY_MAX];
        vendor_family(v, kf, sizeof(kf));
        if (kf[0] && strcmp(kf, fam) == 0) return true;
    }
    return false;
}

static bool vendor_is_ssid_outlier(const scan_results_t *results, uint16_t i,
                                   const char *const *vendor_all)
{
    const char *ssid = results->entries[i].ssid;
    if (!ssid[0]) return false;

    enum { TW_GROUP_MAX = 16 };
    char fams[TW_GROUP_MAX][VENDOR_FAMILY_MAX];
    uint16_t nf = 0;
    int my_slot = -1;
    for (uint16_t k = 0; k < results->count && nf < TW_GROUP_MAX; k++) {
        if (strcmp(results->entries[k].ssid, ssid) != 0) continue;
        bool r = false;
        twin_peer_family(results->entries[k].bssid,
                         vendor_all ? vendor_all[k] : NULL,
                         fams[nf], VENDOR_FAMILY_MAX, &r);
        if (r && !ssid_has_universal_family(results, ssid, vendor_all, fams[nf]))
            fams[nf][0] = '\0';
        if (k == i) my_slot = (int)nf;
        nf++;
    }
    if (my_slot < 0 || !fams[my_slot][0]) return false;

    const char *myf = fams[my_slot];
    uint16_t my_count = 0, other_max = 0;
    for (uint16_t a = 0; a < nf; a++)
        if (fams[a][0] && strcmp(fams[a], myf) == 0) my_count++;
    for (uint16_t a = 0; a < nf; a++) {
        if (!fams[a][0] || strcmp(fams[a], myf) == 0) continue;
        uint16_t c = 0;
        for (uint16_t b = 0; b < nf; b++)
            if (fams[b][0] && strcmp(fams[b], fams[a]) == 0) c++;
        if (c > other_max) other_max = c;
    }
    return other_max >= my_count;
}

static bool same_administered_wlan(const ap_score_t *a, const ap_score_t *b)
{
    if (!a || !b) return false;
    if (strcmp(a->ssid, b->ssid) != 0) return false;
    if (strcmp(a->ssid, "<hidden>") == 0) return false;

    bool same_public_oui = !mac_is_laa(a->bssid) && !mac_is_laa(b->bssid) &&
                           memcmp(a->bssid, b->bssid, 3) == 0;

    bool same_router = same_physical_router(a->bssid, b->bssid);

    char fa[VENDOR_FAMILY_MAX], fb[VENDOR_FAMILY_MAX];
    bool ra = false, rb = false;
    twin_peer_family(a->bssid, a->vendor, fa, sizeof(fa), &ra);
    twin_peer_family(b->bssid, b->vendor, fb, sizeof(fb), &rb);
    bool same_vendor = fa[0] && fb[0] && strcmp(fa, fb) == 0;

    return same_public_oui || same_router || same_vendor;
}

static uint8_t twin_score(
        const scan_results_t *results,
        uint16_t              i,
        const uint16_t       *eui_flags_all,
        const char * const   *vendor_all,
        bool                  is_laa,
        ap_score_t           *s)
{
    const ap_record_t *ap        = &results->entries[i];
    uint16_t           my_tier   = eui_flags_all[i] & TIER_MASK;
    const char        *my_vendor = vendor_all ? vendor_all[i] : NULL;

    if (!ap->ssid[0]) return 20;

    char my_fam[VENDOR_FAMILY_MAX];
    {
        bool rec = false;
        twin_peer_family(ap->bssid, my_vendor, my_fam, sizeof(my_fam), &rec);
        if (rec && !ssid_has_universal_family(results, ap->ssid, vendor_all, my_fam))
            my_fam[0] = '\0';
    }

    bool open_present      = false;
    bool prot_present      = false;
    bool same_oui_peer     = false;
    bool diff_oui_peer     = false;
    bool diff_tier_peer    = false;

    bool same_oui_same_channel  = false;
    bool same_oui_cross_channel = false;

    int8_t   best_peer_rssi = -127;
    uint16_t peer_count     = 0;

    bool     same_physical_peer = false;
    uint32_t max_suffix_delta   = 0;

    for (uint16_t j = 0; j < results->count; j++) {
        const ap_record_t *peer = &results->entries[j];
        if (strcmp(peer->ssid, ap->ssid) != 0) continue;

        if (peer->auth == WIFI_AUTH_OPEN) open_present = true;
        else                              prot_present = true;

        if (j == i) continue;
        peer_count++;

        if (peer->rssi > best_peer_rssi) best_peer_rssi = peer->rssi;

        bool j_laa = mac_is_laa(peer->bssid);

        bool same_oui_classic =
            !is_laa && !j_laa && memcmp(ap->bssid, peer->bssid, 3) == 0;
        bool same_dev_laa =
            same_physical_router(ap->bssid, peer->bssid) && !same_oui_classic;

        if (same_oui_classic || same_dev_laa) {
            same_oui_peer = true;

            if (peer->channel == ap->channel)
                same_oui_same_channel  = true;
            else
                same_oui_cross_channel = true;

            if (same_physical_router(ap->bssid, peer->bssid)) {
                same_physical_peer = true;
                uint32_t my_sfx   = bssid_suffix(ap->bssid);
                uint32_t peer_sfx = bssid_suffix(peer->bssid);
                uint32_t delta    = my_sfx > peer_sfx ? my_sfx - peer_sfx
                                                       : peer_sfx - my_sfx;
                if (delta > max_suffix_delta) max_suffix_delta = delta;
            }

        } else {
            uint16_t j_tier = eui_flags_all[j] & TIER_MASK;
            const char *j_vendor = vendor_all ? vendor_all[j] : NULL;

            char j_fam[VENDOR_FAMILY_MAX];
            bool j_rec = false;
            twin_peer_family(peer->bssid, j_vendor, j_fam, sizeof(j_fam), &j_rec);
            if (j_rec && !ssid_has_universal_family(results, ap->ssid, vendor_all, j_fam))
                j_fam[0] = '\0';
            bool same_family = my_fam[0] && j_fam[0] && strcmp(my_fam, j_fam) == 0;

            if (same_family) {

                same_oui_peer = true;
            } else {
                diff_oui_peer = true;

                bool j_blank_laa  = j_laa  && !j_fam[0];
                bool my_blank_laa = is_laa && !my_fam[0];
                if (j_blank_laa || my_blank_laa) {

                } else if (j_tier != my_tier) {
                    diff_tier_peer = true;
                } else if (my_tier == 0) {

                    diff_tier_peer = true;
                }
            }
        }
    }

    if (is_chain_ssid(ap->ssid)) {
        diff_oui_peer  = false;
        diff_tier_peer = false;
    }

    if (open_present && prot_present) {
        s->twin_detected = true;
        s->auto_fail     = true;
        s->open_clone    = true;
        return 0;
    }
    if (same_oui_peer && !diff_oui_peer)
        s->same_oui_multiband = true;

    s->vendor_mismatch = diff_tier_peer && vendor_is_ssid_outlier(results, i, vendor_all);

    int base = 20;

    int mod = 0;

    if (same_oui_same_channel) {
        mod -= same_oui_cross_channel ? 3 : 7;
    }

    if (diff_oui_peer && peer_count >= 1) {
        int gap = (int)ap->rssi - (int)best_peer_rssi;
        if (gap >= 20) mod -= 10;
    }

    if (same_physical_peer) {
        if      (max_suffix_delta > 32) mod -= 10;
        else if (max_suffix_delta >  8) mod -= 5;
    }

    if (mod <= -10) s->twin_detected = true;

    int result = base + mod;
    if (result < 0)  result = 0;
    if (result > 20) result = 20;
    return (uint8_t)result;
}

static void tier2_twin_adjust(ap_score_t *scores, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
        if (scores[i].auto_fail) continue;

        if (strcmp(scores[i].ssid, "<hidden>") == 0) continue;

        if (is_chain_ssid(scores[i].ssid)) continue;
        const sniffer_rec_t *si = wifi_sniffer_get(scores[i].bssid);
        if (!si) continue;

        for (uint16_t j = i + 1; j < n; j++) {
            if (scores[j].auto_fail) continue;
            if (strcmp(scores[i].ssid, scores[j].ssid) != 0) continue;

            if (same_administered_wlan(&scores[i], &scores[j]))
                continue;
            const sniffer_rec_t *sj = wifi_sniffer_get(scores[j].bssid);
            if (!sj) continue;

            int penalty = 0;

            if (si->has_rsn != sj->has_rsn)                       penalty += 10;
            else if (si->rsn_pmf_required != sj->rsn_pmf_required) penalty += 5;

            if (si->has_wps != sj->has_wps)                        penalty += 5;

            if (si->beacon_interval && sj->beacon_interval) {
                uint16_t lo = si->beacon_interval < sj->beacon_interval
                                ? si->beacon_interval : sj->beacon_interval;
                uint16_t hi = si->beacon_interval > sj->beacon_interval
                                ? si->beacon_interval : sj->beacon_interval;
                if (hi > lo + lo / 5) penalty += 5;
            }

            if (penalty < 10) continue;

            scores[i].twin_detected = true;
            scores[j].twin_detected = true;
        }
    }
}

static void ap_add_sibling(ap_score_t *rep, const uint8_t bssid[6],
                           int8_t rssi, uint8_t channel, bool band_5g)
{
    if (memcmp(rep->bssid, bssid, 6) == 0) return;
    for (uint8_t k = 0; k < rep->sibling_count; k++)
        if (memcmp(rep->siblings[k].bssid, bssid, 6) == 0) return;
    if (rep->sibling_count >= AP_MAX_SIBLINGS) return;
    radio_sibling_t *s = &rep->siblings[rep->sibling_count++];
    memcpy(s->bssid, bssid, 6);
    s->rssi    = rssi;
    s->channel = channel;
    s->band_5g = band_5g;
}

esp_err_t analyzer_run(const scan_results_t *results,
                        const ble_results_t *ble,
                        ap_score_t *scores, uint16_t *count_out)
{
    if (!results || !scores || !count_out) return ESP_ERR_INVALID_ARG;

    uint16_t n = results->count;
    *count_out = 0;
    if (n == 0) return ESP_OK;

    uint16_t    eui_flags[WIFI_SCAN_MAX_APS];
    uint8_t     eui_class[WIFI_SCAN_MAX_APS];
    uint8_t     mac_match[WIFI_SCAN_MAX_APS];
    const char *vendor[WIFI_SCAN_MAX_APS];
    for (uint16_t i = 0; i < n; i++) {
        eui_flags[i] = 0;
        eui_class[i] = EUI_CLASS_UNKNOWN;
        mac_match[i] = 0;
        vendor[i] = eui_lookup_mac(results->entries[i].bssid,
                                    &eui_flags[i], &eui_class[i], &mac_match[i]);
    }

    for (uint16_t i = 0; i < n; i++) {
        const ap_record_t *ap = &results->entries[i];
        ap_score_t        *s  = &scores[i];
        memset(s, 0, sizeof(*s));

        memcpy(s->bssid, ap->bssid, 6);
        strlcpy(s->ssid, ap->ssid[0] ? ap->ssid : "<hidden>", sizeof(s->ssid));
        if (vendor[i]) strlcpy(s->vendor, vendor[i], sizeof(s->vendor));
        s->eui_flags     = eui_flags[i];
        s->device_class  = eui_class[i];
        s->mac_match_len = mac_match[i];
        s->rssi          = ap->rssi;
        s->channel       = ap->channel;
        s->band_5g       = ap->band_5g;
        s->radio_count   = 1;

        if (eui_flags[i] & EUI_FLAG_KNOWN_MALICIOUS) {
            s->auto_fail      = true;
            s->identity_score = wifi_identity_score(s);
            s->identity_conf  = wifi_identity_conf(s);
            s->threat_level   = THREAT_HIGH;
            ESP_LOGW(TAG, "[%2u] %-32s  BLOCKED — known malicious vendor", i, s->ssid);
            continue;
        }

        bool is_laa = mac_is_laa(ap->bssid);
        const sniffer_rec_t *sr = wifi_sniffer_get(ap->bssid);

        s->auth = ap->auth;
        if (sr) {
            s->has_wps          = sr->has_wps;
            s->has_rsn          = sr->has_rsn;
            s->rsn_pmf_required = sr->rsn_pmf_required;
            s->beacon_interval  = sr->beacon_interval;
            s->vendor_ie_count  = sr->vendor_ie_count;
            memcpy(s->vendor_ie_ouis, sr->vendor_ie_ouis, sizeof(sr->vendor_ie_ouis));
            s->lldp_count       = sr->lldp_count;
            s->cdp_count        = sr->cdp_count;
            s->dhcp_count       = sr->dhcp_count;

            for (uint8_t k = 0; k < sr->vendor_ie_count && k < 4; k++) {
                uint16_t f = 0; uint8_t c = 0;
                s->vendor_ie_names[k] = eui_lookup_vendor_ie(sr->vendor_ie_ouis[k], &f, &c);
            }

            strlcpy(s->cdp_device_id,    sr->cdp_device_id,    sizeof(s->cdp_device_id));
            strlcpy(s->lldp_system_name, sr->lldp_system_name, sizeof(s->lldp_system_name));
            strlcpy(s->dhcp_vendor_class, sr->dhcp_vendor_class, sizeof(s->dhcp_vendor_class));
            s->l2l3_flags = sr->cdp_flags | sr->lldp_flags | sr->dhcp_flags;
            if (sr->cdp_class)      s->l2l3_class = sr->cdp_class;
            else if (sr->lldp_class) s->l2l3_class = sr->lldp_class;
            else                     s->l2l3_class = sr->dhcp_class;
            s->l2l3_signal_count = (sr->cdp_count > 0)  +
                                   (sr->lldp_count > 0) +
                                   (sr->dhcp_count > 0);

            strlcpy(s->wps_manufacturer, sr->wps_manufacturer, sizeof(s->wps_manufacturer));
            strlcpy(s->wps_model_name,   sr->wps_model_name,   sizeof(s->wps_model_name));
            s->country_code[0] = sr->country_code[0];
            s->country_code[1] = sr->country_code[1];
            s->country_code[2] = '\0';
            s->ie_pattern_hash = sr->ie_pattern_hash;
            memcpy(s->rsn_group_oui, sr->rsn_group_oui, 3);
            s->rsn_group_suite = sr->rsn_group_suite;
        }

        wifi_refine_ap_identity(s);

        if (sr && sr->karma_suspect) {
            s->karma_suspect = true;
            s->auto_fail     = true;
        }

        (void)twin_score(results, i, eui_flags, vendor, is_laa, s);

        if (sr && sr->deauth_count > 5) {
            s->deauth_flood = true;
            s->auto_fail    = true;
        }

        if (is_pwnagotchi_mac(ap->bssid)) {
            s->pwnagotchi = true;
            s->auto_fail  = true;
            ESP_LOGW(TAG, "[%2u] pwnagotchi beacon (de:ad:be:ef:de:ad)", i);
        }

        s->base_quality  = v2_base_quality(ap, sr, s->eui_flags, is_laa,
                                           s->vendor[0] ? s->vendor : NULL);
        s->hygiene       = v2_hygiene(ap, sr);
        s->pmkid_exposed = wifi_pmkid_exposed(ap);

        s->identity_score = wifi_identity_score(s);
        s->identity_conf  = wifi_identity_conf(s);
        s->threat_level   = wifi_threat_level(s, ble);
    }

    tier2_twin_adjust(scores, n);

    for (uint16_t i = 0; i < n; i++) {
        ap_score_t *s = &scores[i];
        if (s->suppressed || s->auto_fail) continue;

        s->identity_score = wifi_identity_score(s);
        s->identity_conf  = wifi_identity_conf(s);
        s->threat_level   = wifi_threat_level(s, ble);
    }

    for (uint16_t i = 0; i < n; i++) {
        if (scores[i].suppressed) continue;

        if (scores[i].auto_fail || scores[i].threat_level >= THREAT_MEDIUM)
            continue;

        for (uint16_t j = i + 1; j < n; j++) {
            if (scores[j].suppressed) continue;
            if (scores[j].auto_fail || scores[j].threat_level >= THREAT_MEDIUM)
                continue;
            if (strcmp(scores[i].ssid, scores[j].ssid) != 0) continue;

            bool same_public_oui = !mac_is_laa(scores[i].bssid) &&
                                   !mac_is_laa(scores[j].bssid) &&
                                   memcmp(scores[i].bssid, scores[j].bssid, 3) == 0;
            bool same_router = same_physical_router(scores[i].bssid, scores[j].bssid);
            if (!same_public_oui && !same_router) continue;

            if (strcmp(scores[i].ssid, "<hidden>") == 0 && !same_router) continue;

            uint8_t m_threat = scores[i].threat_level > scores[j].threat_level
                             ? scores[i].threat_level : scores[j].threat_level;
            bool    m_wps    = scores[i].has_wps || scores[j].has_wps;

            scores[i].radio_count++;
            scores[i].same_oui_multiband = true;

            uint8_t ib[6]; memcpy(ib, scores[i].bssid, 6);
            int8_t  ir = scores[i].rssi; uint8_t ic = scores[i].channel; bool iband = scores[i].band_5g;
            uint8_t jb[6]; memcpy(jb, scores[j].bssid, 6);
            int8_t  jr = scores[j].rssi; uint8_t jc = scores[j].channel; bool jband = scores[j].band_5g;
            radio_sibling_t saved_sib[AP_MAX_SIBLINGS];
            uint8_t saved_sib_n = scores[i].sibling_count;
            memcpy(saved_sib, scores[i].siblings, sizeof(saved_sib));

            bool prefer_j_bssid = mac_is_laa(scores[i].bssid) &&
                                  !mac_is_laa(scores[j].bssid);
            if (prefer_j_bssid || scores[j].identity_score > scores[i].identity_score) {
                uint8_t saved_bssid[6];
                char    saved_ssid[33];
                uint8_t saved_rc = scores[i].radio_count;

                memcpy(saved_bssid, scores[i].bssid, 6);
                strlcpy(saved_ssid, scores[i].ssid, sizeof(saved_ssid));

                scores[i] = scores[j];

                if (!prefer_j_bssid) {
                    memcpy(scores[i].bssid, saved_bssid, 6);
                    strlcpy(scores[i].ssid, saved_ssid, sizeof(scores[i].ssid));
                }
                scores[i].radio_count        = saved_rc;
                scores[i].same_oui_multiband = true;
                scores[i].suppressed         = false;
            }

            memcpy(scores[i].siblings, saved_sib, sizeof(saved_sib));
            scores[i].sibling_count = saved_sib_n;
            ap_add_sibling(&scores[i], ib, ir, ic, iband);
            ap_add_sibling(&scores[i], jb, jr, jc, jband);

            scores[i].threat_level = m_threat;
            scores[i].has_wps      = m_wps;

            scores[j].suppressed = true;
        }
    }

    uint16_t out_n = 0;
    for (uint16_t i = 0; i < n; i++) {
        if (!scores[i].suppressed) scores[out_n++] = scores[i];
    }
    n = out_n;

    for (uint16_t i = 1; i < n; i++) {
        ap_score_t tmp = scores[i];
        uint16_t j = i;
        while (j > 0) {
            const ap_score_t *prev = &scores[j - 1];
            bool prev_first =
                (prev->threat_level < tmp.threat_level) ||
                (prev->threat_level == tmp.threat_level &&
                 prev->identity_score >= tmp.identity_score);
            if (!prev_first) {
                scores[j] = scores[j - 1];
                j--;
            } else {
                break;
            }
        }
        scores[j] = tmp;
    }

    for (uint16_t i = 0; i < n; i++) {
        ap_score_t *s   = &scores[i];
        bool        laa = mac_is_laa(s->bssid);

        char flags[32] = "";
        if (s->radio_count > 1) {
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "(x%u)", s->radio_count);
            strlcat(flags, tmp, sizeof(flags));
        }
        if (s->twin_detected)    strlcat(flags, "[TWIN]",   sizeof(flags));
        if (s->vendor_mismatch)  strlcat(flags, "[VM]",     sizeof(flags));
        if (s->karma_suspect)    strlcat(flags, "[KARMA]",  sizeof(flags));
        if (s->deauth_flood)     strlcat(flags, "[DEAUTH]", sizeof(flags));
        if (s->auto_fail && !s->twin_detected && !s->deauth_flood && !s->karma_suspect)
                                 strlcat(flags, "[FAIL]",   sizeof(flags));

        ESP_LOGI(TAG, "[%2u] %-32s  id=%3u/%-3u threat=%-6s %-14s  %s",
            i, s->ssid, s->identity_score, s->identity_conf,
            analyzer_threat_label(s->threat_level),
            flags[0] ? flags : "-",
            s->vendor[0] ? s->vendor : (laa ? "LAA" : "unknown"));
    }

    *count_out = n;
    return ESP_OK;
}

const ap_score_t *analyzer_best(const ap_score_t *scores, uint16_t count)
{

    const ap_score_t *best = NULL;
    for (uint16_t i = 0; i < count; i++) {
        const ap_score_t *s = &scores[i];
        if (s->suppressed || s->threat_level >= THREAT_MEDIUM) continue;
        if (!best || s->identity_score > best->identity_score) best = s;
    }
    return best;
}

static uint8_t xref_conf(uint32_t delta)
{
    if (delta == 0)  return 95;
    if (delta <= 4)  return 85;
    if (delta <= 16) return 70;
    return 0;
}

void analyzer_xref_ble(ap_score_t *scores, uint16_t count, ble_results_t *ble)
{
    if (!scores) return;

    for (uint16_t i = 0; i < count; i++) {
        scores[i].ble_match      = -1;
        scores[i].ble_match_conf = 0;
    }
    if (!ble) return;
    for (uint16_t j = 0; j < ble->count; j++) ble->devices[j].wifi_match = -1;

    for (uint16_t i = 0; i < count; i++) {
        if (mac_is_laa(scores[i].bssid)) continue;
        uint32_t ap_suffix = bssid_suffix(scores[i].bssid);
        uint8_t  best_conf = 0;
        int16_t  best_j    = -1;

        for (uint16_t j = 0; j < ble->count; j++) {
            const uint8_t *a = ble->devices[j].addr;
            if (a[0] & 0x02) continue;
            if (memcmp(scores[i].bssid, a, 3) != 0) continue;

            uint32_t bs = bssid_suffix(a);
            uint32_t delta = (bs > ap_suffix) ? bs - ap_suffix : ap_suffix - bs;
            uint8_t  conf  = xref_conf(delta);
            if (conf > best_conf) { best_conf = conf; best_j = (int16_t)j; }
        }

        if (best_j >= 0) {
            scores[i].ble_match      = best_j;
            scores[i].ble_match_conf = best_conf;

            ble->devices[best_j].wifi_match = (int16_t)i;

            const ble_device_t *bd = &ble->devices[best_j];
            ESP_LOGI(TAG, "XREF %-24s <-> BLE %s/%s  conf=%u%%",
                     scores[i].ssid,
                     bd->name[0] ? bd->name : "(no name)",
                     bd->vendor[0] ? bd->vendor : "?", best_conf);
        }
    }
}

static crowd_estimate_t s_last_crowd;

static bool crowd_dev_is_person(const ble_device_t *d)
{
    uint8_t cls = d->device_class;
    if (cls == EUI_CLASS_PHONE  || cls == EUI_CLASS_MOBILE ||
        cls == EUI_CLASS_TABLET || cls == EUI_CLASS_WEARABLE)
        return true;
    if (d->apple_devcat == APPLE_DEVCAT_IPHONE ||
        d->apple_devcat == APPLE_DEVCAT_IPAD   ||
        d->apple_devcat == APPLE_DEVCAT_WATCH)
        return true;
    if (d->name_rule_kind == EUI_NAME_RULE_PHONE_MODEL)
        return true;
    return false;
}

static crowd_bucket_t crowd_bucket_for(uint16_t evidence)
{
    if (evidence == 0)  return CROWD_QUIET;
    if (evidence <= 3)  return CROWD_FEW;
    if (evidence <= 9)  return CROWD_SOME;
    if (evidence <= 24) return CROWD_BUSY;
    return CROWD_CROWDED;
}

const char *analyzer_crowd_bucket_label(crowd_bucket_t b)
{
    switch (b) {
    case CROWD_QUIET:   return "quiet";
    case CROWD_FEW:     return "a_few";
    case CROWD_SOME:    return "some_people";
    case CROWD_BUSY:    return "busy";
    case CROWD_CROWDED: return "crowded";
    default:            return "quiet";
    }
}

void analyzer_crowd_estimate(const ble_results_t *ble, uint16_t wifi_stations,
                             uint16_t probe_reqs, crowd_estimate_t *out)
{
    crowd_estimate_t cd = (crowd_estimate_t){0};
    cd.wifi_stations = wifi_stations;
    cd.probe_reqs    = probe_reqs;

    if (ble) {
        for (uint16_t i = 0; i < ble->count; i++) {
            if (crowd_dev_is_person(&ble->devices[i]))
                cd.ble_person_devices++;
        }
    }

    cd.device_evidence = cd.ble_person_devices + cd.wifi_stations;

    cd.people_high = cd.device_evidence;
    cd.people_low  = (uint16_t)((cd.device_evidence * 10 + 16) / 17);
    if (cd.device_evidence > 0 && cd.people_low == 0) cd.people_low = 1;

    cd.bucket = crowd_bucket_for(cd.device_evidence);

    s_last_crowd = cd;
    if (out) *out = cd;
}

const crowd_estimate_t *analyzer_last_crowd(void)
{
    return &s_last_crowd;
}
