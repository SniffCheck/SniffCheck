#include "vetter.h"
#include "eui_db.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "sc_vet";

static bool icontains(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0]) return false;
    size_t nl = strlen(needle);
    for (; *hay; hay++) {
        size_t k;
        for (k = 0; k < nl; k++) {
            char a = hay[k], b = needle[k];
            if (!a) break;
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (k == nl) return true;
    }
    return false;
}

static vetter_check_t chk_vendor_ssid(const ap_score_t *ap)
{
    uint16_t f = 0; uint8_t c = 0;
    const char *rule_name = eui_match_ssid(ap->ssid, &f, &c);
    if (!rule_name) return VETTER_PASS;

    if (ap->eui_flags & (EUI_FLAG_INVESTIGATION | EUI_FLAG_DEV_MODULE
                       | EUI_FLAG_MAKER | EUI_FLAG_SURVEILLANCE))
        return VETTER_ALERT;

    return VETTER_PASS;
}

static vetter_check_t chk_blocklist(const ap_score_t *ap)
{
    return (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) ? VETTER_ALERT : VETTER_PASS;
}

static vetter_check_t chk_crypto(const ap_score_t *ap)
{
    if (ap->auth == WIFI_AUTH_WEP)     return VETTER_ALERT;
    if (ap->auth == WIFI_AUTH_WPA_PSK) return VETTER_WARN;
    if (ap->has_wps)                   return VETTER_WARN;
    return VETTER_PASS;
}

static vetter_check_t chk_laa(const ap_score_t *ap)
{
    return mac_is_laa(ap->bssid) ? VETTER_WARN : VETTER_PASS;
}

static vetter_check_t chk_vendor_twin(const ap_score_t *ap)
{

    if (ap->twin_detected && !ap->open_clone) return VETTER_ALERT;
    return VETTER_PASS;
}

static vetter_check_t chk_open_clone(const ap_score_t *ap)
{
    return ap->open_clone ? VETTER_ALERT : VETTER_PASS;
}

static bool ble_context_note(const ap_score_t *ap, const ble_results_t *ble, char *note, size_t note_sz)
{
    if (!ble || ble->count == 0) return false;

    static const uint8_t RPI_OUIS[3][3] = {
        { 0xDC, 0xA6, 0x32 }, { 0xB8, 0x27, 0xEB }, { 0xE4, 0x5F, 0x01 }
    };

    bool prox_profile_nearby = false;
    bool rpi_nearby          = false;
    bool malicious_ble       = false;

    for (uint16_t i = 0; i < ble->count; i++) {
        const ble_device_t *d = &ble->devices[i];

        if (d->vendor[0] && icontains(d->vendor, "Hak5")) malicious_ble = true;

        for (int r = 0; r < 3; r++) {
            if (memcmp(d->addr, RPI_OUIS[r], 3) == 0) { rpi_nearby = true; break; }
        }

        bool has_1802 = false, has_1803 = false;
        for (uint8_t k = 0; k < d->num_uuids16; k++) {
            if (d->uuids16[k] == 0x1802) has_1802 = true;
            if (d->uuids16[k] == 0x1803) has_1803 = true;
        }
        if (has_1802 && has_1803) prox_profile_nearby = true;
    }

    if (malicious_ble) {
        snprintf(note, note_sz, " BLE: Hak5/rogue device nearby.");
        return true;
    }
    if (rpi_nearby && ap->threat_level >= THREAT_MEDIUM) {
        snprintf(note, note_sz, " BLE: Raspberry Pi nearby — possible rogue AP rig.");
        return true;
    }
    if (prox_profile_nearby && ap->twin_detected) {
        snprintf(note, note_sz, " BLE: proximity-profile device near twin candidate.");
        return true;
    }
    return false;
}

/* Rogue-AP build platforms (Raspberry Pi, ALFA, etc.) are surfaced as
 * evidence, never a verdict. The OUI identifies the *device*, not intent —
 * so name it and only claim wrongdoing when behavior corroborates it. */
static void append_rogue_hw_note(const ap_score_t *ap, char *note, size_t note_sz)
{
    if (ap->device_class != EUI_CLASS_ROGUE_HW_OUI) return;

    const char *who = ap->vendor[0] ? ap->vendor : "rogue-AP-capable hardware";
    bool corroborated = ap->twin_detected || ap->open_clone ||
                        ap->karma_suspect || ap->deauth_flood ||
                        ap->pwnagotchi || ap->threat_level >= THREAT_MEDIUM;

    char tmp[192];
    if (corroborated)
        snprintf(tmp, sizeof(tmp),
                 " HW: %s — rogue-AP-capable platform, and suspicious "
                 "behavior was observed.", who);
    else
        snprintf(tmp, sizeof(tmp),
                 " HW: %s — rogue-AP-capable platform (evidence only; no "
                 "hostile behavior seen).", who);
    strlcat(note, tmp, note_sz);
}

static const char *conf_label(uint8_t count)
{
    if (count >= 4) return "high";
    if (count >= 2) return "medium";
    return NULL;
}

static void append_l2l3_note(const ap_score_t *ap, char *note, size_t note_sz)
{
    const char *lldp_c = conf_label(ap->lldp_count);
    const char *cdp_c  = conf_label(ap->cdp_count);
    const char *dhcp_c = conf_label(ap->dhcp_count);
    if (!lldp_c && !cdp_c && !dhcp_c) return;

    char tmp[80];

    if (cdp_c) {
        if (ap->cdp_device_id[0])
            snprintf(tmp, sizeof(tmp), " CDP(%s):\"%s\".", cdp_c, ap->cdp_device_id);
        else
            snprintf(tmp, sizeof(tmp), " CDP(%s).", cdp_c);
        strlcat(note, tmp, note_sz);
    }
    if (lldp_c) {
        if (ap->lldp_system_name[0])
            snprintf(tmp, sizeof(tmp), " LLDP(%s):\"%s\".", lldp_c, ap->lldp_system_name);
        else
            snprintf(tmp, sizeof(tmp), " LLDP(%s).", lldp_c);
        strlcat(note, tmp, note_sz);
    }
    if (dhcp_c) {
        if (ap->dhcp_vendor_class[0])
            snprintf(tmp, sizeof(tmp), " DHCP(%s):VC=\"%s\".", dhcp_c, ap->dhcp_vendor_class);
        else
            snprintf(tmp, sizeof(tmp), " DHCP(%s).", dhcp_c);
        strlcat(note, tmp, note_sz);
    }
}

static void append_wps_note(const ap_score_t *ap, char *note, size_t note_sz)
{

    (void)ap; (void)note; (void)note_sz;
}

static const char *sev_str(vetter_check_t c)
{
    switch (c) {
    case VETTER_PASS:  return "PASS";
    case VETTER_INFO:  return "INFO";
    case VETTER_WARN:  return "WARN";
    case VETTER_ALERT: return "ALRT";
    case VETTER_SKIP:  return "SKIP";
    default:           return "?";
    }
}

esp_err_t vetter_run(const ap_score_t *ap,
                     const ble_results_t *ble,
                     vetter_result_t *out)
{
    if (!ap || !out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    out->check[0] = chk_vendor_ssid(ap);
    out->check[1] = chk_blocklist(ap);
    out->check[2] = chk_crypto(ap);
    out->check[3] = chk_laa(ap);
    out->check[4] = chk_vendor_twin(ap);
    out->check[5] = chk_open_clone(ap);

    if (ap->karma_suspect && out->check[4] != VETTER_ALERT)
        out->check[4] = VETTER_ALERT;

    for (int i = 6; i < 10; i++) out->check[i] = VETTER_SKIP;

    out->blocked = ap->pwnagotchi;
    for (int i = 0; i < 10; i++) {
        if (out->check[i] == VETTER_ALERT) { out->blocked = true; break; }
    }

    char ble_note[224] = "";
    ble_context_note(ap, ble, ble_note, sizeof(ble_note));
    append_rogue_hw_note(ap, ble_note, sizeof(ble_note));
    append_l2l3_note(ap, ble_note, sizeof(ble_note));
    append_wps_note(ap, ble_note, sizeof(ble_note));

    if (ap->pwnagotchi) {
        snprintf(out->summary, sizeof(out->summary),
                 "BLOCKED — pwnagotchi attack tool (handshake harvester).%s", ble_note);
    } else if (ap->karma_suspect) {
        snprintf(out->summary, sizeof(out->summary),
                 "BLOCKED — KARMA AP (responds to arbitrary SSIDs).%s", ble_note);
    } else if (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) {
        snprintf(out->summary, sizeof(out->summary),
                 "BLOCKED — known rogue hardware (%s).%s",
                 ap->vendor[0] ? ap->vendor : "?", ble_note);
    } else if (ap->open_clone) {
        snprintf(out->summary, sizeof(out->summary),
                 "BLOCKED — open+protected clone of \"%s\".%s", ap->ssid, ble_note);
    } else if (out->check[4] == VETTER_ALERT) {
        if (ap->vendor_mismatch && out->check[0] == VETTER_ALERT) {
            snprintf(out->summary, sizeof(out->summary),
                     "BLOCKED — vendor mismatch for \"%s\" (%s not expected).%s",
                     ap->ssid, ap->vendor[0] ? ap->vendor : "unknown", ble_note);
        } else {
            snprintf(out->summary, sizeof(out->summary),
                     "BLOCKED — suspicious twin pattern for \"%s\".%s",
                     ap->ssid, ble_note);
        }
    } else if (ap->auth == WIFI_AUTH_WEP) {
        snprintf(out->summary, sizeof(out->summary), "BLOCKED — WEP is broken.%s", ble_note);
    } else {

        char issues[64] = "";
        if (ap->auth == WIFI_AUTH_OPEN)
            strlcat(issues, " No encryption.", sizeof(issues));
        else if (ap->auth == WIFI_AUTH_WPA_PSK)
            strlcat(issues, " Weak crypto (WPA-TKIP).", sizeof(issues));
        if (ap->has_wps)
            strlcat(issues, " WPS active.", sizeof(issues));
        if (mac_is_laa(ap->bssid))
            strlcat(issues, " LAA MAC.", sizeof(issues));

        const char *vlabel =
            analyzer_verdict_label(analyzer_threat_to_verdict(ap->threat_level));
        if (ap->vendor[0]) {
            snprintf(out->summary, sizeof(out->summary), "%s — %s.%s%s",
                     vlabel, ap->vendor, issues, ble_note);
        } else {
            snprintf(out->summary, sizeof(out->summary), "%s — unknown vendor.%s%s",
                     vlabel, issues, ble_note);
        }
    }

    return ESP_OK;
}

uint8_t vetter_lite_reasons(const ap_score_t *ap, char lines[2][64])
{
    if (!ap || !lines) return 0;
    lines[0][0] = '\0';
    lines[1][0] = '\0';
    uint8_t n = 0;

    #define WRITE(fmt, ...) do { \
        if (n < 2) { snprintf(lines[n], 64, fmt, ##__VA_ARGS__); n++; } \
    } while (0)

    if (ap->pwnagotchi) {
        WRITE("A Wi-Fi attack tool is capturing handshakes nearby.");
        WRITE("Treat as hostile. Use cellular if you can.");
        return n;
    }
    if (ap->karma_suspect) {
        WRITE("Pretends to be many networks at once.");
        WRITE("This is a known attacker trick.");
        return n;
    }
    if (ap->open_clone) {
        WRITE("There is a fake copy of this network nearby.");
        WRITE("Skip it. Use cellular if you can.");
        return n;
    }
    if (ap->deauth_flood) {
        WRITE("Something is kicking devices off this network.");
        WRITE("Likely an attack in progress.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_KNOWN_MALICIOUS) {
        WRITE("Made from known hacking hardware.");
        WRITE("This is not a real network. Don't connect.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_INVESTIGATION) {
        WRITE("Made from a known hacking tool.");
        WRITE("Treat as hostile.");
        return n;
    }

    if (ap->vendor_mismatch) {
        WRITE("Wrong brand of hardware for this network name.");
        WRITE("Might be a fake.");
        return n;
    }
    if (ap->twin_detected) {
        WRITE("Two networks with the same name and different gear.");
        WRITE("One could be a fake. Use cellular if you can.");
        return n;
    }
    if (ap->auth == WIFI_AUTH_WEP) {
        WRITE("Uses broken encryption (WEP).");
        WRITE("Anyone nearby can read what you send.");
        return n;
    }
    if (ap->device_class == EUI_CLASS_ROGUE_HW_OUI) {
        WRITE("Built on hardware often used for DIY or pentest rigs.");
        WRITE("Not proof of an attack — watch for twin/KARMA behavior.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_DEV_MODULE) {
        WRITE("Made from raw chip hardware, not a real router.");
        WRITE("Treat with suspicion.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_FCC_COVERED) {
        WRITE("From a maker on the FCC restricted list.");
        WRITE("Many US workplaces block these.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_SURVEILLANCE) {
        WRITE("From a brand of surveillance equipment.");
        WRITE("Usually means a camera or sensor nearby.");
        return n;
    }
    if (ap->eui_flags & EUI_FLAG_MAKER) {
        WRITE("Looks like a homemade hardware project.");
        WRITE("Not a regular router. Be careful.");
        return n;
    }

    if (ap->auth == WIFI_AUTH_OPEN) {
        WRITE("No password. Anyone nearby can see your traffic.");
        WRITE("Skip banking and passwords here.");
        return n;
    }
    if (ap->auth == WIFI_AUTH_WPA_PSK) {
        WRITE("Older encryption (WPA-TKIP).");
        WRITE("OK for browsing. Skip banking.");
        return n;
    }
    if (ap->has_wps) {
        WRITE("WPS shortcut is on (8-digit PIN setup).");
        WRITE("Attackers can guess the PIN to join. OK to browse.");
        return n;
    }
    if (mac_is_laa(ap->bssid)) {
        WRITE("The hardware maker is hidden (randomized ID).");
        WRITE("Common for phone hotspots. Fine if you know it.");
        return n;
    }

    switch (ap->auth) {
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA3_ENTERPRISE:
        WRITE("Strong encryption (WPA3).");
        break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        WRITE("Strong encryption (WPA2 + WPA3).");
        break;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_ENTERPRISE:
        if (ap->rsn_pmf_required)
            WRITE("Good encryption (WPA2 + PMF).");
        else
            WRITE("Good encryption (WPA2).");
        break;
    default:
        WRITE("Encryption looks OK.");
        break;
    }

    if (ap->vendor[0])
        WRITE("From %.24s — recognized gear.", ap->vendor);
    else
        WRITE("Looks like normal network gear.");

    #undef WRITE
    return n;
}

const char *vetter_check_reason(const ap_score_t *ap,
                                const vetter_result_t *result,
                                uint8_t check_idx)
{
    if (!ap || !result || check_idx >= 10) return NULL;
    vetter_check_t s = result->check[check_idx];
    if (s == VETTER_PASS || s == VETTER_INFO || s == VETTER_SKIP) return NULL;

    switch (check_idx) {
    case 0:
        return "SSID rule + suspect class";
    case 1:
        return "Known malicious vendor";
    case 2:
        if (ap->auth == WIFI_AUTH_WEP)     return "WEP — broken crypto";
        if (ap->auth == WIFI_AUTH_WPA_PSK) return "WPA-TKIP — weak";
        if (ap->has_wps)                   return "WPS active";
        return "Crypto warning";
    case 3:
        return "LAA MAC (bit 1 set)";
    case 4:
        if (ap->karma_suspect) return "KARMA suspect";
        if (ap->twin_detected) return "Twin BSSID detected";
        return "Vendor/twin mismatch";
    case 5:
        return "Open + protected clone";
    default:
        return "Active-conn check skipped";
    }
}

void vetter_log(const ap_score_t *ap, const vetter_result_t *result)
{
    ESP_LOGI(TAG, "  ┌── \"%s\"  %s",
             ap->ssid, result->blocked ? "BLOCKED"
                 : analyzer_verdict_label(analyzer_threat_to_verdict(ap->threat_level)));
    ESP_LOGI(TAG, "  │  #1 vendor/SSID:%-4s  #2 blocklist:%-4s  #3 crypto:%-4s",
             sev_str(result->check[0]), sev_str(result->check[1]), sev_str(result->check[2]));
    ESP_LOGI(TAG, "  │  #4 LAA:%-4s  #5 twin/KARMA:%-4s  #6 open-clone:%-4s",
             sev_str(result->check[3]), sev_str(result->check[4]), sev_str(result->check[5]));
    ESP_LOGI(TAG, "  │  #7 DHCP:%-4s  #8 portal:%-4s  #9 DNS:%-4s  #10 route:%-4s",
             sev_str(result->check[6]), sev_str(result->check[7]),
             sev_str(result->check[8]), sev_str(result->check[9]));
    ESP_LOGI(TAG, "  └── %s", result->summary);
}
