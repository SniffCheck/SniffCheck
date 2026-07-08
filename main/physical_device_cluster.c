#include "physical_device_cluster.h"

#include "eui_db.h"
#include "ble_advise.h"
#include "apple_continuity.h"
#include "esp_attr.h"
#include "esp_log.h"

#include <string.h>
#include <strings.h>

static const char *TAG = "sc_pdc";

#define PDC_MAX_NODES  (ANALYZER_MAX_APS + BLE_MAX_DEVICES)

static EXT_RAM_BSS_ATTR uint8_t       s_node_mac[PDC_MAX_NODES][6];
static EXT_RAM_BSS_ATTR pdc_edge_t    s_edges[PDC_MAX_EDGES];
static EXT_RAM_BSS_ATTR pdc_cluster_t s_clusters[PDC_MAX_CLUSTERS];
static EXT_RAM_BSS_ATTR int16_t       s_parent[PDC_MAX_NODES];
static EXT_RAM_BSS_ATTR int8_t        s_cluster_of[PDC_MAX_NODES];

#define PDC_MAX_VCLUSTERS 12
static EXT_RAM_BSS_ATTR pdc_cluster_t s_vclusters[PDC_MAX_VCLUSTERS];
static EXT_RAM_BSS_ATTR int8_t        s_vcluster_of[PDC_MAX_NODES];

static uint16_t s_ap_count;
static uint16_t s_node_count;
static uint8_t  s_edge_count;
static uint8_t  s_cluster_count;
static uint8_t  s_vcluster_count;
static uint8_t  s_edges_dropped;

static uint32_t mac_suffix(const uint8_t *m)
{
    return ((uint32_t)m[3] << 16) | ((uint32_t)m[4] << 8) | m[5];
}

static bool pdc_same_physical_router(const uint8_t a[6], const uint8_t b[6])
{
    if (a[2] != b[2] || a[3] != b[3] || a[4] != b[4]) return false;
    int delta = (int)a[5] - (int)b[5];
    if (delta < 0) delta = -delta;
    return delta <= 16;
}

static uint32_t suffix_delta(const uint8_t a[6], const uint8_t b[6])
{
    uint32_t sa = mac_suffix(a), sb = mac_suffix(b);
    return sa > sb ? sa - sb : sb - sa;
}

static bool l2l3_id_is_generic(const char *id)
{
    if (!id) return true;
    size_t n = strlen(id);
    if (n < 3) return true;
    static const char *generic[] = {
        "ap", "switch", "router", "localhost", "unknown", "gateway", "host"
    };
    for (size_t i = 0; i < sizeof(generic) / sizeof(generic[0]); i++)
        if (strcasecmp(id, generic[i]) == 0) return true;
    return false;
}

static bool ble_name_is_generic(const char *n)
{
    if (!n) return true;
    if (strlen(n) < 5) return true;
    static const char *generic[] = {
        "unknown", "headphones", "headset", "speaker", "keyboard", "mouse",
        "ble device", "bluetooth", "bt device", "earbuds", "earphones"
    };
    for (size_t i = 0; i < sizeof(generic) / sizeof(generic[0]); i++)
        if (strcasecmp(n, generic[i]) == 0) return true;
    return false;
}

#define PDC_RID_IDTYPE_SERIAL  1
#define PDC_RID_IDTYPE_CAA_REG 2
static bool rid_id_is_persistent(uint8_t id_type)
{
    return id_type == PDC_RID_IDTYPE_SERIAL || id_type == PDC_RID_IDTYPE_CAA_REG;
}

#define PDC_CAND_NIC   (1u << 0)
#define PDC_CAND_ADJ   (1u << 1)
#define PDC_CAND_SSID  (1u << 2)
#define PDC_CAND_RF    (1u << 3)

#define PDC_CAND_HW_GROUP  (PDC_CAND_NIC | PDC_CAND_ADJ)
#define PDC_CAND_NET_GROUP (PDC_CAND_SSID)
#define PDC_CAND_RF_GROUP  (PDC_CAND_RF)

#define PDC_CONF_COUNTRY   (1u << 0)
#define PDC_CONF_CHAIN     (1u << 1)
#define PDC_CONF_MESH      (1u << 2)
#define PDC_CONF_AMBIGUOUS (1u << 3)

#define PDC_MESH_MIN_GROUP 4

static uint16_t node_of(uint8_t kind, uint8_t idx)
{
    return kind == PDC_NODE_WIFI ? idx : s_ap_count + idx;
}

static void add_edge(uint8_t kind_a, uint8_t idx_a,
                     uint8_t kind_b, uint8_t idx_b,
                     uint8_t evidence, uint8_t conf, bool can_union)
{
    if (conf == 0) return;
    for (uint8_t e = 0; e < s_edge_count; e++) {
        pdc_edge_t *ed = &s_edges[e];
        bool same = (ed->kind_a == kind_a && ed->idx_a == idx_a &&
                     ed->kind_b == kind_b && ed->idx_b == idx_b) ||
                    (ed->kind_a == kind_b && ed->idx_a == idx_b &&
                     ed->kind_b == kind_a && ed->idx_b == idx_a);
        if (same) {
            if (can_union) ed->can_union = 1;
            if (conf > ed->confidence) {
                ed->confidence = conf;
                ed->evidence   = evidence;
                ed->evclass    = (uint8_t)pdc_evidence_class(evidence);
            }
            return;
        }
    }
    if (s_edge_count >= PDC_MAX_EDGES) { s_edges_dropped++; return; }
    pdc_edge_t *ed = &s_edges[s_edge_count++];
    ed->kind_a = kind_a; ed->idx_a = idx_a;
    ed->kind_b = kind_b; ed->idx_b = idx_b;
    ed->evidence = evidence;
    ed->evclass = (uint8_t)pdc_evidence_class(evidence);
    ed->confidence = conf;
    ed->can_union = can_union ? 1 : 0;

    ed->cand_mask = 0;
    ed->conflict_mask = 0;
    ed->corroborated = 0;
}

static void edge_or_facts(uint8_t ka, uint8_t ia, uint8_t kb, uint8_t ib,
                          uint16_t cand, uint16_t conflict)
{
    for (uint8_t e = 0; e < s_edge_count; e++) {
        pdc_edge_t *ed = &s_edges[e];
        bool same = (ed->kind_a == ka && ed->idx_a == ia &&
                     ed->kind_b == kb && ed->idx_b == ib) ||
                    (ed->kind_a == kb && ed->idx_a == ib &&
                     ed->kind_b == ka && ed->idx_b == ia);
        if (same) {
            ed->cand_mask     |= cand;
            ed->conflict_mask |= conflict;
            return;
        }
    }
}

static bool cand_corroborates(uint16_t m)
{
    if (!(m & PDC_CAND_NIC)) return false;
    return (m & PDC_CAND_NET_GROUP) && (m & PDC_CAND_RF_GROUP);
}

static void pdc_corroborate(void)
{
    for (uint8_t e = 0; e < s_edge_count; e++) {
        pdc_edge_t *ed = &s_edges[e];
        if (ed->can_union) continue;
        if (ed->conflict_mask) continue;
        if (!cand_corroborates(ed->cand_mask)) continue;
        ed->can_union    = 1;
        ed->corroborated = 1;
    }
}

static bool corroborated_edge_between(uint16_t na, uint16_t nb)
{
    for (uint8_t e = 0; e < s_edge_count; e++) {
        const pdc_edge_t *ed = &s_edges[e];
        if (!ed->corroborated) continue;
        uint16_t a = node_of(ed->kind_a, ed->idx_a);
        uint16_t b = node_of(ed->kind_b, ed->idx_b);
        if ((a == na && b == nb) || (a == nb && b == na)) return true;
    }
    return false;
}

static void pdc_resolve_ambiguity(void)
{
    for (uint16_t v = 0; v < s_node_count; v++) {
        uint16_t peers[12];
        uint8_t  np = 0;
        bool     overflow = false;
        for (uint8_t e = 0; e < s_edge_count; e++) {
            const pdc_edge_t *ed = &s_edges[e];
            if (!ed->corroborated) continue;
            uint16_t a = node_of(ed->kind_a, ed->idx_a);
            uint16_t b = node_of(ed->kind_b, ed->idx_b);
            uint16_t peer;
            if (a == v) peer = b; else if (b == v) peer = a; else continue;
            if (np < sizeof(peers) / sizeof(peers[0])) peers[np++] = peer;
            else overflow = true;
        }
        if (np < 2) continue;

        bool clique = !overflow;
        for (uint8_t x = 0; clique && x < np; x++)
            for (uint8_t y = (uint8_t)(x + 1); clique && y < np; y++)
                if (!corroborated_edge_between(peers[x], peers[y])) clique = false;
        if (clique) continue;

        for (uint8_t e = 0; e < s_edge_count; e++) {
            pdc_edge_t *ed = &s_edges[e];
            if (!ed->corroborated) continue;
            uint16_t a = node_of(ed->kind_a, ed->idx_a);
            uint16_t b = node_of(ed->kind_b, ed->idx_b);
            if (a != v && b != v) continue;
            ed->can_union     = 0;
            ed->corroborated  = 0;
            ed->conflict_mask |= PDC_CONF_AMBIGUOUS;
        }
    }
}

static uint8_t adjacency_conf(uint32_t delta)
{
    if (delta == 0)  return 95;
    if (delta <= 4)  return 85;
    if (delta <= 16) return 70;
    return 0;
}

#define PDC_RSSI_GAP_SAME_RADIO 10
#define PDC_RSSI_GAP_CROSS_BAND 25 

static bool pdc_one_box_rf(const ap_score_t *a, const ap_score_t *b)
{
    int gap = (int)a->rssi - (int)b->rssi;
    if (gap < 0) gap = -gap;
    if (a->band_5g != b->band_5g)
        return gap <= PDC_RSSI_GAP_CROSS_BAND;
    return a->channel == b->channel && gap <= PDC_RSSI_GAP_SAME_RADIO;
}

static bool pdc_wifi_union_ok(const ap_score_t *a, const ap_score_t *b,
                              uint8_t evidence, bool id_specific)
{

    if (evidence == PDC_EV_L2L3_ID) return id_specific;

    if (evidence == PDC_EV_SAME_PHYSICAL_ROUTER) {
        if (a->band_5g != b->band_5g) return false;
        if (a->channel != b->channel) return false;

        if (a->country_code[0] && b->country_code[0] &&
            strncmp(a->country_code, b->country_code, 2) != 0) return false;
        return true;
    }
    return false;
}

static const char *const SSID_VARIANT_SUFFIX[] = {
    "-5ghz","_5ghz"," 5ghz","-5g","_5g"," 5g","-5","_5",
    "-2.4ghz","_2.4ghz","-2.4g","_2.4g"," 2.4g","-24g","_24g","-2g","_2g",
    "-guest","_guest"," guest","-iot","_iot"," iot","-ext","_ext"," ext",
};

static size_t ssid_base_len(const char *s)
{
    size_t n = strlen(s);
    for (bool changed = true; changed; ) {
        changed = false;
        for (size_t k = 0; k < sizeof(SSID_VARIANT_SUFFIX) /
                               sizeof(SSID_VARIANT_SUFFIX[0]); k++) {
            size_t sl = strlen(SSID_VARIANT_SUFFIX[k]);
            if (n > sl && strncasecmp(s + n - sl, SSID_VARIANT_SUFFIX[k], sl) == 0) {
                n -= sl; changed = true; break;
            }
        }
    }
    while (n > 0 && (s[n-1] == '-' || s[n-1] == '_' || s[n-1] == ' ')) n--;
    return n;
}

static bool ssid_related(const char *a, const char *b)
{
    if (!a[0] || !b[0]) return false;
    if (strcmp(a, "<hidden>") == 0 || strcmp(b, "<hidden>") == 0) return false;
    if (strcasecmp(a, b) == 0) return true;
    size_t la = ssid_base_len(a), lb = ssid_base_len(b);
    return la > 0 && la == lb && strncasecmp(a, b, la) == 0;
}

static bool ssid_is_public_chain(const char *s)
{
    static const char *const CHAIN[] = {
        "xfinitywifi","attwifi","eduroam","optimumwifi","spectrumwifi",
        "cablewifi","google starbucks","gogoinflight","boingo hotspot",
        "bt wi-fi","btwifi-with-fon","telstra air","sky wifi","linknyc free wi-fi",
    };
    for (size_t i = 0; i < sizeof(CHAIN) / sizeof(CHAIN[0]); i++)
        if (strcasecmp(s, CHAIN[i]) == 0) return true;
    return false;
}

static uint8_t s_ssid_group[ANALYZER_MAX_APS];

static void collect_wifi_wifi(const ap_score_t *scores, uint16_t n)
{
    for (uint16_t i = 0; i < n && i < ANALYZER_MAX_APS; i++) {
        uint8_t cnt = 0;
        if (!scores[i].suppressed)
            for (uint16_t j = 0; j < n; j++)
                if (!scores[j].suppressed &&
                    ssid_related(scores[i].ssid, scores[j].ssid) && cnt < 255)
                    cnt++;
        s_ssid_group[i] = cnt;
    }

    for (uint16_t i = 0; i < n; i++) {
        if (scores[i].suppressed) continue;
        for (uint16_t j = i + 1; j < n; j++) {
            if (scores[j].suppressed) continue;
            const ap_score_t *a = &scores[i], *b = &scores[j];

            bool same_oui = !mac_is_laa(a->bssid) && !mac_is_laa(b->bssid) &&
                            memcmp(a->bssid, b->bssid, 3) == 0;
            bool one_box  = false;

            if (pdc_same_physical_router(a->bssid, b->bssid) &&
                (same_oui || mac_is_laa(a->bssid) || mac_is_laa(b->bssid)) &&
                pdc_one_box_rf(a, b)) {
                uint32_t d = suffix_delta(a->bssid, b->bssid);

                add_edge(PDC_NODE_WIFI, i, PDC_NODE_WIFI, j,
                         PDC_EV_SAME_PHYSICAL_ROUTER, d <= 4 ? 90 : 80,
                         pdc_wifi_union_ok(a, b, PDC_EV_SAME_PHYSICAL_ROUTER,
                                           false));
                one_box = true;
            } else if (same_oui && pdc_one_box_rf(a, b)) {

                uint32_t d = suffix_delta(a->bssid, b->bssid);
                if (d <= 16) {
                    add_edge(PDC_NODE_WIFI, i, PDC_NODE_WIFI, j,
                             PDC_EV_MAC_ADJACENT, d <= 4 ? 60 : 45, false);
                    one_box = true;
                }
            }

            if (one_box) {
                uint16_t cand = pdc_one_box_rf(a, b) ? PDC_CAND_RF : 0;
                cand |= pdc_same_physical_router(a->bssid, b->bssid)
                          ? PDC_CAND_NIC : PDC_CAND_ADJ;

                if (ssid_related(a->ssid, b->ssid)) cand |= PDC_CAND_SSID;
                uint16_t conf = 0;
                if (a->country_code[0] && b->country_code[0] &&
                    strncmp(a->country_code, b->country_code, 2) != 0)
                    conf |= PDC_CONF_COUNTRY;

                if (ssid_is_public_chain(a->ssid) || ssid_is_public_chain(b->ssid))
                    conf |= PDC_CONF_CHAIN;
                if (s_ssid_group[i] >= PDC_MESH_MIN_GROUP ||
                    s_ssid_group[j] >= PDC_MESH_MIN_GROUP)
                    conf |= PDC_CONF_MESH;
                edge_or_facts(PDC_NODE_WIFI, i, PDC_NODE_WIFI, j, cand, conf);
            }

            if (one_box &&
                a->wps_manufacturer[0] && a->wps_model_name[0] &&
                strcmp(a->wps_manufacturer, b->wps_manufacturer) == 0 &&
                strcmp(a->wps_model_name,   b->wps_model_name)   == 0) {
                add_edge(PDC_NODE_WIFI, i, PDC_NODE_WIFI, j,
                         PDC_EV_WPS_VENDOR_MODEL, 55, false);
            }

            bool same_cdp  = a->cdp_device_id[0] &&
                             strcmp(a->cdp_device_id, b->cdp_device_id) == 0;
            bool same_lldp = a->lldp_system_name[0] &&
                             strcmp(a->lldp_system_name, b->lldp_system_name) == 0;
            if (same_cdp || same_lldp) {
                const char *id = same_cdp ? a->cdp_device_id
                                          : a->lldp_system_name;
                add_edge(PDC_NODE_WIFI, i, PDC_NODE_WIFI, j,
                         PDC_EV_L2L3_ID, 85,
                         pdc_wifi_union_ok(a, b, PDC_EV_L2L3_ID,
                                           !l2l3_id_is_generic(id)));
            }
        }
    }
}

static void collect_wifi_ble(const ap_score_t *scores, uint16_t n,
                             const ble_results_t *ble)
{
    for (uint16_t i = 0; i < n; i++) {
        if (scores[i].suppressed) continue;
        const ap_score_t *a = &scores[i];
        bool ap_public = !mac_is_laa(a->bssid);

        for (uint16_t j = 0; j < ble->count; j++) {
            const ble_device_t *d = &ble->devices[j];
            if (d->suppressed) continue;

            if (ap_public && !(d->addr[0] & 0x02) &&
                memcmp(a->bssid, d->addr, 3) == 0) {
                uint8_t conf = adjacency_conf(suffix_delta(a->bssid, d->addr));

                if (conf)
                    add_edge(PDC_NODE_WIFI, i, PDC_NODE_BLE, j,
                             PDC_EV_MAC_ADJACENT, conf, false);
            }

            if (d->name[0] && a->ssid[0] &&
                strcmp(a->ssid, "<hidden>") != 0 &&
                strcasecmp(d->name, a->ssid) == 0) {
                add_edge(PDC_NODE_WIFI, i, PDC_NODE_BLE, j,
                         PDC_EV_NAME_MATCH, 40, false);
            }
        }
    }
}

static void collect_ble_ble(const ble_results_t *ble)
{
    for (uint16_t i = 0; i < ble->count; i++) {
        const ble_device_t *a = &ble->devices[i];
        if (a->suppressed) continue;
        bool a_public = !(a->addr[0] & 0x02);
        for (uint16_t j = i + 1; j < ble->count; j++) {
            const ble_device_t *b = &ble->devices[j];
            if (b->suppressed) continue;

            if (a_public && !(b->addr[0] & 0x02) &&
                memcmp(a->addr, b->addr, 3) == 0 &&
                suffix_delta(a->addr, b->addr) <= 4) {
                add_edge(PDC_NODE_BLE, i, PDC_NODE_BLE, j,
                         PDC_EV_MAC_ADJACENT, 70, false);
            }

            if (a->has_rid && b->has_rid &&
                a->drone.id[0] &&
                rid_id_is_persistent(a->drone.id_type) &&
                a->drone.id_type == b->drone.id_type &&
                strcmp(a->drone.id, b->drone.id) == 0) {
                add_edge(PDC_NODE_BLE, i, PDC_NODE_BLE, j,
                         PDC_EV_BLE_RID_ID, 95, true);
            }

            if (a->fastpair_model_id &&
                a->fastpair_model_id == b->fastpair_model_id) {
                add_edge(PDC_NODE_BLE, i, PDC_NODE_BLE, j,
                         PDC_EV_BLE_FASTPAIR_MODEL, 60, false);
            } else if (a->uuid128_name && b->uuid128_name &&
                       strcmp(a->uuid128_name, b->uuid128_name) == 0) {
                add_edge(PDC_NODE_BLE, i, PDC_NODE_BLE, j,
                         PDC_EV_BLE_SERVICE_UUID, 50, false);
            } else if (a->name[0] && !ble_name_is_generic(a->name) &&
                       strcasecmp(a->name, b->name) == 0) {
                add_edge(PDC_NODE_BLE, i, PDC_NODE_BLE, j,
                         PDC_EV_BLE_LOCAL_NAME, 40, false);
            }
        }
    }
}

#define PDC_ECO_MAX_DIST_DM   150
#define PDC_ECO_MAX_DELTA_DM   50

static bool ble_is_non_apple_phone(const ble_device_t *d)
{
    if (ble_effective_class(d) != EUI_CLASS_PHONE) return false;
    return d->mfg_company_id != 0x004C &&
           d->apple_devcat == APPLE_DEVCAT_UNKNOWN &&
           d->apple_subtype == 0;
}

static bool eco_co_present(const ble_device_t *a, const ble_device_t *b)
{
    if (a->distance_dm == 0xFFFF || b->distance_dm == 0xFFFF) return false;
    if (a->distance_dm > PDC_ECO_MAX_DIST_DM ||
        b->distance_dm > PDC_ECO_MAX_DIST_DM) return false;
    int delta = (int)a->distance_dm - (int)b->distance_dm;
    if (delta < 0) delta = -delta;
    return delta <= PDC_ECO_MAX_DELTA_DM;
}

static void collect_ecosystem(const ble_results_t *ble)
{
    if (!ble) return;
    uint16_t n = ble->count;
    if (n > BLE_MAX_DEVICES) n = BLE_MAX_DEVICES;
    for (uint16_t i = 0; i < n; i++) {
        const ble_device_t *acc = &ble->devices[i];
        if (acc->suppressed) continue;
        if (acc->fastpair_model_id == 0) continue;
        for (uint16_t j = 0; j < n; j++) {
            if (j == i) continue;
            const ble_device_t *ph = &ble->devices[j];
            if (ph->suppressed) continue;
            if (!ble_is_non_apple_phone(ph)) continue;
            if (!eco_co_present(acc, ph)) continue;

            add_edge(PDC_NODE_BLE, (uint8_t)i, PDC_NODE_BLE, (uint8_t)j,
                     PDC_EV_ECOSYSTEM_COPRESENCE, 30, false);
        }
    }
}

#define PDC_MAX_VEH_NODES 32 

static bool node_is_vehicle_cls(uint8_t cls)
{
    return cls == EUI_CLASS_VEHICLE || cls == EUI_CLASS_AUTOMOTIVE;
}

static bool make_key(const char *src, char *out, size_t cap)
{
    if (!src) return false;
    size_t k = 0;
    for (const char *p = src; *p && k + 1 < cap; p++) {
        char c = *p;
        if (c == ' ' || c == '(' || c == '-' || c == '/') break;
        out[k++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    out[k] = '\0';
    return k >= 3;
}

static bool node_vehicle_make(uint8_t kind, uint8_t idx,
                              const ap_score_t *scores, const ble_results_t *ble,
                              char *out, size_t cap)
{
    if (kind == PDC_NODE_WIFI) {
        const ap_score_t *a = &scores[idx];
        if (!node_is_vehicle_cls(a->device_class)) return false;
        return make_key(a->vendor, out, cap);
    }
    const ble_device_t *d = &ble->devices[idx];
    if (!node_is_vehicle_cls(ble_effective_class(d))) return false;
    const char *src = d->name_rule_name ? d->name_rule_name
                    : d->name[0]        ? d->name
                                        : d->vendor;
    return make_key(src, out, cap);
}

static void collect_vehicle(const ap_score_t *scores, uint16_t n,
                            const ble_results_t *ble)
{
    struct { uint8_t kind, idx; char key[12]; } veh[PDC_MAX_VEH_NODES];
    uint8_t nv = 0;

    for (uint16_t i = 0; i < n && nv < PDC_MAX_VEH_NODES; i++) {
        if (scores[i].suppressed) continue;
        if (node_vehicle_make(PDC_NODE_WIFI, (uint8_t)i, scores, ble,
                              veh[nv].key, sizeof(veh[nv].key))) {
            veh[nv].kind = PDC_NODE_WIFI; veh[nv].idx = (uint8_t)i; nv++;
        }
    }
    uint16_t bn = ble ? ble->count : 0;
    if (bn > BLE_MAX_DEVICES) bn = BLE_MAX_DEVICES;
    for (uint16_t j = 0; j < bn && nv < PDC_MAX_VEH_NODES; j++) {
        if (ble->devices[j].suppressed) continue;
        if (node_vehicle_make(PDC_NODE_BLE, (uint8_t)j, scores, ble,
                              veh[nv].key, sizeof(veh[nv].key))) {
            veh[nv].kind = PDC_NODE_BLE; veh[nv].idx = (uint8_t)j; nv++;
        }
    }

    for (uint8_t i = 0; i < nv; i++)
        for (uint8_t j = (uint8_t)(i + 1); j < nv; j++)
            if (strcmp(veh[i].key, veh[j].key) == 0)
                add_edge(veh[i].kind, veh[i].idx, veh[j].kind, veh[j].idx,
                         PDC_EV_VEHICLE_NAME, 35, false);

    for (uint16_t i = 0; i < s_node_count; i++) s_vcluster_of[i] = -1;
    s_vcluster_count = 0;
    for (uint8_t i = 0; i < nv; i++) {
        if (s_vcluster_of[node_of(veh[i].kind, veh[i].idx)] >= 0) continue;
        uint8_t size = 0;
        for (uint8_t j = 0; j < nv; j++)
            if (strcmp(veh[i].key, veh[j].key) == 0) size++;
        if (size < 2) continue;
        if (s_vcluster_count >= PDC_MAX_VCLUSTERS) break;
        pdc_cluster_t *c = &s_vclusters[s_vcluster_count];
        memset(c, 0, sizeof(*c));
        c->kind          = PDC_CLUSTER_VEHICLE;
        c->total_members = size;
        c->confidence    = 35;
        for (uint8_t j = 0; j < nv; j++) {
            if (strcmp(veh[i].key, veh[j].key) != 0) continue;
            s_vcluster_of[node_of(veh[j].kind, veh[j].idx)] =
                (int8_t)s_vcluster_count;
            if (c->member_count < PDC_MAX_MEMBERS) {
                c->members[c->member_count].kind = veh[j].kind;
                c->members[c->member_count].idx  = veh[j].idx;
                c->member_count++;
            }
        }
        s_vcluster_count++;
    }
}

static uint16_t uf_find(uint16_t x)
{
    while (s_parent[x] != (int16_t)x) {
        s_parent[x] = s_parent[s_parent[x]];
        x = (uint16_t)s_parent[x];
    }
    return x;
}

static void uf_union(uint16_t a, uint16_t b)
{
    uint16_t ra = uf_find(a), rb = uf_find(b);
    if (ra != rb) s_parent[rb] = (int16_t)ra;
}

void pdc_build(const ap_score_t *scores, uint16_t ap_count,
               const ble_results_t *ble)
{
    s_edge_count     = 0;
    s_cluster_count  = 0;
    s_vcluster_count = 0;
    s_edges_dropped  = 0;
    s_ap_count      = scores ? (ap_count > ANALYZER_MAX_APS ? ANALYZER_MAX_APS
                                                            : ap_count) : 0;
    uint16_t ble_n  = ble ? ble->count : 0;
    if (ble_n > BLE_MAX_DEVICES) ble_n = BLE_MAX_DEVICES;
    s_node_count    = s_ap_count + ble_n;

    for (uint16_t i = 0; i < s_ap_count; i++)
        memcpy(s_node_mac[i], scores[i].bssid, 6);
    for (uint16_t j = 0; j < ble_n; j++)
        memcpy(s_node_mac[s_ap_count + j], ble->devices[j].addr, 6);

    if (scores) collect_wifi_wifi(scores, s_ap_count);
    if (ble) {
        if (scores) collect_wifi_ble(scores, s_ap_count, ble);
        collect_ble_ble(ble);

        collect_ecosystem(ble);
    }

    collect_vehicle(scores, s_ap_count, ble);

    pdc_corroborate();
    pdc_resolve_ambiguity();

    for (uint16_t i = 0; i < s_node_count; i++) {
        s_parent[i]     = (int16_t)i;
        s_cluster_of[i] = -1;
    }

    for (uint8_t e = 0; e < s_edge_count; e++)
        if (s_edges[e].can_union)
            uf_union(node_of(s_edges[e].kind_a, s_edges[e].idx_a),
                     node_of(s_edges[e].kind_b, s_edges[e].idx_b));

    for (uint16_t i = 0; i < s_node_count; i++) {
        uint16_t root = uf_find(i);
        if (s_cluster_of[root] < 0) {

            uint16_t size = 0;
            for (uint16_t k = i; k < s_node_count; k++)
                if (uf_find(k) == root) size++;
            if (size < 2) continue;
            if (s_cluster_count >= PDC_MAX_CLUSTERS) continue;
            pdc_cluster_t *c = &s_clusters[s_cluster_count];
            memset(c, 0, sizeof(*c));
            c->total_members = size > 255 ? 255 : (uint8_t)size;
            s_cluster_of[root] = (int8_t)s_cluster_count++;
        }
        int8_t cid = s_cluster_of[root];
        if (cid < 0) continue;
        s_cluster_of[i] = cid;
        pdc_cluster_t *c = &s_clusters[(uint8_t)cid];
        if (c->member_count < PDC_MAX_MEMBERS) {
            c->members[c->member_count].kind =
                i < s_ap_count ? PDC_NODE_WIFI : PDC_NODE_BLE;
            c->members[c->member_count].idx  =
                i < s_ap_count ? (uint8_t)i : (uint8_t)(i - s_ap_count);
            c->member_count++;
        }
    }

    for (uint8_t e = 0; e < s_edge_count; e++) {
        if (!s_edges[e].can_union) continue;
        int8_t cid = s_cluster_of[node_of(s_edges[e].kind_a, s_edges[e].idx_a)];
        if (cid >= 0 && s_edges[e].confidence > s_clusters[(uint8_t)cid].confidence)
            s_clusters[(uint8_t)cid].confidence = s_edges[e].confidence;
    }

    if (s_cluster_count || s_edges_dropped) {

        uint8_t by_class[PDC_CLASS_COUNT] = {0};
        uint8_t unionable = 0, corroborated = 0;
        for (uint8_t e = 0; e < s_edge_count; e++) {
            if (s_edges[e].evclass < PDC_CLASS_COUNT) by_class[s_edges[e].evclass]++;
            if (s_edges[e].can_union) unionable++;
            if (s_edges[e].corroborated) corroborated++;
        }
        ESP_LOGI(TAG, "clusters=%u edges=%u union=%u corrob=%u dropped=%u (nodes wifi=%u ble=%u)",
                 s_cluster_count, s_edge_count, unionable, corroborated,
                 s_edges_dropped, s_ap_count, ble_n);
        ESP_LOGI(TAG, "  edge class: phys=%u cand=%u rel=%u prod=%u ctx=%u",
                 by_class[PDC_CLASS_PHYSICAL_STRONG],
                 by_class[PDC_CLASS_PHYSICAL_CANDIDATE],
                 by_class[PDC_CLASS_RELATIONSHIP],
                 by_class[PDC_CLASS_PRODUCT_FAMILY],
                 by_class[PDC_CLASS_CONTEXT]);
        for (uint8_t c = 0; c < s_cluster_count; c++) {
            ESP_LOGI(TAG, "  cluster[%u]: members=%u conf=%u%%",
                     c, s_clusters[c].total_members, s_clusters[c].confidence);
        }
    }
}

uint8_t pdc_cluster_count(void) { return s_cluster_count; }

const pdc_cluster_t *pdc_cluster_get(uint8_t i)
{
    return i < s_cluster_count ? &s_clusters[i] : NULL;
}

uint8_t pdc_vehicle_cluster_count(void) { return s_vcluster_count; }

const pdc_cluster_t *pdc_vehicle_cluster_get(uint8_t i)
{
    return i < s_vcluster_count ? &s_vclusters[i] : NULL;
}

int8_t pdc_vehicle_cluster_of(uint8_t kind, uint8_t idx)
{
    uint16_t node = node_of(kind, idx);
    if (node >= s_node_count) return -1;
    if (kind == PDC_NODE_WIFI && idx >= s_ap_count) return -1;
    return s_vcluster_of[node];
}

uint8_t pdc_edge_count(void) { return s_edge_count; }

const pdc_edge_t *pdc_edge_get(uint8_t i)
{
    return i < s_edge_count ? &s_edges[i] : NULL;
}

const uint8_t *pdc_node_mac(uint8_t kind, uint8_t idx)
{
    uint16_t node = node_of(kind, idx);
    if (node >= s_node_count) return NULL;
    if (kind == PDC_NODE_WIFI && idx >= s_ap_count) return NULL;
    return s_node_mac[node];
}

int8_t pdc_cluster_of(uint8_t kind, uint8_t idx)
{
    uint16_t node = node_of(kind, idx);
    if (node >= s_node_count) return -1;
    if (kind == PDC_NODE_WIFI && idx >= s_ap_count) return -1;
    return s_cluster_of[node];
}

uint8_t pdc_peers_of_mac(uint8_t kind, const uint8_t mac[6],
                         pdc_peer_t *out, uint8_t max, uint8_t *total_out)
{
    if (total_out) *total_out = 0;
    if (!mac) return 0;

    int16_t self = -1;
    uint16_t lo = kind == PDC_NODE_WIFI ? 0 : s_ap_count;
    uint16_t hi = kind == PDC_NODE_WIFI ? s_ap_count : s_node_count;
    for (uint16_t i = lo; i < hi; i++) {
        if (memcmp(s_node_mac[i], mac, 6) == 0) { self = (int16_t)i; break; }
    }
    if (self < 0) return 0;
    uint8_t self_idx = kind == PDC_NODE_WIFI ? (uint8_t)self
                                             : (uint8_t)(self - s_ap_count);

    uint8_t written = 0, total = 0;
    for (uint8_t e = 0; e < s_edge_count; e++) {
        const pdc_edge_t *ed = &s_edges[e];
        uint8_t pk, pi;
        if (ed->kind_a == kind && ed->idx_a == self_idx) {
            pk = ed->kind_b; pi = ed->idx_b;
        } else if (ed->kind_b == kind && ed->idx_b == self_idx) {
            pk = ed->kind_a; pi = ed->idx_a;
        } else {
            continue;
        }
        total++;
        if (out && written < max) {
            pdc_peer_t *p = &out[written++];
            p->kind = pk;
            p->idx  = pi;
            memcpy(p->mac, s_node_mac[node_of(pk, pi)], 6);
            p->evidence   = ed->evidence;
            p->evclass    = ed->evclass;
            p->confidence = ed->confidence;
        }
    }
    if (total_out) *total_out = total;
    return written;
}

const char *pdc_evidence_label(uint8_t ev)
{
    switch (ev) {
    case PDC_EV_MAC_ADJACENT:         return "nearby_mac_suffix";
    case PDC_EV_SAME_PHYSICAL_ROUTER: return "conserved_nic_bytes";
    case PDC_EV_WPS_VENDOR_MODEL:     return "same_product_model";
    case PDC_EV_L2L3_ID:              return "l2l3_id";
    case PDC_EV_NAME_MATCH:           return "name_match";
    case PDC_EV_BLE_FASTPAIR_MODEL:   return "fast_pair_model";
    case PDC_EV_BLE_SERVICE_UUID:     return "shared_service_uuid";
    case PDC_EV_BLE_LOCAL_NAME:       return "ble_local_name";
    case PDC_EV_BLE_RID_ID:           return "remote_id_serial";
    case PDC_EV_VEHICLE_NAME:         return "vehicle_make";
    case PDC_EV_ECOSYSTEM_COPRESENCE: return "ecosystem_copresence";
    default:                          return "unknown";
    }
}

const char *pdc_evidence_short(uint8_t ev)
{
    switch (ev) {
    case PDC_EV_MAC_ADJACENT:         return "near mac";
    case PDC_EV_SAME_PHYSICAL_ROUTER: return "nic match";
    case PDC_EV_WPS_VENDOR_MODEL:     return "product";
    case PDC_EV_L2L3_ID:              return "l2l3 id";
    case PDC_EV_NAME_MATCH:           return "name";
    case PDC_EV_BLE_FASTPAIR_MODEL:   return "fp mdl";
    case PDC_EV_BLE_SERVICE_UUID:     return "svc set";
    case PDC_EV_BLE_LOCAL_NAME:       return "ble name";
    case PDC_EV_BLE_RID_ID:           return "rid id";
    case PDC_EV_VEHICLE_NAME:         return "vehicle";
    case PDC_EV_ECOSYSTEM_COPRESENCE: return "eco co";
    default:                          return "?";
    }
}

pdc_evidence_class_t pdc_evidence_class(uint8_t ev)
{
    switch (ev) {
    case PDC_EV_L2L3_ID:              return PDC_CLASS_PHYSICAL_STRONG;
    case PDC_EV_BLE_RID_ID:           return PDC_CLASS_PHYSICAL_STRONG;
    case PDC_EV_SAME_PHYSICAL_ROUTER: return PDC_CLASS_PHYSICAL_CANDIDATE;
    case PDC_EV_MAC_ADJACENT:         return PDC_CLASS_RELATIONSHIP;
    case PDC_EV_NAME_MATCH:           return PDC_CLASS_RELATIONSHIP;
    case PDC_EV_BLE_LOCAL_NAME:       return PDC_CLASS_RELATIONSHIP;
    case PDC_EV_ECOSYSTEM_COPRESENCE: return PDC_CLASS_RELATIONSHIP;
    case PDC_EV_WPS_VENDOR_MODEL:     return PDC_CLASS_PRODUCT_FAMILY;
    case PDC_EV_BLE_FASTPAIR_MODEL:   return PDC_CLASS_PRODUCT_FAMILY;
    case PDC_EV_BLE_SERVICE_UUID:     return PDC_CLASS_PRODUCT_FAMILY;
    case PDC_EV_VEHICLE_NAME:         return PDC_CLASS_PRODUCT_FAMILY;
    default:                          return PDC_CLASS_CONTEXT;
    }
}

bool pdc_class_can_union_alone(uint8_t evclass)
{

    return evclass == PDC_CLASS_PHYSICAL_STRONG;
}

const char *pdc_class_label(uint8_t evclass)
{
    switch (evclass) {
    case PDC_CLASS_PHYSICAL_STRONG:    return "physical_strong";
    case PDC_CLASS_PHYSICAL_CANDIDATE: return "physical_candidate";
    case PDC_CLASS_RELATIONSHIP:       return "relationship";
    case PDC_CLASS_PRODUCT_FAMILY:     return "product_family";
    case PDC_CLASS_CONTEXT:            return "context";
    default:                           return "unknown";
    }
}

const char *pdc_conflict_label(uint16_t bit)
{
    switch (bit) {
    case PDC_CONF_COUNTRY: return "country_mismatch";
    case PDC_CONF_CHAIN:   return "public_chain_ssid";
    case PDC_CONF_MESH:    return "mesh_or_enterprise_ssid";
    case PDC_CONF_AMBIGUOUS: return "ambiguous_multi_peer";
    default:               return NULL;
    }
}

const char *pdc_cand_label(uint16_t bit)
{
    switch (bit) {
    case PDC_CAND_NIC:  return "conserved_nic";
    case PDC_CAND_ADJ:  return "adjacent_suffix";
    case PDC_CAND_SSID: return "ssid_related";
    case PDC_CAND_RF:   return "rf_consistent";
    default:            return NULL;
    }
}

const char *pdc_class_short(uint8_t evclass)
{
    switch (evclass) {
    case PDC_CLASS_PHYSICAL_STRONG:    return "phys";
    case PDC_CLASS_PHYSICAL_CANDIDATE: return "cand";
    case PDC_CLASS_RELATIONSHIP:       return "rel";
    case PDC_CLASS_PRODUCT_FAMILY:     return "prod";
    case PDC_CLASS_CONTEXT:            return "ctx";
    default:                           return "?";
    }
}
