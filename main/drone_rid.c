#include "drone_rid.h"
#include "opendroneid.h"

#include <string.h>
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define RID_SVC_UUID      0xFFFA
#define RID_BLE_APP_CODE  0x0D
#define RID_HEADER_LEN    4

static const uint8_t RID_WIFI_OUI[3] = { 0xFA, 0x0B, 0xBC };
#define RID_WIFI_OUI_TYPE   0x0D
#define RID_WIFI_BEACON_HDR 5

#define RID_NAN_MGMT_HDR   24
static const uint8_t RID_NAN_WFA_OUI[3]   = { 0x50, 0x6F, 0x9A };
#define RID_NAN_OUI_TYPE   0x13
#define RID_NAN_ATTR_SD    0x03

static const uint8_t RID_NAN_SERVICE_ID[6] = { 0x88, 0x69, 0x19, 0x9D, 0x92, 0x09 };

#define RID_NAN_PACK_OFF   44

static void extract_mfr_code(drone_rid_t *out)
{
    if (out->id_type != ODID_IDTYPE_SERIAL_NUMBER) return;
    if (strnlen(out->id, sizeof(out->id)) < 5) return;
    for (int i = 0; i < 4; i++) {
        char ch = out->id[i];
        bool alnum = (ch >= '0' && ch <= '9') ||
                     (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
        if (!alnum) return;
        out->mfr_code[i] = ch;
    }
    out->mfr_code[4] = '\0';
}

static bool decode_odid(const uint8_t *msg, size_t msg_len, drone_rid_t *out)
{
    if (msg_len < 1) return false;

    ODID_UAS_Data uas;
    odid_initUasData(&uas);

    if (decodeMessageType(msg[0]) == ODID_MESSAGETYPE_PACKED) {

        if (msg_len < 3) return false;
        uint8_t single = msg[1];
        uint8_t count  = msg[2];
        if (single != ODID_MESSAGE_SIZE) return false;
        if (count == 0 || count > ODID_PACK_MAX_MESSAGES) return false;
        if (msg_len < (size_t)3 + (size_t)count * ODID_MESSAGE_SIZE) return false;
        if (decodeMessagePack(&uas, (const ODID_MessagePack_encoded *)msg) != ODID_SUCCESS)
            return false;
    } else {
        if (msg_len < ODID_MESSAGE_SIZE) return false;
        if (decodeOpenDroneID(&uas, msg) == ODID_MESSAGETYPE_INVALID)
            return false;
    }

    for (int i = 0; i < ODID_BASIC_ID_MAX_MESSAGES; i++) {
        if (uas.BasicIDValid[i]) {
            out->ua_type = (uint8_t)uas.BasicID[i].UAType;
            out->id_type = (uint8_t)uas.BasicID[i].IDType;
            strlcpy(out->id, uas.BasicID[i].UASID, sizeof(out->id));
            extract_mfr_code(out);
            out->msg_mask |= DRONE_RID_MSG_BASIC_ID;
            break;
        }
    }

    if (uas.LocationValid) {
        out->lat   = (int32_t)lround(uas.Location.Latitude  * 1e7);
        out->lon   = (int32_t)lround(uas.Location.Longitude * 1e7);
        out->alt_m = (int32_t)lroundf(uas.Location.AltitudeGeo);
        out->speed = (int16_t)lroundf(uas.Location.SpeedHorizontal);
        out->track = (int16_t)lroundf(uas.Location.Direction);
        out->msg_mask |= DRONE_RID_MSG_LOCATION;
    }

    if (uas.SystemValid) {
        double olat = uas.System.OperatorLatitude;
        double olon = uas.System.OperatorLongitude;
        out->op_lat = (int32_t)lround(olat * 1e7);
        out->op_lon = (int32_t)lround(olon * 1e7);

        out->has_op_loc = !(olat == 0.0 && olon == 0.0);
        out->msg_mask |= DRONE_RID_MSG_SYSTEM;
    }

    if (uas.OperatorIDValid) {
        strlcpy(out->op_id, uas.OperatorID.OperatorId, sizeof(out->op_id));
        out->msg_mask |= DRONE_RID_MSG_OPERATOR_ID;
    }

    if (uas.SelfIDValid) {
        strlcpy(out->self_id, uas.SelfID.Desc, sizeof(out->self_id));
        out->msg_mask |= DRONE_RID_MSG_SELF_ID;
    }

    for (int i = 0; i < ODID_AUTH_MAX_PAGES; i++) {
        if (uas.AuthValid[i]) {
            out->auth_present = true;
            out->msg_mask |= DRONE_RID_MSG_AUTH;
            break;
        }
    }

    return out->msg_mask != 0;
}

bool drone_rid_decode(const uint8_t *svc_data, size_t len, drone_rid_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!svc_data || len < RID_HEADER_LEN + 1) return false;

    uint16_t uuid = (uint16_t)svc_data[0] | ((uint16_t)svc_data[1] << 8);
    if (uuid != RID_SVC_UUID)            return false;
    if (svc_data[2] != RID_BLE_APP_CODE) return false;

    if (!decode_odid(&svc_data[RID_HEADER_LEN], len - RID_HEADER_LEN, out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    out->bearer = DRONE_RID_BEARER_BLE;
    return true;
}

bool drone_rid_decode_wifi_beacon(const uint8_t *ie, size_t len, drone_rid_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!ie || len < RID_WIFI_BEACON_HDR + 1) return false;

    if (memcmp(ie, RID_WIFI_OUI, 3) != 0)  return false;
    if (ie[3] != RID_WIFI_OUI_TYPE)        return false;

    if (!decode_odid(&ie[RID_WIFI_BEACON_HDR], len - RID_WIFI_BEACON_HDR, out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    out->bearer = DRONE_RID_BEARER_WIFI_BEACON;
    return true;
}

bool drone_rid_decode_wifi_nan(const uint8_t *frame, size_t len, drone_rid_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!frame || len < RID_NAN_PACK_OFF + 1) return false;

    if (frame[RID_NAN_MGMT_HDR + 0] != 0x04) return false;
    if (frame[RID_NAN_MGMT_HDR + 1] != 0x09) return false;
    if (memcmp(&frame[RID_NAN_MGMT_HDR + 2], RID_NAN_WFA_OUI, 3) != 0) return false;
    if (frame[RID_NAN_MGMT_HDR + 5] != RID_NAN_OUI_TYPE) return false;

    if (frame[RID_NAN_MGMT_HDR + 6] != RID_NAN_ATTR_SD) return false;
    if (memcmp(&frame[RID_NAN_MGMT_HDR + 9], RID_NAN_SERVICE_ID, 6) != 0) return false;

    if (!decode_odid(&frame[RID_NAN_PACK_OFF], len - RID_NAN_PACK_OFF, out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    out->bearer = DRONE_RID_BEARER_WIFI_NAN;
    return true;
}

const char *drone_rid_bearer_label(uint8_t bearer)
{
    switch (bearer) {
    case DRONE_RID_BEARER_BLE:         return "BLE";
    case DRONE_RID_BEARER_WIFI_BEACON: return "Wi-Fi";
    case DRONE_RID_BEARER_WIFI_NAN:    return "Wi-Fi NaN";
    default:                            return "?";
    }
}

int drone_op_separation_m(const drone_rid_t *d)
{
    if (!d || !d->has_op_loc) return -1;
    if (!(d->msg_mask & DRONE_RID_MSG_LOCATION)) return -1;

    const double R = 6371000.0;
    double lat1 = (double)d->lat    * 1e-7 * (M_PI / 180.0);
    double lat2 = (double)d->op_lat * 1e-7 * (M_PI / 180.0);
    double dlat = lat2 - lat1;
    double dlon = ((double)d->op_lon - (double)d->lon) * 1e-7 * (M_PI / 180.0);

    double a = sin(dlat / 2.0) * sin(dlat / 2.0) +
               cos(lat1) * cos(lat2) * sin(dlon / 2.0) * sin(dlon / 2.0);
    double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
    return (int)lround(R * c);
}

const char *drone_ua_type_label(uint8_t ua_type)
{
    switch (ua_type) {
    case ODID_UATYPE_NONE:                       return "Unspecified";
    case ODID_UATYPE_AEROPLANE:                  return "Fixed-wing";
    case ODID_UATYPE_HELICOPTER_OR_MULTIROTOR:   return "Multirotor";
    case ODID_UATYPE_GYROPLANE:                  return "Gyroplane";
    case ODID_UATYPE_HYBRID_LIFT:                return "Hybrid VTOL";
    case ODID_UATYPE_ORNITHOPTER:                return "Ornithopter";
    case ODID_UATYPE_GLIDER:                     return "Glider";
    case ODID_UATYPE_KITE:                        return "Kite";
    case ODID_UATYPE_FREE_BALLOON:
    case ODID_UATYPE_CAPTIVE_BALLOON:            return "Balloon";
    case ODID_UATYPE_AIRSHIP:                    return "Airship";
    case ODID_UATYPE_FREE_FALL_PARACHUTE:        return "Parachute";
    case ODID_UATYPE_ROCKET:                     return "Rocket";
    case ODID_UATYPE_TETHERED_POWERED_AIRCRAFT:  return "Tethered";
    case ODID_UATYPE_GROUND_OBSTACLE:            return "Ground obj";
    default:                                      return "Other";
    }
}
